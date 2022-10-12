// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"path"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
)

// maintainAssets is a permanently-blocking function
// that loops indefinitely and, on a regular schedule, checks
// certificates for expiration and initiates a renewal of certs
// that are expiring soon. It also updates OCSP stapling. It
// should only be called once per cache. Panics are recovered,
// and if panicCount < 10, the function is called recursively,
// incrementing panicCount each time. Initial invocation should
// start panicCount at 0.
func (certCache *Cache) maintainAssets(panicCount int) {
	log := certCache.logger.Named("maintenance")
	log = log.With(zap.String("cache", fmt.Sprintf("%p", certCache)))

	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackTraceBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			log.Error("panic", zap.Any("error", err), zap.ByteString("stack", buf))
			if panicCount < 10 {
				certCache.maintainAssets(panicCount + 1)
			}
		}
	}()

	renewalTicker := time.NewTicker(certCache.options.RenewCheckInterval)

	log.Info("started background certificate maintenance")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		select {
		case <-renewalTicker.C:
			err := certCache.RenewManagedCertificates(ctx)
			if err != nil {
				log.Error("renewing managed certificates", zap.Error(err))
			}
		case <-certCache.stopChan:
			renewalTicker.Stop()
			log.Info("stopped background certificate maintenance")
			close(certCache.doneChan)
			return
		}
	}
}

// RenewManagedCertificates renews managed certificates,
// including ones loaded on-demand. Note that this is done
// automatically on a regular basis; normally you will not
// need to call this. This method assumes non-interactive
// mode (i.e. operating in the background).
func (certCache *Cache) RenewManagedCertificates(ctx context.Context) error {
	log := certCache.logger.Named("maintenance")

	// configs will hold a map of certificate name to the config
	// to use when managing that certificate
	configs := make(map[string]*Config)

	// we use the queues for a very important reason: to do any and all
	// operations that could require an exclusive write lock outside
	// of the read lock! otherwise we get a deadlock, yikes. in other
	// words, our first iteration through the certificate cache does NOT
	// perform any operations--only queues them--so that more fine-grained
	// write locks may be obtained during the actual operations.
	var renewQueue, reloadQueue, deleteQueue []Certificate

	certCache.mu.RLock()
	for certKey, cert := range certCache.cache {
		if !cert.managed {
			continue
		}

		// the list of names on this cert should never be empty... programmer error?
		if cert.Names == nil || len(cert.Names) == 0 {
			log.Warn("certificate has no names; removing from cache", zap.String("cert_key", certKey))
			deleteQueue = append(deleteQueue, cert)
			continue
		}

		// get the config associated with this certificate
		cfg, err := certCache.getConfig(cert)
		if err != nil {
			log.Error("unable to get configuration to manage certificate; unable to renew",
				zap.Strings("identifiers", cert.Names),
				zap.Error(err))
			continue
		}
		if cfg == nil {
			// this is bad if this happens, probably a programmer error (oops)
			log.Error("no configuration associated with certificate; unable to manage",
				zap.Strings("identifiers", cert.Names))
			continue
		}
		if cfg.OnDemand != nil {
			continue
		}

		// if time is up or expires soon, we need to try to renew it
		if cert.NeedsRenewal(cfg) {
			configs[cert.Names[0]] = cfg

			// see if the certificate in storage has already been renewed, possibly by another
			// instance that didn't coordinate with this one; if so, just load it (this
			// might happen if another instance already renewed it - kinda sloppy but checking disk
			// first is a simple way to possibly drastically reduce rate limit problems)
			storedCertExpiring, err := cfg.managedCertInStorageExpiresSoon(ctx, cert)
			if err != nil {
				// hmm, weird, but not a big deal, maybe it was deleted or something
				log.Warn("error while checking if stored certificate is also expiring soon",
					zap.Strings("identifiers", cert.Names),
					zap.Error(err))
			} else if !storedCertExpiring {
				// if the certificate is NOT expiring soon and there was no error, then we
				// are good to just reload the certificate from storage instead of repeating
				// a likely-unnecessary renewal procedure
				reloadQueue = append(reloadQueue, cert)
				continue
			}

			// the certificate in storage has not been renewed yet, so we will do it
			// NOTE: It is super-important to note that the TLS-ALPN challenge requires
			// a write lock on the cache in order to complete its challenge, so it is extra
			// vital that this renew operation does not happen inside our read lock!
			renewQueue = append(renewQueue, cert)
		}
	}
	certCache.mu.RUnlock()

	// Reload certificates that merely need to be updated in memory
	for _, oldCert := range reloadQueue {
		timeLeft := expiresAt(oldCert.Certificate).Sub(time.Now().UTC())
		log.Info("certificate expires soon, but is already renewed in storage; reloading stored certificate",
			zap.Strings("identifiers", oldCert.Names),
			zap.Duration("remaining", timeLeft))

		cfg := configs[oldCert.Names[0]]

		// crucially, this happens OUTSIDE a lock on the certCache
		_, err := cfg.reloadManagedCertificate(ctx, oldCert)
		if err != nil {
			log.Error("loading renewed certificate",
				zap.Strings("identifiers", oldCert.Names),
				zap.Error(err))
			continue
		}
	}

	// Renewal queue
	for _, oldCert := range renewQueue {
		cfg := configs[oldCert.Names[0]]
		err := certCache.queueRenewalTask(ctx, oldCert, cfg)
		if err != nil {
			log.Error("queueing renewal task",
				zap.Strings("identifiers", oldCert.Names),
				zap.Error(err))
			continue
		}
	}

	// Deletion queue
	certCache.mu.Lock()
	for _, cert := range deleteQueue {
		certCache.removeCertificate(cert)
	}
	certCache.mu.Unlock()

	return nil
}

func (certCache *Cache) queueRenewalTask(ctx context.Context, oldCert Certificate, cfg *Config) error {
	log := certCache.logger.Named("maintenance")

	timeLeft := expiresAt(oldCert.Certificate).Sub(time.Now().UTC())
	log.Info("certificate expires soon; queuing for renewal",
		zap.Strings("identifiers", oldCert.Names),
		zap.Duration("remaining", timeLeft))

	// Get the name which we should use to renew this certificate;
	// we only support managing certificates with one name per cert,
	// so this should be easy.
	renewName := oldCert.Names[0]

	// queue up this renewal job (is a no-op if already active or queued)
	jm.Submit(cfg.Logger, "renew_"+renewName, func() error {
		timeLeft := expiresAt(oldCert.Certificate).Sub(time.Now().UTC())
		log.Info("attempting certificate renewal",
			zap.Strings("identifiers", oldCert.Names),
			zap.Duration("remaining", timeLeft))

		// perform renewal - crucially, this happens OUTSIDE a lock on certCache
		err := cfg.RenewCertAsync(ctx, renewName, false)
		if err != nil {
			if cfg.OnDemand != nil {
				// loaded dynamically, remove dynamically
				certCache.mu.Lock()
				certCache.removeCertificate(oldCert)
				certCache.mu.Unlock()
			}
			return fmt.Errorf("%v %v", oldCert.Names, err)
		}

		// successful renewal, so update in-memory cache by loading
		// renewed certificate so it will be used with handshakes
		_, err = cfg.reloadManagedCertificate(ctx, oldCert)
		if err != nil {
			return ErrNoRetry{fmt.Errorf("%v %v", oldCert.Names, err)}
		}
		return nil
	})

	return nil
}

// CleanStorageOptions specifies how to clean up a storage unit.
type CleanStorageOptions struct {
	ExpiredCerts           bool
	ExpiredCertGracePeriod time.Duration
}

// CleanStorage removes assets which are no longer useful,
// according to opts.
func CleanStorage(ctx context.Context, storage Storage, opts CleanStorageOptions) {
	if opts.ExpiredCerts {
		err := deleteExpiredCerts(ctx, storage, opts.ExpiredCertGracePeriod)
		if err != nil {
			log.Printf("[ERROR] Deleting expired certificates: %v", err)
		}
	}
	// TODO: delete stale locks?
}

func deleteExpiredCerts(ctx context.Context, storage Storage, gracePeriod time.Duration) error {
	issuerKeys, err := storage.List(ctx, prefixCerts, false)
	if err != nil {
		// maybe just hasn't been created yet; no big deal
		return nil
	}

	for _, issuerKey := range issuerKeys {
		siteKeys, err := storage.List(ctx, issuerKey, false)
		if err != nil {
			log.Printf("[ERROR] Listing contents of %s: %v", issuerKey, err)
			continue
		}

		for _, siteKey := range siteKeys {
			// if context was cancelled, quit early; otherwise proceed
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			siteAssets, err := storage.List(ctx, siteKey, false)
			if err != nil {
				log.Printf("[ERROR] Listing contents of %s: %v", siteKey, err)
				continue
			}

			for _, assetKey := range siteAssets {
				if path.Ext(assetKey) != ".crt" {
					continue
				}

				certFile, err := storage.Load(ctx, assetKey)
				if err != nil {
					return fmt.Errorf("loading certificate file %s: %v", assetKey, err)
				}
				block, _ := pem.Decode(certFile)
				if block == nil || block.Type != "CERTIFICATE" {
					return fmt.Errorf("certificate file %s does not contain PEM-encoded certificate", assetKey)
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return fmt.Errorf("certificate file %s is malformed; error parsing PEM: %v", assetKey, err)
				}

				if expiredTime := time.Since(expiresAt(cert)); expiredTime >= gracePeriod {
					log.Printf("[INFO] Certificate %s expired %s ago; cleaning up", assetKey, expiredTime)
					baseName := strings.TrimSuffix(assetKey, ".crt")
					for _, relatedAsset := range []string{
						assetKey,
						baseName + ".key",
						baseName + ".json",
					} {
						log.Printf("[INFO] Deleting %s because resource expired", relatedAsset)
						err := storage.Delete(ctx, relatedAsset)
						if err != nil {
							log.Printf("[ERROR] Cleaning up asset related to expired certificate for %s: %s: %v",
								baseName, relatedAsset, err)
						}
					}
				}
			}

			// update listing; if folder is empty, delete it
			siteAssets, err = storage.List(ctx, siteKey, false)
			if err != nil {
				continue
			}
			if len(siteAssets) == 0 {
				log.Printf("[INFO] Deleting %s because key is empty", siteKey)
				err := storage.Delete(ctx, siteKey)
				if err != nil {
					return fmt.Errorf("deleting empty site folder %s: %v", siteKey, err)
				}
			}
		}
	}
	return nil
}

// forceRenew forcefully renews cert and replaces it in the cache, and returns the new certificate. It is intended
// for use primarily in the case of cert revocation. This MUST NOT be called within a lock on cfg.certCacheMu.
func (cfg *Config) forceRenew(ctx context.Context, logger *zap.Logger, cert Certificate) (Certificate, error) {
	logger.Warn("forcefully renewing certificate",
		zap.Strings("identifiers", cert.Names),
		zap.Time("expiration", expiresAt(cert.Certificate)))

	renewName := cert.Names[0]

	// notice that we force renewal; otherwise, it might see that the
	// certificate isn't close to expiring and return, but we really
	// need a replacement certificate! see issue #4191
	err := cfg.RenewCertAsync(ctx, renewName, true)
	if err != nil {
		return cert, fmt.Errorf("unable to forcefully get new certificate for %v: %w", cert.Names, err)
	}

	return cfg.reloadManagedCertificate(ctx, cert)
}

const (
	// DefaultRenewCheckInterval is how often to check certificates for expiration.
	// Scans are very lightweight, so this can be semi-frequent. This default should
	// be smaller than <Minimum Cert Lifetime>*DefaultRenewalWindowRatio/3, which
	// gives certificates plenty of chance to be renewed on time.
	DefaultRenewCheckInterval = 10 * time.Minute

	// DefaultRenewalWindowRatio is how much of a certificate's lifetime becomes the
	// renewal window. The renewal window is the span of time at the end of the
	// certificate's validity period in which it should be renewed. A default value
	// of ~1/3 is pretty safe and recommended for most certificates.
	DefaultRenewalWindowRatio = 1.0 / 3.0
)
