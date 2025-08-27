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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/mholt/acmez/v3/acme"
)

func TestSaveCertResource(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\t"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\n"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte(" "), []byte(""))
	if !reflect.DeepEqual(cert, siteData) {
		t.Errorf("Expected '%+v' to match '%+v'\n%s\n%s", cert.IssuerData, siteData.IssuerData, string(cert.IssuerData), string(siteData.IssuerData))
	}
}

func mustJSON(val any) []byte {
	result, err := json.Marshal(val)
	if err != nil {
		panic("marshaling JSON: " + err.Error())
	}
	return result
}

func TestLoadCertResourceWithMissingPrivateKey(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp_missing_key"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	// First save the certificate normally
	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error saving, got: %v", err)
	}

	// Now simulate a storage backend that doesn't provide private keys
	// by manually deleting the private key file
	privateKeyPath := testConfig.Storage.(*FileStorage).Filename(StorageKeys.SitePrivateKey(am.IssuerKey(), domain))
	err = os.Remove(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to remove private key file: %v", err)
	}

	// Try to load certificate (should succeed gracefully without private key)
	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}

	// Private key should be nil when not available from storage
	if siteData.PrivateKeyPEM != nil {
		t.Error("Expected private key to be nil when not available from storage")
	}

	// Certificate should still be loaded correctly
	if !reflect.DeepEqual(siteData.CertificatePEM, cert.CertificatePEM) {
		t.Error("Certificate PEM should match")
	}
}

// Tests for the new functionality will be added in Phase 3
