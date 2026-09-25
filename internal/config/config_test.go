package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.json")
	err := os.WriteFile(path, []byte(`{
		"Endpoint": "https://example.codesigning.azure.net/",
		"CodeSigningAccountName": "account",
		"CertificateProfileName": "profile"
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if got.Endpoint != "https://example.codesigning.azure.net" {
		t.Fatalf("Endpoint = %q", got.Endpoint)
	}
	if got.CodeSigningAccountName != "account" {
		t.Fatalf("CodeSigningAccountName = %q", got.CodeSigningAccountName)
	}
	if got.CertificateProfileName != "profile" {
		t.Fatalf("CertificateProfileName = %q", got.CertificateProfileName)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{name: "missing endpoint", json: `{"CodeSigningAccountName":"account","CertificateProfileName":"profile"}`},
		{name: "non-HTTPS endpoint", json: `{"Endpoint":"http://example.com","CodeSigningAccountName":"account","CertificateProfileName":"profile"}`},
		{name: "missing account", json: `{"Endpoint":"https://example.com","CertificateProfileName":"profile"}`},
		{name: "missing profile", json: `{"Endpoint":"https://example.com","CodeSigningAccountName":"account"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metadata.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := Load(path); err == nil {
				t.Fatal("Load() succeeded, want error")
			}
		})
	}
}
