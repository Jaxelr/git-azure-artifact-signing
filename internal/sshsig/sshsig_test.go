package sshsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
)

func TestSignatureIsAcceptedByOpenSSH(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("commit payload")
	prepared, err := Prepare(message, "git")
	if err != nil {
		t.Fatal(err)
	}
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, prepared.Digest())
	if err != nil {
		t.Fatal(err)
	}
	armoredSignature, _, err := prepared.Finish(certificate, rawSignature)
	if err != nil {
		t.Fatal(err)
	}

	signaturePath := filepath.Join(t.TempDir(), "signature")
	if err := os.WriteFile(signaturePath, armoredSignature, 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(sshKeygen, "-Y", "check-novalidate", "-n", "git", "-s", signaturePath)
	command.Stdin = bytes.NewReader(message)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen rejected signature: %v\n%s", err, output)
	}
}

func TestPrepareRejectsEmptyNamespace(t *testing.T) {
	if _, err := Prepare([]byte("message"), ""); err == nil {
		t.Fatal("Prepare() succeeded, want error")
	}
}

func TestParseCertificateAcceptsBase64EncodedDER(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	encoded := []byte(base64.StdEncoding.EncodeToString(der))
	if _, err := ParseCertificate(encoded); err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
}

func TestParseCertificateAcceptsBase64EncodedPKCS7(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	container, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	encoded := []byte(base64.StdEncoding.EncodeToString(container))
	if _, err := ParseCertificate(encoded); err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
}

func TestVerifyRS256RejectsAlteredSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0xff

	if err := VerifyRS256(&privateKey.PublicKey, digest, signature); err == nil {
		t.Fatal("VerifyRS256() succeeded, want error")
	}
}
