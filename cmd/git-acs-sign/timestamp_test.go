package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/jaxelr/artifact-signing-sdk-go/codesigning"
	"github.com/jaxelr/git-azure-artifact-signing/internal/sshsig"
	"golang.org/x/crypto/ssh"
)

type timestampRequestFunc func(context.Context, []byte, *codesigning.TimestampOptions) (*codesigning.TimestampResult, error)

func (request timestampRequestFunc) Timestamp(ctx context.Context, data []byte, options *codesigning.TimestampOptions) (*codesigning.TimestampResult, error) {
	return request(ctx, data, options)
}

type timestampFixture struct {
	key         *ecdsa.PrivateKey
	certificate *x509.Certificate
	roots       *x509.CertPool
}

func TestTimestampSignatureKeepsVerifiedACSResponseSeparate(t *testing.T) {
	// Arrange
	signed := testSigningResult(t)
	authority := newTimestampFixture(t)
	var response []byte
	client := timestampRequestFunc(func(ctx context.Context, data []byte, options *codesigning.TimestampOptions) (*codesigning.TimestampResult, error) {
		if !bytes.Equal(data, signed.rawSignature) || options.Hash != crypto.SHA256 {
			t.Fatal("timestamp request did not cover the raw RSA signature using SHA-256")
		}
		response = authority.response(t, data)
		return &codesigning.TimestampResult{RawToken: response}, nil
	})
	// Act
	result, err := timestampSignature(context.Background(), signed, client, authority.roots)
	if err != nil {
		t.Fatal(err)
	}
	// Assert
	evidence, err := sshsig.ReadTimestamp(result.signature)
	if err != nil {
		t.Fatal(err)
	}
	if evidence != nil || !bytes.Equal(result.signature, signed.signature) || !bytes.Equal(result.timestampResponse, response) {
		t.Fatal("timestamping changed the SSH signature or lost the detached timestamp")
	}
	assertStandardSSHSignature(t, result, []byte("commit payload"))
}

func assertStandardSSHSignature(t *testing.T, result signingResult, payload []byte) {
	t.Helper()
	block, _ := pem.Decode(result.signature)
	if block == nil || len(block.Bytes) < 6 {
		t.Fatal("invalid SSH signature armor")
	}
	var envelope struct {
		Version       uint32
		PublicKey     []byte
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Signature     []byte
	}
	if err := ssh.Unmarshal(block.Bytes[6:], &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Reserved != "" {
		t.Fatal("standard SSH signatures must have an empty reserved field")
	}
	digest := sha256.Sum256(payload)
	data := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Digest        []byte
	}{envelope.Namespace, envelope.Reserved, envelope.HashAlgorithm, digest[:]})...)
	var signature ssh.Signature
	if err := ssh.Unmarshal(envelope.Signature, &signature); err != nil {
		t.Fatal(err)
	}
	if err := result.publicKey.Verify(data, &signature); err != nil {
		t.Fatalf("strict SSH verification including reserved data failed: %v", err)
	}
}

func TestTimestampSignatureFailsClosed(t *testing.T) {
	signed := testSigningResult(t)
	authority := newTimestampFixture(t)
	tests := []struct {
		name     string
		response *codesigning.TimestampResult
		err      error
	}{
		{"request failure", nil, errors.New("TSA unavailable")},
		{"missing response", nil, nil},
		{"empty response", &codesigning.TimestampResult{}, nil},
		{"invalid response", &codesigning.TimestampResult{RawToken: []byte("invalid")}, nil},
		{"untrusted response", &codesigning.TimestampResult{RawToken: authority.response(t, signed.rawSignature)}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := timestampRequestFunc(func(context.Context, []byte, *codesigning.TimestampOptions) (*codesigning.TimestampResult, error) {
				return test.response, test.err
			})
			result, err := timestampSignature(context.Background(), signed, client, x509.NewCertPool())
			if err == nil || len(result.signature) != 0 {
				t.Fatalf("timestampSignature() = %v, %v; want an error and no usable signature", result, err)
			}
		})
	}
}

func TestVerifyTimestampRejectsSigningCertificateOutsideValidity(t *testing.T) {
	authority := newTimestampFixture(t)
	signature := []byte("signature")
	response := authority.response(t, signature)
	for _, certificate := range []*x509.Certificate{
		{NotBefore: time.Now().Add(time.Hour), NotAfter: time.Now().Add(2 * time.Hour)},
		{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)},
	} {
		if _, err := verifyTimestamp(response, signature, certificate, authority.roots); err == nil || !strings.Contains(err.Error(), "validity period") {
			t.Fatalf("verifyTimestamp() error = %v, want a signing certificate validity error", err)
		}
	}
}

func TestVerifyTimestampAcceptsCertificateValidityBoundaries(t *testing.T) {
	authority := newTimestampFixture(t)
	signature := []byte("signature")
	response := authority.response(t, signature)
	proof, err := timestamp.ParseResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{NotBefore: proof.Time, NotAfter: proof.Time}
	if _, err := verifyTimestamp(response, signature, certificate, authority.roots); err != nil {
		t.Fatal(err)
	}
}

func newTimestampFixture(t *testing.T) timestampFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := timestampFixtureCertificate(t, key)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return timestampFixture{key, certificate, roots}
}

func timestampFixtureCertificate(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	usage, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test TSA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: usage}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func (authority timestampFixture) response(t *testing.T, signature []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(signature)
	proof := &timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: digest[:],
		Time: time.Now().UTC().Truncate(time.Second), Policy: asn1.ObjectIdentifier{1, 2, 3, 4},
		AddTSACertificate: true,
	}
	response, err := proof.CreateResponseWithOpts(authority.certificate, authority.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testSigningResult(t *testing.T) signingResult {
	t.Helper()
	return testSigningPayload(t, []byte("commit payload"))
}

func testSigningPayload(t *testing.T, payload []byte) signingResult {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := sshsig.Prepare(payload, "git")
	if err != nil {
		t.Fatal(err)
	}
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, prepared.Digest())
	if err != nil {
		t.Fatal(err)
	}
	result, err := assembleSignature(prepared, rawSignature, der)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
