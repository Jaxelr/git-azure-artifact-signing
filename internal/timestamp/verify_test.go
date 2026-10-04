package timestamp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

type testAuthority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	roots       *x509.CertPool
}

func TestVerifyAcceptsTrustedTimestamp(t *testing.T) {
	authority := newTestAuthority(t, time.Now().Add(time.Hour), nil)
	signature := []byte("RSA signature")
	response := authority.response(t, signature, nil)
	proof, err := Verify(response, signature, authority.roots)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(signature)
	if proof.HashAlgorithm != crypto.SHA256 || !bytes.Equal(proof.HashedMessage, digest[:]) {
		t.Fatal("verified timestamp does not cover the signature's SHA-256 digest")
	}
	if proof.Time.IsZero() || len(proof.RawToken) == 0 || proof.SerialNumber == nil {
		t.Fatal("verified timestamp is missing its time, token, or serial number")
	}
}

func TestVerifyChecksChainAtTimestampTime(t *testing.T) {
	historicalTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	authority := newTestAuthority(t, historicalTime.Add(time.Hour), nil)
	signature := []byte("historical signature")
	response := authority.response(t, signature, func(proof *timestamp.Timestamp) { proof.Time = historicalTime })
	proof, err := Verify(response, signature, authority.roots)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Time.Equal(historicalTime) {
		t.Fatalf("timestamp time = %v, want %v", proof.Time, historicalTime)
	}
}

func TestVerifyRejectsWrongSignatureImprint(t *testing.T) {
	authority := newTestAuthority(t, time.Now().Add(time.Hour), nil)
	response := authority.response(t, []byte("original signature"), nil)
	if _, err := Verify(response, []byte("altered signature"), authority.roots); err == nil || !strings.Contains(err.Error(), "message imprint") {
		t.Fatalf("Verify() error = %v, want an imprint mismatch", err)
	}
}

func TestVerifyRejectsUntrustedAuthority(t *testing.T) {
	authority := newTestAuthority(t, time.Now().Add(time.Hour), nil)
	signature := []byte("signature")
	response := authority.response(t, signature, nil)
	if _, err := Verify(response, signature, x509.NewCertPool()); err == nil || !strings.Contains(err.Error(), "certificate chain") {
		t.Fatalf("Verify() error = %v, want an untrusted chain error", err)
	}
	if _, err := Verify(response, signature, nil); err == nil {
		t.Fatal("Verify() accepted a nil trust store")
	}
	if _, err := Verify(response, nil, authority.roots); err == nil {
		t.Fatal("Verify() accepted an empty RSA signature")
	}
}

func TestVerifyRejectsAuthorityOutsideTimestampValidity(t *testing.T) {
	authority := newTestAuthority(t, time.Now().Add(-time.Minute), nil)
	signature := []byte("signature")
	response := authority.response(t, signature, nil)
	if _, err := Verify(response, signature, authority.roots); err == nil || !strings.Contains(err.Error(), "certificate chain") {
		t.Fatalf("Verify() error = %v, want an authority validity error", err)
	}
}

func TestVerifyRejectsInvalidTimestampResponses(t *testing.T) {
	authority := newTestAuthority(t, time.Now().Add(time.Hour), nil)
	signature := []byte("signature")
	mutations := map[string]func(*timestamp.Timestamp){
		"missing TSA certificate": func(proof *timestamp.Timestamp) { proof.AddTSACertificate = false },
		"wrong hash algorithm":    func(proof *timestamp.Timestamp) { proof.HashAlgorithm = crypto.SHA512 },
		"missing generation time": func(proof *timestamp.Timestamp) { proof.Time = time.Time{} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			response := authority.response(t, signature, mutate)
			if _, err := Verify(response, signature, authority.roots); err == nil {
				t.Fatal("Verify() accepted invalid timestamp evidence")
			}
		})
	}
	if _, err := Verify([]byte("not DER"), signature, authority.roots); err == nil {
		t.Fatal("Verify() accepted malformed DER")
	}
}

func TestVerifyRejectsTamperedTimestampSignature(t *testing.T) {
	authority := newTestAuthority(t, time.Now().Add(time.Hour), nil)
	signature := []byte("signature")
	response := authority.response(t, signature, nil)
	response[len(response)-1] ^= 1
	if _, err := Verify(response, signature, authority.roots); err == nil {
		t.Fatal("Verify() accepted a tampered timestamp")
	}
}

func TestVerifyRequiresExclusiveCriticalTimestampUsage(t *testing.T) {
	for _, critical := range []bool{false, true} {
		t.Run(map[bool]string{false: "noncritical usage", true: "additional usage"}[critical], func(t *testing.T) {
			authority := newTestAuthority(t, time.Now().Add(time.Hour), func(certificate *x509.Certificate) {
				certificate.ExtraExtensions[0].Critical = critical
				if critical {
					value, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}, {1, 3, 6, 1, 5, 5, 7, 3, 3}})
					if err != nil {
						t.Fatal(err)
					}
					certificate.ExtraExtensions[0].Value = value
				}
			})
			signature := []byte("signature")
			response := authority.response(t, signature, nil)
			if _, err := Verify(response, signature, authority.roots); err == nil || !strings.Contains(err.Error(), "Time Stamping usage") {
				t.Fatalf("Verify() error = %v, want an invalid TSA usage error", err)
			}
		})
	}
}

func newTestAuthority(t *testing.T, rootExpiry time.Time, mutate func(*x509.Certificate)) testAuthority {
	t.Helper()
	rootKey := testECKey(t)
	root := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: rootExpiry,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, rootKey)
	authority := testAuthority{key: testECKey(t), roots: x509.NewCertPool()}
	authority.roots.AddCert(root)
	template := timestampCertificateTemplate(t)
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &authority.key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	authority.certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func timestampCertificateTemplate(t *testing.T) *x509.Certificate {
	t.Helper()
	value, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test TSA"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: value}},
	}
}

func testECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testCertificate(t *testing.T, template *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
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

func (authority testAuthority) response(t *testing.T, signature []byte, mutate func(*timestamp.Timestamp)) []byte {
	t.Helper()
	digest := sha256.Sum256(signature)
	proof := &timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: digest[:],
		Time: time.Now().UTC().Truncate(time.Second), Policy: asn1.ObjectIdentifier{1, 2, 3, 4},
		AddTSACertificate: true,
	}
	if mutate != nil {
		mutate(proof)
	}
	response, err := proof.CreateResponseWithOpts(authority.certificate, authority.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
