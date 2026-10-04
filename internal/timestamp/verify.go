package timestamp

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

func Verify(response, signature []byte, roots *x509.CertPool) (*timestamp.Timestamp, error) {
	if roots == nil {
		return nil, errors.New("timestamp verification requires trusted root certificates")
	}
	if len(signature) == 0 {
		return nil, errors.New("timestamp verification requires a nonempty RSA signature")
	}
	proof, err := timestamp.ParseResponse(response)
	if err != nil {
		return nil, fmt.Errorf("parse RFC 3161 timestamp response: %w", err)
	}
	digest := sha256.Sum256(signature)
	if proof.HashAlgorithm != crypto.SHA256 || !bytes.Equal(proof.HashedMessage, digest[:]) {
		return nil, errors.New("timestamp message imprint does not match the RSA signature's SHA-256 digest")
	}
	if proof.Time.IsZero() {
		return nil, errors.New("timestamp response has no generation time")
	}
	if err := verifyAuthority(proof, roots); err != nil {
		return nil, err
	}
	return proof, nil
}

func verifyAuthority(proof *timestamp.Timestamp, roots *x509.CertPool) error {
	token, err := pkcs7.Parse(proof.RawToken)
	if err != nil {
		return fmt.Errorf("parse timestamp token: %w", err)
	}
	signer := token.GetOnlySigner()
	if signer == nil {
		return errors.New("timestamp token must contain exactly one signer and its certificate")
	}
	if !hasTimestampUsage(signer) {
		return errors.New("timestamp authority certificate must have exclusively critical Time Stamping usage")
	}
	var contentType asn1.ObjectIdentifier
	if err := token.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType); err != nil {
		return fmt.Errorf("read timestamp content type: %w", err)
	}
	if !contentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}) {
		return errors.New("timestamp token has an invalid signed content type")
	}
	return verifyTrustedChain(token, proof.Time, roots)
}

func verifyTrustedChain(token *pkcs7.PKCS7, timestampTime time.Time, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, certificate := range token.Certificates {
		intermediates.AddCert(certificate)
	}
	if err := token.VerifyWithOpts(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   timestampTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return fmt.Errorf("verify timestamp authority signature and certificate chain: %w", err)
	}
	return nil
}

func hasTimestampUsage(certificate *x509.Certificate) bool {
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(certificate.UnknownExtKeyUsage) != 0 {
		return false
	}
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			return extension.Critical
		}
	}
	return false
}
