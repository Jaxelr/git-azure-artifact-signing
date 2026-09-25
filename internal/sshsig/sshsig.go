package sshsig

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/digitorus/pkcs7"
	"golang.org/x/crypto/ssh"
)

const (
	armorType          = "SSH SIGNATURE"
	hashAlgorithm      = "sha256"
	rsaSignatureFormat = "rsa-sha2-256"
	version            = uint32(1)
)

var magic = []byte("SSHSIG")

type Prepared struct {
	namespace string
	digest    []byte
}

func Prepare(message []byte, namespace string) (Prepared, error) {
	if namespace == "" {
		return Prepared{}, errors.New("SSH signature namespace cannot be empty")
	}

	messageDigest := sha256.Sum256(message)

	var signedData bytes.Buffer
	signedData.Write(magic)
	writeString(&signedData, []byte(namespace))
	writeString(&signedData, nil)
	writeString(&signedData, []byte(hashAlgorithm))
	writeString(&signedData, messageDigest[:])

	digest := sha256.Sum256(signedData.Bytes())
	return Prepared{namespace: namespace, digest: digest[:]}, nil
}

func (p Prepared) Digest() []byte {
	return bytes.Clone(p.digest)
}

func (p Prepared) Finish(certificateBytes, signature []byte) ([]byte, ssh.PublicKey, error) {
	certificate, err := ParseCertificate(certificateBytes)
	if err != nil {
		return nil, nil, err
	}
	if _, ok := certificate.PublicKey.(*rsa.PublicKey); !ok {
		return nil, nil, fmt.Errorf("unsupported Artifact Signing public key type %T; RSA is required", certificate.PublicKey)
	}

	publicKey, err := ssh.NewPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("convert signing certificate public key to SSH: %w", err)
	}

	var signatureBlob bytes.Buffer
	writeString(&signatureBlob, []byte(rsaSignatureFormat))
	writeString(&signatureBlob, signature)

	var envelope bytes.Buffer
	envelope.Write(magic)
	if err := binary.Write(&envelope, binary.BigEndian, version); err != nil {
		return nil, nil, fmt.Errorf("write SSH signature version: %w", err)
	}
	writeString(&envelope, publicKey.Marshal())
	writeString(&envelope, []byte(p.namespace))
	writeString(&envelope, nil)
	writeString(&envelope, []byte(hashAlgorithm))
	writeString(&envelope, signatureBlob.Bytes())

	return armor(envelope.Bytes()), publicKey, nil
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}

	certificate, parseErr := parseLeafCertificate(data)
	if parseErr == nil {
		return certificate, nil
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	bytesWritten, decodeErr := base64.StdEncoding.Decode(decoded, bytes.TrimSpace(data))
	if decodeErr != nil {
		return nil, fmt.Errorf("parse Artifact Signing certificate: %w", parseErr)
	}
	certificate, parseErr = parseLeafCertificate(decoded[:bytesWritten])
	if parseErr != nil {
		return nil, fmt.Errorf("parse base64 Artifact Signing certificate: %w", parseErr)
	}
	return certificate, nil
}

func parseLeafCertificate(data []byte) (*x509.Certificate, error) {
	if certificates, err := x509.ParseCertificates(data); err == nil {
		return findLeaf(certificates)
	}

	container, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	return findLeaf(container.Certificates)
}

func findLeaf(certificates []*x509.Certificate) (*x509.Certificate, error) {
	for _, candidate := range certificates {
		isIssuer := false
		for _, certificate := range certificates {
			if candidate != certificate && bytes.Equal(candidate.RawSubject, certificate.RawIssuer) {
				isIssuer = true
				break
			}
		}
		if !isIssuer {
			return candidate, nil
		}
	}
	return nil, errors.New("certificate collection does not contain a leaf certificate")
}

func writeString(destination *bytes.Buffer, value []byte) {
	_ = binary.Write(destination, binary.BigEndian, uint32(len(value)))
	destination.Write(value)
}

func armor(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)
	var result strings.Builder
	result.WriteString("-----BEGIN ")
	result.WriteString(armorType)
	result.WriteString("-----\n")
	for len(encoded) > 0 {
		lineLength := min(70, len(encoded))
		result.WriteString(encoded[:lineLength])
		result.WriteByte('\n')
		encoded = encoded[lineLength:]
	}
	result.WriteString("-----END ")
	result.WriteString(armorType)
	result.WriteString("-----\n")
	return []byte(result.String())
}

func VerifyRS256(publicKey crypto.PublicKey, digest, signature []byte) error {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported public key type %T", publicKey)
	}
	if err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, signature); err != nil {
		return fmt.Errorf("verify Artifact Signing response: %w", err)
	}
	return nil
}
