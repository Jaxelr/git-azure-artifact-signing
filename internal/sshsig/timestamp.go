package sshsig

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type TimestampEvidence struct {
	Version           int    `json:"version"`
	CertificateDER    []byte `json:"certificateDer"`
	TimestampResponse []byte `json:"timestampResponse"`
	Signature         []byte `json:"-"`
}

type signatureEnvelope struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      []byte
	HashAlgorithm string
	Signature     []byte
}

func AttachTimestamp(signature, certificateDER, response []byte) ([]byte, error) {
	envelope, err := decodeEnvelope(signature)
	if err != nil {
		return nil, err
	}
	if len(envelope.Reserved) != 0 {
		return nil, errors.New("SSH signature already contains reserved data")
	}
	envelope.Reserved, err = json.Marshal(TimestampEvidence{
		Version:           1,
		CertificateDER:    certificateDER,
		TimestampResponse: response,
	})
	if err != nil {
		return nil, fmt.Errorf("encode timestamp evidence: %w", err)
	}
	if _, err := envelopeTimestamp(envelope); err != nil {
		return nil, err
	}
	return armor(append(bytes.Clone(magic), ssh.Marshal(envelope)...)), nil
}

func ReadTimestamp(signature []byte) (*TimestampEvidence, error) {
	envelope, err := decodeEnvelope(signature)
	if err != nil {
		return nil, err
	}
	if len(envelope.Reserved) == 0 {
		return nil, nil
	}
	return envelopeTimestamp(envelope)
}

func decodeEnvelope(signature []byte) (signatureEnvelope, error) {
	block, rest := pem.Decode(signature)
	if block == nil || block.Type != armorType || len(bytes.TrimSpace(rest)) != 0 {
		return signatureEnvelope{}, errors.New("invalid SSH signature armor")
	}
	if !bytes.HasPrefix(block.Bytes, magic) {
		return signatureEnvelope{}, errors.New("invalid SSH signature preamble")
	}
	var envelope signatureEnvelope
	if err := ssh.Unmarshal(block.Bytes[len(magic):], &envelope); err != nil {
		return signatureEnvelope{}, fmt.Errorf("decode SSH signature: %w", err)
	}
	if envelope.Version != version || envelope.Namespace != "git" || envelope.HashAlgorithm != hashAlgorithm {
		return signatureEnvelope{}, errors.New("unsupported Git SSH signature format")
	}
	return envelope, nil
}

func envelopeTimestamp(envelope signatureEnvelope) (*TimestampEvidence, error) {
	var evidence TimestampEvidence
	if err := json.Unmarshal(envelope.Reserved, &evidence); err != nil {
		return nil, fmt.Errorf("decode timestamp evidence: %w", err)
	}
	if evidence.Version != 1 || len(evidence.CertificateDER) == 0 || len(evidence.TimestampResponse) == 0 {
		return nil, errors.New("unsupported or incomplete timestamp evidence")
	}
	certificate, err := ParseCertificate(evidence.CertificateDER)
	if err != nil {
		return nil, err
	}
	publicKey, err := ssh.NewPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("convert timestamp evidence certificate public key: %w", err)
	}
	if !bytes.Equal(publicKey.Marshal(), envelope.PublicKey) {
		return nil, errors.New("timestamp evidence certificate does not match the SSH signing key")
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(envelope.Signature, &signature); err != nil {
		return nil, fmt.Errorf("decode timestamped RSA signature: %w", err)
	}
	if signature.Format != rsaSignatureFormat || len(signature.Blob) == 0 || len(signature.Rest) != 0 {
		return nil, errors.New("unsupported timestamped RSA signature format")
	}
	evidence.Signature = signature.Blob
	return &evidence, nil
}
