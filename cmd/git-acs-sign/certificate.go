package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func printCertificate(certificate *x509.Certificate, fingerprint string) {
	fmt.Printf("Subject:               %s\n", certificate.Subject)
	fmt.Printf("Issuer:                %s\n", certificate.Issuer)
	fmt.Printf("Serial number:         %s\n", strings.ToUpper(certificate.SerialNumber.Text(16)))
	fmt.Printf("SHA-256 thumbprint:    %s\n", certificateThumbprint(certificate))
	fmt.Printf("SSH key fingerprint:   %s\n", fingerprint)
	fmt.Printf("Valid from:            %s\n", certificate.NotBefore.Format(time.RFC3339))
	fmt.Printf("Valid until:           %s\n", certificate.NotAfter.Format(time.RFC3339))
	fmt.Printf("Public key algorithm:  %s%s\n", certificate.PublicKeyAlgorithm, publicKeyDetails(certificate))
	fmt.Printf("Signature algorithm:   %s\n", certificate.SignatureAlgorithm)
	fmt.Printf("Key usage:             %s\n", strings.Join(keyUsageNames(certificate.KeyUsage), ", "))
	fmt.Printf("Extended key usage:    %s\n", strings.Join(extendedKeyUsageNames(certificate.ExtKeyUsage), ", "))
	if len(certificate.UnknownExtKeyUsage) > 0 {
		unknown := make([]string, 0, len(certificate.UnknownExtKeyUsage))
		for _, oid := range certificate.UnknownExtKeyUsage {
			unknown = append(unknown, oid.String())
		}
		fmt.Printf("Other extended usage:  %s\n", strings.Join(unknown, ", "))
	}
}

func certificateThumbprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(encoded)/2)
	for index := 0; index < len(encoded); index += 2 {
		parts = append(parts, encoded[index:index+2])
	}
	return strings.Join(parts, ":")
}

func publicKeyDetails(certificate *x509.Certificate) string {
	if key, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
		return fmt.Sprintf(" (%d bits)", key.N.BitLen())
	}
	return ""
}

func keyUsageNames(usage x509.KeyUsage) []string {
	names := []struct {
		value x509.KeyUsage
		name  string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Signing"},
		{x509.KeyUsageCRLSign, "CRL Signing"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	var result []string
	for _, candidate := range names {
		if usage&candidate.value != 0 {
			result = append(result, candidate.name)
		}
	}
	if len(result) == 0 {
		return []string{"none"}
	}
	return result
}

func extendedKeyUsageNames(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "Server Authentication",
		x509.ExtKeyUsageClientAuth:                     "Client Authentication",
		x509.ExtKeyUsageCodeSigning:                    "Code Signing",
		x509.ExtKeyUsageEmailProtection:                "Email Protection",
		x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
	}
	result := make([]string, 0, len(usages))
	for _, usage := range usages {
		if name, ok := names[usage]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("unknown (%d)", usage))
		}
	}
	if len(result) == 0 {
		return []string{"none"}
	}
	return result
}
