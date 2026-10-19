package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/jaxelr/git-azure-artifact-signing/internal/sshsig"
	"golang.org/x/crypto/ssh"
)

type signatureInspection struct {
	receipt     certificateReceipt
	receiptPath string
	certificate *x509.Certificate
	timestamp   *timestamp.Timestamp
}

func inspect(arguments []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	receiptPath := flags.String("receipt", "", "path to a shared certificate and timestamp receipt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	arguments = flags.Args()
	revision := "HEAD"
	if len(arguments) > 1 {
		return errors.New("usage: git-acs-sign inspect [--receipt path] [revision]")
	}
	if len(arguments) == 1 {
		revision = arguments[0]
	}
	signature, commitID, err := verifiedCommitSignature(revision)
	if err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("load timestamp trust roots: %w", err)
	}
	details, err := inspectSignatureFrom(signature, roots, *receiptPath)
	if err != nil {
		return err
	}
	printInspection(commitID, details)
	return nil
}

func verifiedCommitSignature(revision string) ([]byte, string, error) {
	commitID, err := gitOutput("rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return nil, "", err
	}
	verifyOutput, err := exec.Command("git", "verify-commit", "--raw", commitID).CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("verify commit %s: %w: %s", commitID, err, strings.TrimSpace(string(verifyOutput)))
	}
	rawCommit, err := exec.Command("git", "cat-file", "commit", commitID).Output()
	if err != nil {
		return nil, "", fmt.Errorf("read commit %s: %w", commitID, err)
	}
	signature, err := extractCommitSignature(rawCommit)
	return signature, commitID, err
}

func inspectSignature(signature []byte, roots *x509.CertPool) (signatureInspection, error) {
	return inspectSignatureFrom(signature, roots, "")
}

func inspectSignatureFrom(signature []byte, roots *x509.CertPool, receiptPath string) (signatureInspection, error) {
	evidence, err := sshsig.ReadTimestamp(signature)
	if err != nil {
		return signatureInspection{}, err
	}
	var receipt certificateReceipt
	var path string
	if receiptPath == "" {
		receipt, path, err = receiptForSignature(signature, evidence)
	} else {
		path = receiptPath
		receipt, err = readReceipt(signature, path)
	}
	if err != nil {
		return signatureInspection{}, err
	}
	certificate, err := receiptCertificate(receipt)
	if err != nil {
		return signatureInspection{}, err
	}
	rawSignature, err := sshsig.RawSignature(signature, receipt.CertificateDER)
	if err != nil {
		return signatureInspection{}, err
	}
	details := signatureInspection{receipt: receipt, receiptPath: path, certificate: certificate}
	if evidence != nil {
		if !bytes.Equal(receipt.CertificateDER, evidence.CertificateDER) {
			return signatureInspection{}, errors.New("receipt certificate does not match the commit's embedded certificate")
		}
		if len(receipt.TimestampResponse) != 0 && !bytes.Equal(receipt.TimestampResponse, evidence.TimestampResponse) {
			return signatureInspection{}, errors.New("receipt timestamp does not match the commit's embedded timestamp")
		}
		receipt.TimestampResponse = evidence.TimestampResponse
		details.receipt = receipt
	}
	if len(receipt.TimestampResponse) != 0 {
		details.timestamp, err = verifyTimestamp(receipt.TimestampResponse, rawSignature, certificate, roots)
		if err != nil {
			return signatureInspection{}, err
		}
	}
	return details, nil
}

func receiptForSignature(signature []byte, evidence *sshsig.TimestampEvidence) (certificateReceipt, string, error) {
	receipt, path, err := readLocalReceipt(signature)
	if err != nil {
		return certificateReceipt{}, "", err
	}
	if receipt != nil {
		return *receipt, path, nil
	}
	if evidence == nil {
		return certificateReceipt{}, "", errors.New("no certificate receipt is available; import a matching receipt or use inspect --receipt <path>")
	}
	certificate, err := x509.ParseCertificate(evidence.CertificateDER)
	if err != nil {
		return certificateReceipt{}, "", fmt.Errorf("parse embedded signing certificate: %w", err)
	}
	publicKey, err := ssh.NewPublicKey(certificate.PublicKey)
	if err != nil {
		return certificateReceipt{}, "", fmt.Errorf("convert embedded signing certificate public key: %w", err)
	}
	return certificateReceipt{
		SignatureSHA256:   signatureID(signature),
		CertificateDER:    evidence.CertificateDER,
		SSHKeyFingerprint: ssh.FingerprintSHA256(publicKey),
		TimestampResponse: evidence.TimestampResponse,
	}, "", nil
}

func readLocalReceipt(signature []byte) (*certificateReceipt, string, error) {
	path, err := localReceiptPath(signature)
	if err != nil {
		return nil, "", err
	}
	receipt, err := readReceipt(signature, path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return &receipt, path, nil
}

func signatureID(signature []byte) string {
	hash := sha256.Sum256(signature)
	return hex.EncodeToString(hash[:])
}

func localReceiptPath(signature []byte) (string, error) {
	keyPath, err := optionalSigningKeyPath()
	if err != nil {
		return "", err
	}
	directory := filepath.Dir(keyPath)
	if keyPath == "" {
		gitDirectory, err := gitOutput("rev-parse", "--path-format=absolute", "--git-dir")
		if err != nil {
			return "", err
		}
		directory = filepath.Join(gitDirectory, "artifact-signing")
	}
	return filepath.Join(directory, "receipts", signatureID(signature)+".json"), nil
}

func readReceipt(signature []byte, path string) (certificateReceipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return certificateReceipt{}, fmt.Errorf("read certificate receipt %q: %w", path, err)
	}
	var receipt certificateReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return certificateReceipt{}, fmt.Errorf("parse certificate receipt: %w", err)
	}
	if receipt.SignatureSHA256 != signatureID(signature) {
		return certificateReceipt{}, errors.New("certificate receipt does not match the commit's signature")
	}
	return receipt, nil
}

func optionalSigningKeyPath() (string, error) {
	output, err := exec.Command("git", "config", "--path", "--get", "artifactsigning.keyFile").CombinedOutput()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 && len(output) == 0 {
			return "", nil
		}
		return "", fmt.Errorf("read signing key configuration: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func receiptCertificate(receipt certificateReceipt) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(receipt.CertificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse receipt certificate: %w", err)
	}
	publicKey, err := ssh.NewPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("convert receipt certificate public key: %w", err)
	}
	if ssh.FingerprintSHA256(publicKey) != receipt.SSHKeyFingerprint {
		return nil, errors.New("certificate receipt fingerprint does not match its certificate")
	}
	return certificate, nil
}

func printInspection(commitID string, details signatureInspection) {
	fmt.Printf("Commit:                %s\n", commitID)
	fmt.Printf("Verification:          valid Git SSH signature\n")
	if details.receiptPath == "" {
		fmt.Printf("Receipt:               unavailable; using commit-embedded certificate\n")
	} else {
		fmt.Printf("Receipt:               %s\n", details.receiptPath)
		fmt.Printf("Recorded at:           %s\n", details.receipt.RecordedAt.Format(time.RFC3339))
		fmt.Printf("Artifact endpoint:     %s\n", details.receipt.Endpoint)
		fmt.Printf("Signing account:       %s\n", details.receipt.Account)
		fmt.Printf("Certificate profile:   %s\n", details.receipt.Profile)
	}
	if details.timestamp == nil {
		fmt.Printf("Timestamp:             not recorded in receipt or signature\n")
	} else {
		fmt.Printf("Timestamp:             valid RFC 3161 proof with trusted TSA chain\n")
		fmt.Printf("Timestamp time:        %s\n", details.timestamp.Time.Format(time.RFC3339Nano))
		fmt.Printf("Timestamp serial:      %s\n", details.timestamp.SerialNumber)
		fmt.Printf("Timestamp policy:      %s\n", details.timestamp.Policy)
	}
	printCertificate(details.certificate, details.receipt.SSHKeyFingerprint)
}

func extractCommitSignature(rawCommit []byte) ([]byte, error) {
	lines := strings.Split(strings.ReplaceAll(string(rawCommit), "\r\n", "\n"), "\n")
	for index, line := range lines {
		if !strings.HasPrefix(line, "gpgsig ") {
			continue
		}
		var signature strings.Builder
		signature.WriteString(strings.TrimPrefix(line, "gpgsig "))
		signature.WriteByte('\n')
		for index++; index < len(lines) && strings.HasPrefix(lines[index], " "); index++ {
			signature.WriteString(strings.TrimPrefix(lines[index], " "))
			signature.WriteByte('\n')
		}
		return []byte(signature.String()), nil
	}
	return nil, errors.New("commit does not contain a signature")
}
