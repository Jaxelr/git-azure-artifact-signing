package sshsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type signedPayload struct {
	signature      []byte
	rawSignature   []byte
	certificateDER []byte
	publicKey      ssh.PublicKey
}

func TestTimestampEvidenceRoundTrip(t *testing.T) {
	signed := signTestPayload(t, []byte("commit payload"))
	response := []byte("RFC 3161 response")
	signature, err := AttachTimestamp(signed.signature, signed.certificateDER, response)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ReadTimestamp(signature)
	if err != nil {
		t.Fatal(err)
	}
	if evidence == nil || evidence.Version != 1 || !bytes.Equal(evidence.CertificateDER, signed.certificateDER) ||
		!bytes.Equal(evidence.Signature, signed.rawSignature) || !bytes.Equal(evidence.TimestampResponse, response) {
		t.Fatalf("ReadTimestamp() = %+v, want the original signature, certificate, and timestamp", evidence)
	}
	legacy, err := ReadTimestamp(signed.signature)
	if err != nil || legacy != nil {
		t.Fatalf("ReadTimestamp(legacy) = %v, %v; want nil, nil", legacy, err)
	}
}

func TestTimestampedSignatureIsAcceptedByOpenSSH(t *testing.T) {
	message := []byte("commit payload")
	signed := signTestPayload(t, message)
	signature, err := AttachTimestamp(signed.signature, signed.certificateDER, []byte("timestamp response"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signature")
	if err := os.WriteFile(path, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", "git", "-s", path)
	command.Stdin = bytes.NewReader(message)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("OpenSSH rejected the timestamped signature: %v\n%s", err, output)
	}
}

func TestTimestampedCommitIsAcceptedByGit(t *testing.T) {
	directory := t.TempDir()
	runTestGit(t, directory, []string{"init", "--quiet"}, nil)
	tree := runTestGit(t, directory, []string{"hash-object", "-w", "-t", "tree", "--stdin"}, nil)
	message := []byte("tree " + tree + "\nauthor Test <test@example.com> 1700000000 +0000\ncommitter Test <test@example.com> 1700000000 +0000\n\nTimestamped commit\n")
	signed := signTestPayload(t, message)
	signature, err := AttachTimestamp(signed.signature, signed.certificateDER, []byte("timestamp response"))
	if err != nil {
		t.Fatal(err)
	}
	allowedSigners := filepath.Join(directory, "allowed-signers")
	key := "test@example.com namespaces=\"git\" " + string(ssh.MarshalAuthorizedKey(signed.publicKey))
	if err := os.WriteFile(allowedSigners, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	header := "gpgsig " + strings.ReplaceAll(strings.TrimSuffix(string(signature), "\n"), "\n", "\n ")
	commit := strings.Replace(string(message), "\n\n", "\n"+header+"\n\n", 1)
	commitID := runTestGit(t, directory, []string{"hash-object", "-w", "-t", "commit", "--stdin"}, []byte(commit))
	output := runTestGit(t, directory, []string{
		"-c", "gpg.format=ssh", "-c", "gpg.ssh.program=ssh-keygen",
		"-c", "gpg.ssh.allowedSignersFile=" + allowedSigners, "verify-commit", "--raw", commitID,
	}, nil)
	if !strings.Contains(output, "Good \"git\" signature") {
		t.Fatalf("Git verification did not report a valid signature: %s", output)
	}
}

func TestTimestampEvidenceRejectsCertificateMismatch(t *testing.T) {
	signed := signTestPayload(t, []byte("payload"))
	other := signTestPayload(t, []byte("other payload"))
	if _, err := AttachTimestamp(signed.signature, other.certificateDER, []byte("response")); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("AttachTimestamp() error = %v, want a certificate/key mismatch", err)
	}
}

func TestTimestampEvidenceRejectsInvalidData(t *testing.T) {
	signed := signTestPayload(t, []byte("payload"))
	if _, err := AttachTimestamp(signed.signature, signed.certificateDER, nil); err == nil {
		t.Fatal("AttachTimestamp() accepted an empty timestamp")
	}
	for _, signature := range [][]byte{[]byte("not a signature"), append(bytes.Clone(signed.signature), []byte("trailing data")...)} {
		if _, err := ReadTimestamp(signature); err == nil {
			t.Fatal("ReadTimestamp() accepted malformed signature data")
		}
	}
}

func TestTimestampEvidenceRejectsUnsupportedVersionAndDuplicate(t *testing.T) {
	signed := signTestPayload(t, []byte("payload"))
	signature, err := AttachTimestamp(signed.signature, signed.certificateDER, []byte("response"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AttachTimestamp(signature, signed.certificateDER, []byte("other response")); err == nil {
		t.Fatal("AttachTimestamp() replaced existing reserved data")
	}
	envelope, err := decodeEnvelope(signature)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Reserved = bytes.Replace(envelope.Reserved, []byte(`"version":1`), []byte(`"version":2`), 1)
	if _, err := ReadTimestamp(armor(append(bytes.Clone(magic), ssh.Marshal(envelope)...))); err == nil {
		t.Fatal("ReadTimestamp() accepted an unsupported evidence version")
	}
}

func signTestPayload(t *testing.T, message []byte) signedPayload {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testSigningCertificate(t, key)
	prepared, err := Prepare(message, "git")
	if err != nil {
		t.Fatal(err)
	}
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, prepared.Digest())
	if err != nil {
		t.Fatal(err)
	}
	signature, publicKey, err := prepared.Finish(certificate, rawSignature)
	if err != nil {
		t.Fatal(err)
	}
	return signedPayload{signature, rawSignature, certificate, publicKey}
}

func testSigningCertificate(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func runTestGit(t *testing.T, directory string, arguments []string, input []byte) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}
