package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaxelr/artifact-signing-sdk-go/codesigning"
	"github.com/jaxelr/git-azure-artifact-signing/internal/sshsig"
	"golang.org/x/crypto/ssh"
)

func TestTimestampedCommitVerificationAndInspection(t *testing.T) {
	isolateInspection(t)
	payload := inspectionCommitPayload(t)
	signed := testSigningPayload(t, payload)
	authority := newTimestampFixture(t)
	client := timestampRequestFunc(func(context.Context, []byte, *codesigning.TimestampOptions) (*codesigning.TimestampResult, error) {
		return &codesigning.TimestampResult{RawToken: authority.response(t, signed.rawSignature)}, nil
	})
	result, err := timestampSignature(context.Background(), signed, client, authority.roots)
	if err != nil {
		t.Fatal(err)
	}
	commitID := writeInspectionCommit(t, payload, result)
	signature, verifiedID, err := verifiedCommitSignature(commitID)
	if err != nil {
		t.Fatal(err)
	}
	details, err := inspectSignature(signature, authority.roots)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedID != commitID || details.timestamp == nil || details.receiptPath != "" {
		t.Fatalf("commit verification/inspection lost its timestamp or required a local receipt: %s, %+v", verifiedID, details)
	}
}

func TestInspectTimestampWithoutLocalReceipt(t *testing.T) {
	isolateInspection(t)
	signed := testSigningResult(t)
	authority := newTimestampFixture(t)
	client := timestampRequestFunc(func(context.Context, []byte, *codesigning.TimestampOptions) (*codesigning.TimestampResult, error) {
		return &codesigning.TimestampResult{RawToken: authority.response(t, signed.rawSignature)}, nil
	})
	result, err := timestampSignature(context.Background(), signed, client, authority.roots)
	if err != nil {
		t.Fatal(err)
	}
	details, err := inspectSignature(result.signature, authority.roots)
	if err != nil {
		t.Fatal(err)
	}
	if details.timestamp == nil || details.receiptPath != "" || !bytes.Equal(details.certificate.Raw, signed.certificate.Raw) {
		t.Fatalf("inspection did not recover the embedded certificate and timestamp without a receipt: %+v", details)
	}
}

func TestInspectLegacySignatureWithLocalReceipt(t *testing.T) {
	isolateInspection(t)
	signed := testSigningResult(t)
	writeTestReceipt(t, signed)
	details, err := inspectSignature(signed.signature, x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if details.timestamp != nil || details.receiptPath == "" || !bytes.Equal(details.certificate.Raw, signed.certificate.Raw) {
		t.Fatalf("legacy inspection lost its receipt or invented a timestamp: %+v", details)
	}
}

func TestInspectLegacySignatureWithoutReceiptFails(t *testing.T) {
	isolateInspection(t)
	signed := testSigningResult(t)
	if _, err := inspectSignature(signed.signature, x509.NewCertPool()); err == nil {
		t.Fatal("inspection accepted a legacy signature without its certificate receipt")
	}
}

func TestInspectRejectsInvalidEmbeddedTimestamp(t *testing.T) {
	isolateInspection(t)
	signed := testSigningResult(t)
	signature, err := sshsig.AttachTimestamp(signed.signature, signed.certificate.Raw, []byte("invalid timestamp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectSignature(signature, x509.NewCertPool()); err == nil {
		t.Fatal("inspection accepted an invalid embedded timestamp")
	}
}

func TestInspectRejectsLocalReceiptCertificateMismatch(t *testing.T) {
	isolateInspection(t)
	signed := testSigningResult(t)
	signature, err := sshsig.AttachTimestamp(signed.signature, signed.certificate.Raw, []byte("timestamp"))
	if err != nil {
		t.Fatal(err)
	}
	other := testSigningResult(t)
	other.signature = signature
	writeTestReceipt(t, other)
	if _, err := inspectSignature(signature, x509.NewCertPool()); err == nil {
		t.Fatal("inspection accepted a receipt with a different embedded certificate")
	}
}

func isolateInspection(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	configPath := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", configPath)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	if output, err := exec.Command("git", "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
}

func writeTestReceipt(t *testing.T, result signingResult) {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	settings := repositorySettings{
		principal: "test@example.com", keyPath: filepath.Join(directory, ".git", "artifact-signing", "signing-key.pub"),
		allowedSignersPath: filepath.Join(directory, ".git", "artifact-signing", "allowed-signers"),
	}
	if err := writeVerificationFiles(settings, result); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "config", "--local", "artifactsigning.keyFile", settings.keyPath).CombinedOutput(); err != nil {
		t.Fatalf("git config: %v\n%s", err, output)
	}
}

func inspectionCommitPayload(t *testing.T) []byte {
	t.Helper()
	command := exec.Command("git", "hash-object", "-w", "-t", "tree", "--stdin")
	command.Stdin = bytes.NewReader(nil)
	tree, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("write tree object: %v\n%s", err, tree)
	}
	return []byte("tree " + strings.TrimSpace(string(tree)) + "\nauthor Test <test@example.com> 1700000000 +0000\ncommitter Test <test@example.com> 1700000000 +0000\n\nTimestamped commit\n")
}

func writeInspectionCommit(t *testing.T, payload []byte, result signingResult) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowed-signers")
	if err := os.WriteFile(path, append([]byte("test@example.com namespaces=\"git\" "), ssh.MarshalAuthorizedKey(result.publicKey)...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, setting := range [][2]string{{"gpg.format", "ssh"}, {"gpg.ssh.program", "ssh-keygen"}, {"gpg.ssh.allowedSignersFile", path}} {
		if err := gitRun("config", "--local", setting[0], setting[1]); err != nil {
			t.Fatal(err)
		}
	}
	header := "gpgsig " + strings.ReplaceAll(strings.TrimSuffix(string(result.signature), "\n"), "\n", "\n ")
	commit := strings.Replace(string(payload), "\n\n", "\n"+header+"\n\n", 1)
	command := exec.Command("git", "hash-object", "-w", "-t", "commit", "--stdin")
	command.Stdin = strings.NewReader(commit)
	commitID, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("write commit object: %v\n%s", err, commitID)
	}
	return strings.TrimSpace(string(commitID))
}
