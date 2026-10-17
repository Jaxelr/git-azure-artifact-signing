package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaxelr/artifact-signing-sdk-go/codesigning"
	"github.com/jaxelr/git-azure-artifact-signing/internal/config"
	"github.com/jaxelr/git-azure-artifact-signing/internal/sshsig"
	"golang.org/x/crypto/ssh"
)

const defaultMetadataPath = `C:\tools\AcsUnitTest\metadata.scus.json`

type repositorySettings struct {
	metadataPath       string
	principal          string
	keyPath            string
	allowedSignersPath string
}

type signingResult struct {
	signature    []byte
	rawSignature []byte
	publicKey    ssh.PublicKey
	certificate  *x509.Certificate
	metadata     config.Metadata
}

type certificateReceipt struct {
	SignatureSHA256   string    `json:"signatureSha256"`
	SSHKeyFingerprint string    `json:"sshKeyFingerprint"`
	RecordedAt        time.Time `json:"recordedAt"`
	Endpoint          string    `json:"endpoint"`
	Account           string    `json:"account"`
	Profile           string    `json:"profile"`
	CertificateDER    []byte    `json:"certificateDer"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "git-acs-sign: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) > 0 && arguments[0] == "setup" {
		return setup(arguments[1:])
	}
	if len(arguments) > 0 && arguments[0] == "inspect" {
		return inspect(arguments[1:])
	}

	operation := argumentValue(arguments, "-Y")
	if operation != "sign" {
		return forwardToSSHKeygen(arguments)
	}

	namespace := argumentValue(arguments, "-n")
	if namespace == "" {
		return errors.New("Git did not provide an SSH signature namespace")
	}

	inputPath := signingInputPath(arguments)
	var payload []byte
	var err error
	if inputPath == "" {
		payload, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read Git signing payload: %w", err)
		}
	} else {
		payload, err = os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("read Git signing payload %q: %w", inputPath, err)
		}
	}

	settings, err := loadRepositorySettings()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := sign(ctx, payload, namespace, settings.metadataPath)
	if err != nil {
		return err
	}
	if err := writeVerificationFiles(settings, result); err != nil {
		return err
	}
	if inputPath != "" {
		if err := os.WriteFile(inputPath+".sig", result.signature, 0o600); err != nil {
			return fmt.Errorf("write SSH signature file: %w", err)
		}
	} else if _, err := os.Stdout.Write(result.signature); err != nil {
		return fmt.Errorf("write SSH signature: %w", err)
	}
	return nil
}

func setup(arguments []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	metadataPath := flags.String("metadata", defaultMetadataPath, "path to Artifact Signing metadata JSON")
	programPath := flags.String("program", "", "absolute path to the built git-acs-sign executable")
	principal := flags.String("principal", "", "identity recorded in Git's allowed signers file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	absoluteMetadataPath, err := filepath.Abs(*metadataPath)
	if err != nil {
		return fmt.Errorf("resolve metadata path: %w", err)
	}
	if _, err := config.Load(absoluteMetadataPath); err != nil {
		return err
	}

	absoluteProgramPath := *programPath
	if absoluteProgramPath == "" {
		absoluteProgramPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("resolve signer executable: %w", err)
		}
	}
	absoluteProgramPath, err = filepath.Abs(absoluteProgramPath)
	if err != nil {
		return fmt.Errorf("resolve signer executable path: %w", err)
	}

	if *principal == "" {
		*principal, err = gitOutput("config", "--get", "user.email")
		if err != nil || *principal == "" {
			return errors.New("principal is required because Git user.email is not configured")
		}
	}

	gitDirectory, err := gitOutput("rev-parse", "--path-format=absolute", "--git-dir")
	if err != nil {
		return errors.New("setup must be run inside a Git repository")
	}
	stateDirectory := filepath.Join(gitDirectory, "artifact-signing")
	settings := repositorySettings{
		metadataPath:       absoluteMetadataPath,
		principal:          *principal,
		keyPath:            filepath.Join(stateDirectory, "signing-key.pub"),
		allowedSignersPath: filepath.Join(stateDirectory, "allowed-signers"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := sign(ctx, []byte("Artifact Signing Git setup validation\n"), "git", settings.metadataPath)
	if err != nil {
		return fmt.Errorf("validate Artifact Signing access: %w", err)
	}
	if err := writeVerificationFiles(settings, result); err != nil {
		return err
	}

	values := [][2]string{
		{"artifactsigning.metadataFile", settings.metadataPath},
		{"artifactsigning.principal", settings.principal},
		{"artifactsigning.keyFile", settings.keyPath},
		{"artifactsigning.allowedSignersFile", settings.allowedSignersPath},
		{"gpg.format", "ssh"},
		{"gpg.ssh.program", absoluteProgramPath},
		{"gpg.ssh.allowedSignersFile", settings.allowedSignersPath},
		{"user.signingKey", settings.keyPath},
		{"commit.gpgSign", "true"},
	}
	for _, value := range values {
		if err := gitRun("config", "--local", value[0], value[1]); err != nil {
			return err
		}
	}

	fmt.Printf("Configured this repository to sign commits as %s with Artifact Signing.\n", settings.principal)
	return nil
}

func sign(ctx context.Context, payload []byte, namespace, metadataPath string) (signingResult, error) {
	metadata, err := config.Load(metadataPath)
	if err != nil {
		return signingResult{}, err
	}
	prepared, err := sshsig.Prepare(payload, namespace)
	if err != nil {
		return signingResult{}, err
	}

	signed, err := signArtifact(ctx, metadata, prepared)
	if err != nil {
		return signingResult{}, err
	}
	signed.metadata = metadata
	roots, err := x509.SystemCertPool()
	if err != nil {
		return signingResult{}, fmt.Errorf("load timestamp trust roots: %w", err)
	}
	return timestampSignature(ctx, signed, codesigning.NewTimestampClient(codesigning.DefaultMicrosoftTSAURL, nil), roots)
}

func assembleSignature(prepared sshsig.Prepared, rawSignature, certificateBytes []byte) (signingResult, error) {
	if len(rawSignature) == 0 {
		return signingResult{}, errors.New("Artifact Signing returned an empty signature")
	}
	if len(certificateBytes) == 0 {
		return signingResult{}, errors.New("Artifact Signing returned no signing certificate")
	}
	certificate, err := sshsig.ParseCertificate(certificateBytes)
	if err != nil {
		return signingResult{}, fmt.Errorf("parse Artifact Signing response certificate: %w", err)
	}
	if err := sshsig.VerifyRS256(certificate.PublicKey, prepared.Digest(), rawSignature); err != nil {
		return signingResult{}, err
	}

	signature, publicKey, err := prepared.Finish(certificateBytes, rawSignature)
	if err != nil {
		return signingResult{}, err
	}
	return signingResult{
		signature:    signature,
		rawSignature: rawSignature,
		publicKey:    publicKey,
		certificate:  certificate,
	}, nil
}

func loadRepositorySettings() (repositorySettings, error) {
	settings := repositorySettings{}
	var err error
	settings.metadataPath, err = gitOutput("config", "--path", "--get", "artifactsigning.metadataFile")
	if err != nil || settings.metadataPath == "" {
		if fromEnvironment := os.Getenv("ACS_METADATA_PATH"); fromEnvironment != "" {
			settings.metadataPath = fromEnvironment
		} else {
			settings.metadataPath = defaultMetadataPath
		}
	}
	settings.principal, err = requiredGitConfig("artifactsigning.principal")
	if err != nil {
		return repositorySettings{}, err
	}
	settings.keyPath, err = requiredGitConfig("artifactsigning.keyFile")
	if err != nil {
		return repositorySettings{}, err
	}
	settings.allowedSignersPath, err = requiredGitConfig("artifactsigning.allowedSignersFile")
	if err != nil {
		return repositorySettings{}, err
	}
	return settings, nil
}

func writeVerificationFiles(settings repositorySettings, result signingResult) error {
	if err := os.MkdirAll(filepath.Dir(settings.keyPath), 0o700); err != nil {
		return fmt.Errorf("create Artifact Signing state directory: %w", err)
	}

	authorizedKey := bytes.TrimSpace(ssh.MarshalAuthorizedKey(result.publicKey))
	if err := os.WriteFile(settings.keyPath, append(authorizedKey, '\n'), 0o600); err != nil {
		return fmt.Errorf("write signing public key: %w", err)
	}

	allowedSigner := fmt.Sprintf("%s namespaces=\"git\" %s\n", settings.principal, authorizedKey)
	if err := os.WriteFile(settings.allowedSignersPath, []byte(allowedSigner), 0o600); err != nil {
		return fmt.Errorf("write allowed signers file: %w", err)
	}

	signatureHash := sha256.Sum256(result.signature)
	receipt := certificateReceipt{
		SignatureSHA256:   hex.EncodeToString(signatureHash[:]),
		SSHKeyFingerprint: ssh.FingerprintSHA256(result.publicKey),
		RecordedAt:        time.Now().UTC(),
		Endpoint:          result.metadata.Endpoint,
		Account:           result.metadata.CodeSigningAccountName,
		Profile:           result.metadata.CertificateProfileName,
		CertificateDER:    result.certificate.Raw,
	}
	receiptData, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize certificate receipt: %w", err)
	}
	receiptDirectory := filepath.Join(filepath.Dir(settings.keyPath), "receipts")
	if err := os.MkdirAll(receiptDirectory, 0o700); err != nil {
		return fmt.Errorf("create certificate receipt directory: %w", err)
	}
	receiptPath := filepath.Join(receiptDirectory, receipt.SignatureSHA256+".json")
	if err := os.WriteFile(receiptPath, append(receiptData, '\n'), 0o600); err != nil {
		return fmt.Errorf("write certificate receipt: %w", err)
	}
	return nil
}

func requiredGitConfig(key string) (string, error) {
	value, err := gitOutput("config", "--path", "--get", key)
	if err != nil || value == "" {
		return "", fmt.Errorf("missing local Git configuration %s; run scripts\\setup.ps1", key)
	}
	return value, nil
}

func argumentValue(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

func signingInputPath(arguments []string) string {
	for index := len(arguments) - 1; index >= 0; index-- {
		if strings.HasPrefix(arguments[index], "-") {
			continue
		}
		if index > 0 {
			switch arguments[index-1] {
			case "-Y", "-n", "-f", "-O":
				continue
			}
		}
		return arguments[index]
	}
	return ""
}

func forwardToSSHKeygen(arguments []string) error {
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return errors.New("ssh-keygen is required to verify Git SSH signatures")
	}
	command := exec.Command(path, arguments...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("ssh-keygen: %w", err)
	}
	return nil
}

func gitOutput(arguments ...string) (string, error) {
	command := exec.Command("git", arguments...)
	var stderr strings.Builder
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %s", strings.Join(arguments, " "), strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(output)), nil
}

func gitRun(arguments ...string) error {
	command := exec.Command("git", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
