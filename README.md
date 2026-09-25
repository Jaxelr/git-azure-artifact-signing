# Git commit signing with Azure Artifact Signing

`git-acs-sign` uses the
[Artifact Signing SDK for Go](https://github.com/Jaxelr/artifact-signing-sdk-go)
to Git's SSH signing interface. Git supplies the commit payload, `git-acs-sign`
constructs an OpenSSH SSHSIG digest, and Azure Artifact Signing signs that digest
with the certificate profile's private key.

The helper works on Windows and Linux. It supports:

- automatic or explicit signed Git commits;
- Git/OpenSSH signature verification;
- local verification of every Artifact Signing response before Git receives it;
- inspection of the exact X.509 leaf certificate returned for a signed commit; and
- local certificate receipts that are never added to source control.

## How it works

1. Git invokes `git-acs-sign` through `gpg.ssh.program`.
2. The helper hashes the Git payload according to the SSHSIG format.
3. `DefaultAzureCredential` authenticates to Azure.
4. Artifact Signing signs the SSHSIG digest with `RS256`.
5. The helper verifies the returned signature against the returned X.509 certificate.
6. The helper emits a standard SSH signature for Git.
7. Git verifies that signature with OpenSSH and the local allowed-signers file.

Git stores the SSH public key and SSH signature in the commit. The full X.509
certificate is stored separately in a local receipt under
`.git/artifact-signing/receipts`.

## Prerequisites

Install the following on Windows or Linux:

- Go 1.25 or later;
- Git 2.34 or later;
- OpenSSH `ssh-keygen` with `-Y` signing support;
- Azure CLI; and
- access to an Azure Artifact Signing account and certificate profile.

Confirm the tools are available:

```text
go version
git --version
ssh-keygen -Y check-novalidate
az version
```

`ssh-keygen -Y check-novalidate` prints usage or a missing-argument error when
SSH signature support is installed. An "unknown option" or "unsupported operation"
response can indicate an older OpenSSH installation.

## Create the Artifact Signing metadata file

Create a local JSON file with the Artifact Signing endpoint, account, and
certificate profile:

```json
{
  "Endpoint": "https://<region>.codesigning.azure.net",
  "CodeSigningAccountName": "<account-name>",
  "CertificateProfileName": "<profile-name>"
}
```

This file identifies the signing resource; it does not contain a private key.
Do not add environment-specific metadata files to source control.

Example locations:

- Windows: `C:\tools\AcsUnitTest\metadata.scus.json`
- Linux: `$HOME/.config/git-acs-sign/metadata.json`

On Linux, restrict access to the file:

```bash
chmod 600 "$HOME/.config/git-acs-sign/metadata.json"
```

## Authenticate to Azure

The helper uses Azure Identity's `DefaultAzureCredential`. For local interactive
use, sign in with Azure CLI:

```text
az login
az account show
```

If the Artifact Signing resource belongs to a specific tenant:

```text
az login --tenant <tenant-id>
```

The authenticated identity must have permission to sign with the configured
Artifact Signing certificate profile.

## Configure Git identity

Set the name and email that should appear on commits. The same email is used as
the default SSH signing principal:

```text
git config user.name "Your Name"
git config user.email "you@example.com"
```

Omit `--global` to configure only the current repository. Add `--global` if the
identity should be the default for all repositories.

## Windows setup

From the root of this repository, use the PowerShell setup script:

```powershell
.\scripts\setup.ps1 `
    -MetadataPath 'C:\tools\AcsUnitTest\metadata.scus.json' `
    -Principal 'you@example.com'
```

The script builds the helper into `.git\artifact-signing`, validates Azure access,
retrieves the current signing certificate, and configures this repository.

If the PowerShell execution policy blocks the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 `
    -MetadataPath 'C:\tools\AcsUnitTest\metadata.scus.json' `
    -Principal 'you@example.com'
```

### Configure another repository on Windows

Install the helper:

```powershell
go install .\cmd\git-acs-sign
$signer = Join-Path (go env GOPATH) 'bin\git-acs-sign.exe'
```

Then change to the target repository and configure it:

```powershell
Set-Location 'C:\src\target-repository'
& $signer setup `
    --metadata 'C:\tools\AcsUnitTest\metadata.scus.json' `
    --principal 'you@example.com' `
    --program $signer
```

## Linux setup

Make the Bash setup script executable after cloning:

```bash
chmod +x scripts/setup.sh
```

Run it from the root of this repository:

```bash
./scripts/setup.sh \
  "$HOME/.config/git-acs-sign/metadata.json" \
  "you@example.com"
```

The metadata path can alternatively come from `ACS_METADATA_PATH`:

```bash
export ACS_METADATA_PATH="$HOME/.config/git-acs-sign/metadata.json"
./scripts/setup.sh "$ACS_METADATA_PATH" "you@example.com"
```

### Configure another repository on Linux

Install the helper:

```bash
go install ./cmd/git-acs-sign
export PATH="$(go env GOPATH)/bin:$PATH"
signer="$(command -v git-acs-sign)"
```

Then change to the target repository and configure it:

```bash
cd ~/src/target-repository
"$signer" setup \
  --metadata "$HOME/.config/git-acs-sign/metadata.json" \
  --principal "you@example.com" \
  --program "$signer"
```

## Configuration performed by setup

Setup writes repository-local configuration similar to:

```text
gpg.format=ssh
gpg.ssh.program=<absolute-path-to-git-acs-sign>
gpg.ssh.allowedSignersFile=<git-dir>/artifact-signing/allowed-signers
user.signingKey=<git-dir>/artifact-signing/signing-key.pub
commit.gpgSign=true
artifactsigning.metadataFile=<absolute-path-to-metadata>
artifactsigning.principal=<email-or-principal>
```

Review it on either platform:

```text
git config --local --get-regexp "^(artifactsigning|gpg\.|user\.signingkey|commit\.gpgsign)"
```

The executable, public key, allowed-signers file, receipts, and metadata path are
stored under `.git` or `.git/config`; they are not committed.

## Sign commits

Setup enables automatic signing:

```text
git add .
git commit -m "Describe the change"
```

To sign only selected commits:

```text
git config --local commit.gpgSign false
git commit -S -m "Describe the change"
```

To restore automatic signing:

```text
git config --local commit.gpgSign true
```

## Review and verify a Git signature

Display Git's verification result:

```text
git log -1 --show-signature
```

Perform an explicit verification and check the exit status.

Windows PowerShell:

```powershell
git verify-commit --raw HEAD
$LASTEXITCODE
```

Linux Bash:

```bash
git verify-commit --raw HEAD
echo $?
```

A valid signature produces output similar to:

```text
Good "git" signature for you@example.com with RSA key SHA256:...
```

and exits with status `0`.

Inspect the signature embedded directly in the commit:

```text
git cat-file commit HEAD
```

The object contains a `gpgsig -----BEGIN SSH SIGNATURE-----` block. Because the
signature covers the commit object, changing its tree, parent, author, committer,
timestamp, or message invalidates the signature.

Review the trusted SSH key fingerprint.

Windows PowerShell:

```powershell
$key = git config --local --path --get user.signingKey
ssh-keygen -lf $key
```

Linux Bash:

```bash
key="$(git config --local --path --get user.signingKey)"
ssh-keygen -lf "$key"
```

The fingerprint must match the key shown by `git verify-commit`.

## Review the certificate used for a commit

Each signing operation records the exact returned leaf certificate in a local
receipt keyed by the SHA-256 digest of the SSH signature. The `inspect` command:

1. asks Git to verify the commit;
2. extracts the embedded SSH signature;
3. locates the matching local receipt;
4. confirms that the receipt fingerprint matches its certificate; and
5. displays the certificate and Artifact Signing profile properties.

Windows PowerShell:

```powershell
$signer = git config --local --get gpg.ssh.program
& $signer inspect HEAD
```

Linux Bash:

```bash
signer="$(git config --local --get gpg.ssh.program)"
"$signer" inspect HEAD
```

Replace `HEAD` with any local commit ID or revision:

```text
git-acs-sign inspect <commit>
```

The output includes:

- commit ID and Git verification result;
- receipt path and recording time;
- Artifact Signing endpoint, account, and certificate profile;
- certificate subject and issuer;
- serial number;
- SHA-256 certificate thumbprint;
- SSH public-key fingerprint;
- validity period;
- public-key type and size;
- certificate signature algorithm;
- key usage; and
- extended key usage and additional EKU object identifiers.

Receipts are local evidence and are not embedded in Git. If a repository is cloned
on another machine, Git can still verify the SSH signature when the public key is
trusted, but `inspect` requires the original matching receipt.

## Local files and source control

Setup creates:

```text
.git/artifact-signing/
├── allowed-signers
├── git-acs-sign[.exe]
├── signing-key.pub
└── receipts/
    └── <signature-sha256>.json
```

These files are inside `.git` and cannot be accidentally committed with the
repository working tree. The metadata file remains at the path supplied during
setup.

## Updating the helper

After pulling a newer version, rerun the platform setup command. It rebuilds or
replaces the helper and preserves the repository-local configuration model.

Windows:

```powershell
.\scripts\setup.ps1 `
    -MetadataPath 'C:\tools\AcsUnitTest\metadata.scus.json' `
    -Principal 'you@example.com'
```

Linux:

```bash
./scripts/setup.sh \
  "$HOME/.config/git-acs-sign/metadata.json" \
  "you@example.com"
```

## Troubleshooting

### Git reports that signing failed

Confirm the configured executable exists:

```text
git config --local --get gpg.ssh.program
```

Then rerun setup to rebuild it.

### Azure authentication fails

Check the active identity and tenant:

```text
az account show
```

If necessary:

```text
az logout
az login --tenant <tenant-id>
```

### Git reports "No principal matched"

Confirm that the commit is being verified with the expected email:

```text
git config user.email
git config --local --get artifactsigning.principal
```

Rerun setup with the correct principal.

### `inspect` cannot find a receipt

Receipts exist only for signing operations performed by a receipt-enabled build on
the current machine. Git signature verification is still available:

```text
git verify-commit --raw <commit>
```

### The certificate has expired

The current integration verifies the cryptographic SSH signature and reports the
certificate validity period. It does not timestamp the Git signature or perform
historical X.509 chain validation. The receipt shows which certificate was returned
at signing time, but it is not an RFC 3161 timestamp.

## Security and trust model

- Azure credentials and private keys are never written by this project.
- The Artifact Signing private key remains managed by Azure.
- The metadata file contains resource coordinates, not credentials.
- The helper verifies the raw Artifact Signing signature against the returned leaf
  certificate before returning an SSH signature to Git.
- Git verification is SSH public-key verification; Git does not independently
  validate the Artifact Signing X.509 chain.
- Certificate receipts are local correlation records, not trusted timestamps.
- Protect repository `.git` directories and metadata files from unauthorized
  modification.

## Development

Windows PowerShell:

```powershell
go test ./...
go vet ./...
go build .\cmd\git-acs-sign
```

Linux Bash:

```bash
go test ./...
go vet ./...
go build ./cmd/git-acs-sign
```
