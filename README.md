# Git commit signing with Artifact Signing

This repository adapts [artifact-signing-sdk-go](https://github.com/Jaxelr/artifact-signing-sdk-go)
to Git's SSH commit-signing interface. Git sends the commit payload to `git-acs-sign`,
the helper creates a standard SSHSIG digest, and Azure Artifact Signing produces the
RSA-SHA256 signature.

The metadata file is read from your machine and is never copied into the repository.
Azure authentication uses `DefaultAzureCredential`, so an existing `az login` session
is sufficient.

## Prerequisites

- Go 1.25 or later
- Git 2.34 or later
- OpenSSH `ssh-keygen` with `-Y` signature support
- Access to the configured Artifact Signing account and certificate profile
- `az login` completed for the required tenant

## Configure this repository

From PowerShell:

```powershell
.\scripts\setup.ps1 -MetadataPath 'C:\tools\AcsUnitTest\metadata.scus.json'
```

The setup script:

1. Builds the helper under the repository's `.git\artifact-signing` directory.
2. Performs a signing operation to validate access and obtain the profile's public key.
3. Writes local verification state under `.git\artifact-signing`.
4. Configures this repository for SSH-format signatures and enables automatic commit signing.

No endpoint, account name, profile name, credentials, or generated binary is committed.
The local configuration can be inspected with:

```powershell
git config --local --get-regexp '^(artifactsigning|gpg\.|user\.signingkey|commit\.gpgsign)'
```

## Sign and verify

Commits are signed automatically after setup:

```powershell
git commit -m 'Describe the change'
git log -1 --show-signature
```

Review the exact X.509 certificate returned for a signed commit:

```powershell
$signer = git config --local --get gpg.ssh.program
& $signer inspect HEAD
```

The command verifies the commit first, correlates its embedded SSH signature with a
local receipt, and displays the certificate subject, issuer, serial number, SHA-256
thumbprint, validity period, public-key details, signature algorithm, key usages, and
Artifact Signing account/profile. Receipts are stored only under
`.git\artifact-signing\receipts` and are not source controlled.

To sign only selected commits, disable the default and use `-S`:

```powershell
git config --local commit.gpgSign false
git commit -S -m 'Describe the change'
```

## Security and trust model

- The helper validates the raw Artifact Signing response against the returned X.509
  certificate before emitting an SSH signature.
- The current certificate public key is written to Git's local `allowedSignersFile`.
  This supports Artifact Signing certificate rotation without committing generated state.
- Verification is delegated to the system `ssh-keygen`.
- The local metadata path is stored only in `.git\config`.
- Each signing operation records the returned leaf certificate in a local receipt keyed
  by the exact SSH signature embedded in the commit.

This integration proves that the commit was signed by the private key corresponding to
the Artifact Signing certificate returned for that operation. Git's SSH verification is
key-based; it does not independently validate the X.509 certificate chain.

## Development

```powershell
go test ./...
go build ./cmd/git-acs-sign
```
