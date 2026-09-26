# Sign Git commits with Azure Artifact Signing

> [!IMPORTANT]
> This project is still in alpha and its considered an experiment on
> limitations on the integration of Azure Artifact Signing with Git.
    
Hey, so you want to sign Git commits with a key that lives in Azure? Cool.

`git-acs-sign` is a small helper that uses
[Artifact Signing SDK for Go](https://github.com/Jaxelr/artifact-signing-sdk-go)
to sign commits with Azure Artifact Signing.

It plugs into Git's SSH signing support, which means you keep using Git like
you normally would:

```text
git add .
git commit -m "My signed commit"
```

No weird commit flow. No private key sitting on your laptop. It works on Windows
and Linux, and it can show you the certificate Artifact Signing used for a
commit.

## Stuff you'll need

- Go 1.25 or newer
- Git 2.34 or newer
- OpenSSH with `ssh-keygen -Y` support
- Azure CLI
- An Artifact Signing account and certificate profile
- Permission to sign with that profile

Give these a quick check before we get going:

```text
go version
git --version
ssh-keygen -Y check-novalidate
az version
```

The `ssh-keygen` command may complain that you didn't give it a signature.
That's okay—we're only checking that the `-Y` commands exist.

## Tell it where your signing profile lives

The helper needs three things: the Artifact Signing endpoint, account, and
certificate profile. Put them in a JSON file:

```json
{
  "Endpoint": "https://scus.codesigning.azure.net",
  "CodeSigningAccountName": "codesign-account",
  "CertificateProfileName": "public-trust-profile"
}
```

Nothing secret is hiding in here. This file doesn't contain credentials or a
private key; it just points at your Artifact Signing resource.

> [!NOTE]
> Your Azure identity still needs permission to use the signing profile. Check
> out [Tutorial: Assign roles in Artifact Signing](https://learn.microsoft.com/en-us/azure/artifact-signing/tutorial-assign-roles)
> if you need to wire that up.

You can keep it wherever you like. Usually kept under your home directory:

- Windows: `C:\Users\jaxel\.config\git-acs-sign\metadata.json`
- Linux: `$HOME/.config/git-acs-sign/metadata.json`

## Log in to Azure

For local use, an Azure CLI login does the trick:

```text
az login --tenant <tenant-id>
az account show
```

The helper uses `DefaultAzureCredential`, so it'll pick up the Azure CLI login.

## Windows:

Clone this repository, open PowerShell in it, and configure your Git identity:

```powershell
git config user.name 'Jaxel Rojas Lopez'
git config user.email 'jrojaslopez@microsoft.com'
```

Now let setup do its thing:

```powershell
.\scripts\setup.ps1 `
    -MetadataPath 'C:\Users\jaxel\.config\git-acs-sign\metadata.json' `
    -Principal 'jrojaslopez@microsoft.com'
```

If PowerShell blocks the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 `
    -MetadataPath 'C:\Users\jaxel\.config\git-acs-sign\metadata.json' `
    -Principal 'jrojaslopez@microsoft.com'
```

The script builds the helper under `.git\artifact-signing`, makes sure Azure
actually lets you sign, and wires up this repository so commits are signed
automatically.

## Linux:

Clone this repository, open a shell in it, and configure your Git identity:

```bash
git config user.name "Jaxel Rojas Lopez"
git config user.email "jrojaslopez@microsoft.com"
```

Now run setup:

```bash
chmod +x scripts/setup.sh

./scripts/setup.sh \
  "$HOME/.config/git-acs-sign/metadata.json" \
  "jrojaslopez@microsoft.com"
```

You can also use `ACS_METADATA_PATH`:

```bash
export ACS_METADATA_PATH="$HOME/.config/git-acs-sign/metadata.json"
./scripts/setup.sh "$ACS_METADATA_PATH" "jrojaslopez@microsoft.com"
```

Same deal as Windows: it builds the helper under `.git/artifact-signing`, tries
a real signing operation, and configures the current repository.

## Make GitHub show the Verified badge

Git can verify the signature locally right away, but GitHub doesn't know who
owns the Artifact Signing public key yet. Upload it to your GitHub account as a
**signing key**.

### Windows

```powershell
$key = git config --local --path --get user.signingKey

gh ssh-key add "$key" `
    --type signing `
    --title 'Azure Artifact Signing - git-acs-sign'
```

### Linux

```bash
key="$(git config --local --path --get user.signingKey)"

gh ssh-key add "$key" \
  --type signing \
  --title "Azure Artifact Signing - git-acs-sign"
```

If GitHub CLI asks for another permission:

```text
gh auth refresh -h github.com -s admin:public_key
```

Then run the `gh ssh-key add` command again.

Prefer clicking through the website? Open
[GitHub SSH and GPG key settings](https://github.com/settings/keys), choose
**New SSH key**, set the key type to **Signing Key**, and paste the contents of
`signing-key.pub`.

On Windows, this copies the key:

```powershell
$key = git config --local --path --get user.signingKey
Get-Content $key | Set-Clipboard
```

On Linux:

```bash
key="$(git config --local --path --get user.signingKey)"
cat "$key"
```

Also make sure the email used on your commits is verified in
[GitHub email settings](https://github.com/settings/emails).

Only the public key goes to GitHub. The private key stays in Azure. If Artifact
Signing rotates to a new public key later, upload the new `signing-key.pub` as
another signing key so new commits keep their Verified badge.

## Okay, let's sign something

Make a small change and commit it normally:

### Windows

```powershell
'Artifact Signing example' | Set-Content example.txt
git add example.txt
git commit -m 'Add signed example'
```

### Linux

```bash
printf '%s\n' 'Artifact Signing example' > example.txt
git add example.txt
git commit -m 'Add signed example'
```

Setup turns on `commit.gpgSign`, so that's it—no need to remember `-S` every
time.

If you only want to sign some commits:

```text
git config --local commit.gpgSign false
git commit -S -m "Sign only this commit"
```

## But did it actually sign?

Yep. Here's the quick check:

```text
git log -1 --show-signature
```

You should see something like:

```text
Good "git" signature for jrojaslopez@microsoft.com with RSA key SHA256:...
```

Want Git to be extra explicit? Ask it to verify the commit directly.

### Windows

```powershell
git verify-commit --raw HEAD
$LASTEXITCODE
```

### Linux

```bash
git verify-commit --raw HEAD
echo $?
```

Exit code `0` means the signature is valid.

Want to see the signature tucked inside the commit?

```text
git cat-file commit HEAD
```

Look for the `BEGIN SSH SIGNATURE` block.

## Show me the certificate

This is the fun part. The helper keeps a local receipt for each signature, so
you can look up the exact certificate Artifact Signing returned.

### Windows

```powershell
$signer = git config --local --get gpg.ssh.program
& $signer inspect HEAD
```

### Linux

```bash
signer="$(git config --local --get gpg.ssh.program)"
"$signer" inspect HEAD
```

Looking for a different commit? Replace `HEAD` with any commit or revision:

```text
git-acs-sign inspect <commit>
```

The output includes:

- Artifact Signing account and profile
- Certificate subject and issuer
- Serial number
- SHA-256 thumbprint
- SSH key fingerprint
- Valid-from and valid-until dates
- Public key type and size
- Signature algorithm
- Key usage and extended key usage

Receipts live under `.git/artifact-signing/receipts`. They stay local and aren't
committed.

If you clone the repository on another machine, Git can still verify the commit
as long as the signing key is trusted there. The certificate details need the
matching receipt from the machine that created the signature.

## Bring it to another repository

Install the helper straight from GitHub:

```text
go install github.com/jaxelr/git-azure-artifact-signing/cmd/git-acs-sign@latest
```

Don't have Go installed on the machine where you want to use it? Grab a
prebuilt Windows or Linux package from
[GitHub Releases](https://github.com/Jaxelr/git-azure-artifact-signing/releases).
Each archive comes with a `.sha256` checksum file.

The repository also builds packages for every push and pull request. Open the
run under the
[Actions tab](https://github.com/Jaxelr/git-azure-artifact-signing/actions/workflows/build-and-package.yml)
and download the artifact for your platform:

- `git-acs-sign_linux_amd64`
- `git-acs-sign_linux_arm64`
- `git-acs-sign_windows_amd64`
- `git-acs-sign_windows_arm64`

Tagged versions such as `v0.1.0` are published to GitHub Releases automatically.

### Windows

```powershell
$signer = Join-Path (go env GOPATH) 'bin\git-acs-sign.exe'
Set-Location 'C:\src\target-repository'

& $signer setup `
    --metadata 'C:\Users\jaxel\.config\git-acs-sign\metadata.json' `
    --principal 'jrojaslopez@microsoft.com' `
    --program $signer
```

### Linux

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
signer="$(command -v git-acs-sign)"
cd ~/src/target-repository

"$signer" setup \
  --metadata "$HOME/.config/git-acs-sign/metadata.json" \
  --principal "jrojaslopez@microsoft.com" \
  --program "$signer"
```

Setup is repository-local, so run it once in each repository you want to sign.

## So, what did setup change?

Nothing mysterious. It writes local Git settings that look like this:

```text
gpg.format=ssh
gpg.ssh.program=<path-to-git-acs-sign>
gpg.ssh.allowedSignersFile=<git-dir>/artifact-signing/allowed-signers
user.signingKey=<git-dir>/artifact-signing/signing-key.pub
commit.gpgSign=true
artifactsigning.metadataFile=<path-to-metadata>
artifactsigning.principal=<email>
```

You can review them with:

```text
git config --local --get-regexp "^(artifactsigning|gpg\.|user\.signingkey|commit\.gpgsign)"
```

Setup also creates:

```text
.git/artifact-signing/
├── allowed-signers
├── git-acs-sign[.exe]
├── signing-key.pub
└── receipts/
    └── <signature-sha256>.json
```

Everything lives under `.git`, safely out of your normal commits.

## Troubleshooting

### Git says signing failed

Check that the configured helper exists:

```text
git config --local --get gpg.ssh.program
```

If it doesn't, rerun setup.

### Azure doesn't like your login

Check the current account:

```text
az account show
```

Sign in again if needed:

```text
az logout
az login --tenant <tenant-id>
```

### Git says "No principal matched"

Check that these values use the same email:

```text
git config user.email
git config --local --get artifactsigning.principal
```

Rerun setup with the right principal if they don't match.

### `inspect` can't find a receipt

The receipt may have been created on another machine, or the commit may predate
receipt support. You can still check the Git signature:

```text
git verify-commit --raw <commit>
```

## License

[MIT](LICENSE)
