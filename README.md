# pdf-sign

A lightweight, modern PDF signing utility written in Rust that supports both **OpenPGP (GPG)** and **Sigstore (keyless OIDC)** signatures. It appends cryptographic signatures directly to PDFs, making it easy to sign and verify documents without heavyweight PDF signing stacks.

## Why pdf-sign?

Many "enterprise PDF signing" solutions require a full **CMS/PKCS#7** / **X.509 PKI** toolchain (certificate chains, policy constraints, CRL/OCSP revocation, time-stamping/TSAs) plus PDF-form machinery to produce **PAdES** signatures. Those stacks are powerful, but complex to configure, audit, and automate.

`pdf-sign` intentionally stays minimal and scriptable:

* **Two signing backends**: Choose between traditional GPG (with hardware key support) or modern Sigstore (keyless OIDC).
* **Preserves PDF integrity**: Original PDF content unchanged; signatures appended after `%%EOF`.
* **Multi-signer workflow**: Supports multiple signatures (GPG + Sigstore) on the same document.
* **Privacy-preserving**: No extra PII embedded; library never logs sensitive data.
* **Portable architecture**: Clean core library (WASM-ready) with pluggable backends.

## Quickstart

### Install with Cargo

```bash
cargo install --git https://github.com/0x77dev/pdf-sign --locked

# GPG signing (default backend)
pdf-sign sign document.pdf --key 0xDEADBEEF

# Sigstore keyless signing
pdf-sign sign --backend sigstore document.pdf

# Verify (automatically handles both GPG and Sigstore)
pdf-sign verify document_signed.pdf
```

### Install with Nix

```bash
nix profile install github:0x77dev/pdf-sign#pdf-sign
pdf-sign --help
```

### Build from Source

```bash
# Clone and build
git clone https://github.com/0x77dev/pdf-sign
cd pdf-sign
cargo build --release
./target/release/pdf-sign --help

# Or with Nix flake
nix build
./result/bin/pdf-sign --help
```

## Commands

### `sign` - Sign a PDF

Unified signing command with backend selection.

**GPG backend (default):**
```bash
pdf-sign sign contract.pdf --key 0xF1171FAAAA237211
# or explicitly:
pdf-sign sign --backend gpg contract.pdf --key user@example.com
```

**Sigstore backend:**
```bash
pdf-sign sign --backend sigstore document.pdf
```

**Common options:**
* `--output, -o`: Output path (default: `<input>_signed.pdf`)
* `--backend, -b`: Backend to use (`gpg` or `sigstore`, default: `gpg`)
* `--json`: Machine-readable JSON output

**GPG-specific options:**
* `--key, -k`: Key spec (file, fingerprint, key ID, or email) - **required for GPG**
* `--embed-uid`: Embed signer UID as notation

**Sigstore-specific options:**
* `--oidc-issuer <URL>`: OIDC provider (default: `https://oauth2.sigstore.dev/auth`)
* `--fulcio-url <URL>`: Fulcio CA (default: `https://fulcio.sigstore.dev`)
* `--rekor-url <URL>`: Rekor log (default: `https://rekor.sigstore.dev`)
* `--oidc-client-id <ID>`: Client ID (default: `sigstore`)
* `--oidc-client-secret <SECRET>`: Client secret
* `--identity-token <JWT>`: Non-interactive (CI mode)
* `--digest-algorithm <ALG>`: Hash (default: `sha512`)

### `verify` - Verify signatures

Automatically detects and verifies **both GPG and Sigstore** signatures in a single pass.

```bash
# Verify GPG signatures (uses keybox by default)
pdf-sign verify contract_signed.pdf

# Verify GPG with specific cert
pdf-sign verify contract_signed.pdf --cert signer.asc

# Verify Sigstore signatures (requires identity policy)
pdf-sign verify document_signed.pdf \
  --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com

# Verify both GPG and Sigstore in one PDF
pdf-sign verify multi_signed.pdf \
  --cert alice.asc \
  --certificate-identity bob@example.com \
  --certificate-oidc-issuer https://accounts.google.com
```

**GPG verification options:**
* `--cert, -c`: Optional cert spec (can repeat)

**Sigstore verification options:**
* `--certificate-identity <EMAIL|URI>`: Expected signer identity (required if Sigstore sigs present)
* `--certificate-identity-regexp <REGEX>`: Identity regex
* `--certificate-oidc-issuer <URL>`: Expected issuer (required if Sigstore sigs present)
* `--certificate-oidc-issuer-regexp <REGEX>`: Issuer regex
* `--offline`: Skip Rekor verification

**Common options:**
* `--json`: Machine-readable JSON output

## Features

### OpenPGP Backend

* **GPG agent integration**: All private key operations delegated to `gpg-agent`.
* **Hardware key support**: Smartcards and YubiKeys work seamlessly.
* **Keybox lookups**: Reads your `~/.gnupg/pubring.kbx` for verification.
* **Privacy by default**: Signer UIDs only embedded if explicitly requested.

### Sigstore Backend

* **Keyless signing**: No long-lived keys—authenticate with your existing OIDC account.
* **Transparency logging**: All signatures publicly logged to Rekor.
* **Short-lived certificates**: Fulcio issues ephemeral certs tied to your verified identity.
* **Strict verification**: Requires explicit identity and issuer constraints (prevents identity confusion).
* **Customizable endpoints**: Use public Sigstore or private deployments.

### Architecture

* **Portable core**: PDF splitting, suffix parsing, digest abstraction (no CLI/UI deps).
* **Pluggable backends**: Clean separation between GPG and Sigstore signing logic.
* **Hash agility**: SHA-512 default with SRI-style encoding (`sha512-<base64>`).
* **Versioned format**: Sigstore blocks use bilrost (efficient binary) with version tagging.
* **Structured tracing**: Full `tracing` instrumentation (never logs sensitive data).
* **Multi-signer**: Multiple signatures (GPG + Sigstore) can coexist on one PDF.

## Security Model

### OpenPGP

* **No private keys in tool**: All signing via `gpg-agent`.
* **Reduced exposure**: Private keys stay in agent or on hardware.
* **Explicit verification**: Uses keybox by default or provided certs.

### Sigstore

* **Identity-based**: Signatures tied to verified OIDC identity (email/URI).
* **Transparency**: Rekor ensures signatures are publicly auditable.
* **Strict by default**: Verification fails unless expected identity/issuer provided.
* **Privacy-aware**: Library code never logs tokens or identity material.

## Embedded Signature Formats

### OpenPGP

Standard ASCII-armored blocks appended after `%%EOF`:

```
%%EOF
-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
```

### Sigstore

Versioned bilrost-encoded blocks with digest binding:

```
%%EOF
-----BEGIN PDF-SIGN SIGSTORE-----
<base64-encoded bilrost payload>
-----END PDF-SIGN SIGSTORE-----
```

**Bilrost payload** (v1):

* `version`: Format version (1)
* `signed_range_len`: Length of clean PDF bytes
* `digest_alg`: Hash algorithm (1 = SHA-512)
* `digest`: Raw digest bytes (for integrity binding)
* `bundle_json`: Sigstore bundle (signature + cert + Rekor proof)

## Requirements

### For OpenPGP Signing

* Rust toolchain (`cargo`)
* Running `gpg-agent`
* Public cert importable or in keyring
* Private key in `gpg-agent` (software or hardware)

### For Sigstore Signing

* Rust toolchain (`cargo`)
* Web browser (for OIDC auth) or `--identity-token` for CI
* Network access (Fulcio, Rekor, OIDC provider)
* No keys/certs required

## Workspace Structure

```
crates/
├── core/      # Portable library (PDF, suffix, digest)
├── gpg/       # OpenPGP backend (sequoia)
├── sigstore/  # Sigstore keyless backend
└── cli/       # CLI with UI/JSON/tracing setup
```

Modular design enables:

* Backend-agnostic PDF processing
* Future WASM compilation (core + sigstore)
* Clean testing boundaries
* Structured tracing without data leakage

## Environment Variables

* `GNUPGHOME`: GPG keybox location (default: `~/.gnupg`)
* `RUST_LOG`: Tracing verbosity (e.g., `RUST_LOG=debug`)
* Output channels:
  * `stderr`: Progress, status, errors
  * `stdout`: Result paths (sign) or "OK" (verify) for pipelines

## Examples

### GPG signing with YubiKey

```bash
# Sign with hardware key (default backend)
pdf-sign sign contract.pdf --key user@example.com

# Verify
pdf-sign verify contract_signed.pdf
```

### Sigstore keyless signing

```bash
# Interactive signing (opens browser for OIDC)
pdf-sign sign --backend sigstore document.pdf

# Verify with strict identity policy
pdf-sign verify document_signed.pdf \
  --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com
```

### CI/CD with Sigstore

```bash
# Non-interactive signing with pre-obtained token
pdf-sign sign --backend sigstore release.pdf --identity-token "$OIDC_TOKEN"

# Verify in CI
pdf-sign verify release_signed.pdf \
  --certificate-identity https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --json
```

### Multi-signer workflow

```bash
# Alice signs with GPG
pdf-sign sign contract.pdf --key alice@example.com

# Bob adds Sigstore signature to the same PDF
pdf-sign sign --backend sigstore contract_signed.pdf --output contract_multi.pdf

# Verify both signatures in one command
pdf-sign verify contract_multi.pdf \
  --cert alice.asc \
  --certificate-identity bob@example.com \
  --certificate-oidc-issuer https://accounts.google.com
```

## License

GPL-3.0-only
