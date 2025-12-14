//! Unified verify command that handles both GPG and Sigstore signatures.

use anyhow::{Context, Result, bail};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use pdf_sign_core::{
    split_pdf,
    suffix::{SuffixBlock, parse_suffix_blocks},
};
use pdf_sign_gpg::{VerifyOptions as GpgVerifyOptions, load_cert};
use pdf_sign_sigstore::verify::{
    CertificateIdentityMatcher, OidcIssuerMatcher, VerifyOptions as SigstoreVerifyOptions,
    VerifyPolicy, verify_blob,
};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::time::Duration;

use crate::json::{SigstoreVerifiedSigJson, UnifiedVerifyJson, VerifySignatureJson};
use crate::util::format_bytes;

#[allow(clippy::too_many_arguments)]
pub fn verify_pdf(
    input: PathBuf,
    cert_spec: Vec<String>,
    certificate_identity: Option<String>,
    certificate_identity_regexp: Option<String>,
    certificate_oidc_issuer: Option<String>,
    certificate_oidc_issuer_regexp: Option<String>,
    offline: bool,
    json: bool,
) -> Result<()> {
    eprintln!("{}", style("==> Verifying PDF signatures").cyan().bold());

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!(
        "Reading signed PDF {}",
        style(input.display()).cyan()
    ));

    let mut signed_data = Vec::new();
    let mut file = BufReader::new(
        File::open(&input)
            .with_context(|| format!("Failed to open signed PDF: {}", input.display()))?,
    );
    file.read_to_end(&mut signed_data)?;

    spinner.finish_with_message(format!(
        "[OK] Read PDF ({})",
        style(format_bytes(signed_data.len())).cyan()
    ));

    let (pdf_data, suffix) = split_pdf(&signed_data)?;
    let blocks = parse_suffix_blocks(suffix)?;

    if blocks.is_empty() {
        bail!("No signatures found after %%EOF marker");
    }

    eprintln!(
        "    Found {} signature block(s)",
        style(blocks.len()).cyan()
    );

    // Separate GPG and Sigstore blocks
    let mut gpg_sigs = Vec::new();
    let mut sigstore_blocks = Vec::new();

    for block in blocks {
        match block {
            SuffixBlock::OpenPgpSig(data) => gpg_sigs.push(data),
            SuffixBlock::SigstoreBundle(bundle) => sigstore_blocks.push(bundle),
        }
    }

    let mut gpg_verified = Vec::new();
    let mut sigstore_verified = Vec::new();

    // Verify GPG signatures if any
    if !gpg_sigs.is_empty() {
        eprintln!("    Verifying {} OpenPGP signature(s)...", gpg_sigs.len());

        let certs = cert_spec
            .iter()
            .map(|spec| load_cert(spec))
            .collect::<Result<Vec<_>>>()?;

        let options = GpgVerifyOptions { certs };
        let verify_result = pdf_sign_gpg::verify::verify_signatures(pdf_data, &gpg_sigs, &options)?;

        gpg_verified = verify_result.verified;
        eprintln!(
            "      {} {} OpenPGP signature(s)",
            style("[OK]").green().bold(),
            gpg_verified.len()
        );
    }

    // Verify Sigstore signatures if any
    if !sigstore_blocks.is_empty() {
        eprintln!(
            "    Verifying {} Sigstore signature(s)...",
            sigstore_blocks.len()
        );

        // Build policy if identity constraints provided
        let has_sigstore_constraints = certificate_identity.is_some()
            || certificate_identity_regexp.is_some()
            || certificate_oidc_issuer.is_some()
            || certificate_oidc_issuer_regexp.is_some();

        if !has_sigstore_constraints {
            bail!(
                "Sigstore signatures found, but no verification policy provided.\n\
                 Please specify --certificate-identity and --certificate-oidc-issuer\n\
                 (or their regexp variants) to verify Sigstore signatures."
            );
        }

        let cert_identity_matcher = match (certificate_identity, certificate_identity_regexp) {
            (Some(exact), None) => Some(CertificateIdentityMatcher::Exact(exact)),
            (None, Some(re)) => Some(CertificateIdentityMatcher::Regexp(re)),
            _ => None,
        };

        let cert_issuer_matcher = match (certificate_oidc_issuer, certificate_oidc_issuer_regexp) {
            (Some(exact), None) => Some(OidcIssuerMatcher::Exact(exact)),
            (None, Some(re)) => Some(OidcIssuerMatcher::Regexp(re)),
            _ => None,
        };

        let policy = VerifyPolicy {
            certificate_identity: cert_identity_matcher,
            certificate_oidc_issuer: cert_issuer_matcher,
        };

        let options = SigstoreVerifyOptions { policy, offline };

        let rt = tokio::runtime::Runtime::new()?;

        for bundle_block in &sigstore_blocks {
            let result = rt.block_on(verify_blob(pdf_data, bundle_block, &options))?;
            sigstore_verified.push(result);
        }

        eprintln!(
            "      {} {} Sigstore signature(s)",
            style("[OK]").green().bold(),
            sigstore_verified.len()
        );
    }

    eprintln!(
        "\n{} {}",
        style("[VALID]").green().bold(),
        style("All signatures verified").green()
    );

    // Display results
    if !gpg_verified.is_empty() {
        eprintln!("\n    OpenPGP signatures:");
        for (i, sig) in gpg_verified.iter().enumerate() {
            eprintln!(
                "      {}. Fingerprint: {}",
                i + 1,
                style(&sig.key_fingerprint).cyan()
            );
            for uid in &sig.uids {
                eprintln!("         Identity: {}", style(uid).cyan());
            }
        }
    }

    if !sigstore_verified.is_empty() {
        eprintln!("\n    Sigstore signatures:");
        for (i, sig) in sigstore_verified.iter().enumerate() {
            eprintln!(
                "      {}. Identity: {}",
                i + 1,
                style(&sig.certificate_identity).cyan()
            );
            eprintln!(
                "         Issuer: {}",
                style(&sig.certificate_oidc_issuer).cyan()
            );
            if let Some(idx) = sig.rekor_log_index {
                eprintln!("         Rekor: {}", style(format!("index {}", idx)).cyan());
            }
        }
    }

    if json {
        let gpg_sigs: Vec<VerifySignatureJson> = gpg_verified
            .into_iter()
            .map(|v| VerifySignatureJson {
                key_fingerprint: v.key_fingerprint,
                uids: v.uids,
                cert_source: v.source,
            })
            .collect();

        let sigstore_sigs: Vec<SigstoreVerifiedSigJson> = sigstore_verified
            .into_iter()
            .map(|v| SigstoreVerifiedSigJson {
                certificate_identity: v.certificate_identity,
                certificate_oidc_issuer: v.certificate_oidc_issuer,
                rekor_log_index: v.rekor_log_index,
            })
            .collect();

        let payload = UnifiedVerifyJson {
            status: "ok",
            command: "verify",
            input: input.display().to_string(),
            openpgp_signatures: gpg_sigs,
            sigstore_signatures: sigstore_sigs,
        };
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        // Only print "OK" when stdout is piped (for pipeline composition)
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            println!("OK");
        }
    }

    Ok(())
}
