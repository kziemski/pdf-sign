//! OpenPGP signing and verification backend using sequoia-openpgp and gpg-agent.

pub mod keybox;
pub mod sign;
pub mod verify;

pub use keybox::{find_certs_in_keybox, load_cert, load_keybox_certs};
pub use sign::{SignOptions, SignResult, create_signature};
pub use verify::{
    CertSource, VerifyOptions, VerifyResult, extract_pgp_signatures, verify_signatures,
};
