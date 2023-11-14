use crate::error::AppError;
use crate::x509_helpers::x509_is_ca;
use dashmap::DashMap;
use log::{debug, info};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509StoreContext, X509StoreContextRef, X509};
use std::fs;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};

/// CA storage that can be shared among threads and dynamically updated
pub struct CAStorage {
    store: Arc<RwLock<X509Store>>,
    trusted_fingerprints: Arc<DashMap<String, bool>>,
}

impl CAStorage {
    /// Creates new CAStorage with the default CA paths and empty trusted fingerprints
    pub fn new() -> Result<Self, AppError> {
        let mut nstore =
            X509StoreBuilder::new().map_err(|e| AppError::CAInitError(e.to_string()))?;
        nstore
            .set_default_paths()
            .map_err(|e| AppError::CAInitError(e.to_string()))?;
        Ok(Self {
            store: Arc::new(RwLock::new(nstore.build())),
            trusted_fingerprints: Arc::new(DashMap::new()),
        })
    }

    /// Adds a new trusted fingerprint to the list
    /// Fingerprint must be hex representation of sha256 for the desired
    /// CA certificate.
    pub fn add_fingerprint(&self, fp: &str) -> Result<(), AppError> {
        // Must be specific length
        if fp.len() != 256 / 8 * 2 {
            return Err(AppError::InvalidFingerprint);
        }
        // Must have only hex characters
        if !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::InvalidFingerprint);
        }
        info!("added trusted fingerprint {}", fp);
        self.trusted_fingerprints.insert(fp.to_string(), false);
        Ok(())
    }

    /// Adds CA certificates from a PEM file
    /// All certificates in this file must be CA certificates
    pub fn add_ca_pem(&self, fname: &str) -> Result<(), AppError> {
        let pem = fs::read(fname)?;
        let mut x509_stack = X509::stack_from_pem(&pem[..])
            .map_err(|e| AppError::CertificateParseError(e.to_string()))?;

        while let Some(cert) = x509_stack.pop() {
            let cert_digest_hex = cert_hex_digest(&cert)?;

            if x509_is_ca(&cert) {
                self.trusted_fingerprints.insert(cert_digest_hex, false);
                self.try_add_ca_cert(&cert)?;
            } else {
                let err_message = String::from("Not CA cert found: ") + cert_digest_hex.as_str();
                return Err(AppError::CertificateParseError(err_message));
            }
        }

        Ok(())
    }

    /// Adds a new CA certificate to the storage
    /// Certificate must match trusted fingerprints database
    /// If a certificate has been already added, this function is no-op
    pub fn try_add_ca_cert(&self, cert: &X509) -> Result<(), AppError> {
        let cert_digest_hex = cert_hex_digest(cert)?;

        let mut fp_count = self
            .trusted_fingerprints
            .get_mut(cert_digest_hex.as_str())
            .ok_or_else(|| AppError::UntrustedCACert(cert_digest_hex.clone()))?;

        if *fp_count {
            // Already added
            debug!("already seen certificate with SHA256: {}", &cert_digest_hex);
            return Ok(());
        }

        // Increase count in the hash and
        *fp_count = true;

        info!("added trusted CA cert with fp {}", &cert_digest_hex);
        let mut ca_store = self.store.write().unwrap();
        add_cert_to_store(ca_store.deref_mut(), cert)
    }

    /// Verifies a certificate using the system and the local trusted CA storage
    /// This function requires a target certificate and all intermediate certificates
    /// in OpenSSL chain
    pub fn verify_cert(&self, cert: &X509, chain: &Stack<X509>) -> Result<(), AppError> {
        let mut nstore_ctx =
            X509StoreContext::new().map_err(|e| AppError::CAInitError(e.to_string()))?;
        let ca_store = self.store.read().unwrap();
        let mut verify_error = String::new();
        let verify_result = nstore_ctx
            .init(ca_store.as_ref(), cert.as_ref(), chain.as_ref(), |ctx| {
                let res = X509StoreContextRef::verify_cert(ctx)?;
                if !res {
                    verify_error.push_str(ctx.error().error_string());
                }

                Ok(res)
            })
            .map_err(|e| AppError::CertificateVerificationError(e.to_string()))?;

        // We have to store verification result in this way
        // as closure is expected to return bool/ErrorStack and ErrorStack
        // is an alien ffi structure that cannot be created directly
        if !verify_result {
            return Err(AppError::CertificateVerificationError(verify_error));
        }

        Ok(())
    }
}

fn cert_hex_digest(cert: &X509) -> Result<String, AppError> {
    let cert_digest = cert
        .digest(MessageDigest::sha256())
        .map_err(|_| AppError::CertificateParseError("no digest in CA cert".to_string()))?;
    Ok(hex::encode(cert_digest))
}

// Not exported by rust-openssl aside of Builder stuff
fn add_cert_to_store(store: &mut X509Store, cert: &X509) -> Result<(), AppError> {
    unsafe {
        match openssl_ffi::X509_STORE_add_cert(store as *const _ as *mut _, cert as *const _ as *mut _) {
            1 => Ok(()),
            _ => Err(AppError::OpenSSLError(ErrorStack::get())),
        }
    }
}
