use std::ops::{DerefMut};
use openssl::x509::store::{X509StoreBuilder, X509Store};
use crate::error::{Error};
use dashmap::DashMap;
use std::sync::{Arc, RwLock};
use openssl::x509::{X509, X509StoreContext, X509StoreContextRef};
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;
use openssl::stack::Stack;
use hex;
use foreign_types::{ForeignTypeRef};
use log::{debug, info};

// Not exported by rust-openssl aside of Builder stuff
fn add_cert_to_store(store: &mut X509Store, cert: &X509) -> Result<(), Error>
{
    unsafe {
        match openssl_ffi::X509_STORE_add_cert(store.as_ref().as_ptr(),
                                         cert.as_ref().as_ptr()) {
            1 => Ok(()),
            _ => Err(Error::OpenSSLError(ErrorStack::get()))
        }
    }
}

/// CA storage that can be shared among threads and dynamically updated
pub struct CAStorage {
    store: Arc<RwLock<X509Store>>,
    trusted_fingerprints: Arc<DashMap<String, bool>>,
}

impl CAStorage {
    /// Creates new CAStorage with the default CA paths and empty trusted fingerprints
    pub fn new() -> Result<Self, Error> {
        let mut nstore = X509StoreBuilder::new()
            .map_err(|e| Error::CAInitError(e.to_string()))?;
        nstore.set_default_paths()
            .map_err(|e| Error::CAInitError(e.to_string()))?;
        Ok(Self {
            store: Arc::new(RwLock::new(nstore.build())),
            trusted_fingerprints: Arc::new(DashMap::new())
        })
    }

    /// Adds a new trusted fingerprint to the list
    /// Fingerprint must be hex representation of sha256 for the desired
    /// CA certificate.
    pub fn add_fingerprint(&self, fp: &str) {
        info!("added trusted fingerprint {}", fp);
        self.trusted_fingerprints.insert(fp.to_string(), false);
    }

    /// Adds a new CA certificate to the storage
    /// Certificate must match trusted fingerprints database
    /// If a certificate has been already added, this function is no-op
    pub fn try_add_ca_cert(&self, cert: &X509) -> Result<(), Error> {
        let cert_digest = cert.digest(MessageDigest::sha256())
            .map_err(|_| Error::CertificateParseError("no digest in CA cert".to_string()))?;
        let cert_digest_hex = hex::encode(cert_digest);

        let mut fp_count = self.trusted_fingerprints
            .get_mut(cert_digest_hex.as_str())
            .ok_or(Error::UntrustedCACert(cert_digest_hex.clone()))?;

        if *fp_count {
            // Already added
            debug!("already seen certificate with fp {}", &cert_digest_hex);
            return Ok(());
        }

        // Increase count in the hash and
        *fp_count = true;

        info!("added trusted CA cert with fp {}", &cert_digest_hex);
        let mut ca_store = self.store.write().unwrap();
        add_cert_to_store(ca_store.deref_mut(), cert)
    }

    pub fn verify_cert(&self, cert: &X509, chain: &Stack<X509>) -> Result<(), Error> {
        let mut nstore_ctx = X509StoreContext::new().
            map_err(|e| Error::CAInitError(e.to_string()))?;
        let ca_store = self.store.read().unwrap();
        let mut verify_error = String::new();
        let verify_result = nstore_ctx.init(&*ca_store.as_ref(), cert.as_ref(),
                        chain.as_ref(), |ctx| {
                let res = X509StoreContextRef::verify_cert(ctx)?;
                if !res {
                    verify_error.push_str(ctx.error().error_string());
                }

                Ok(res)
            })
            .map_err(|e| Error::CertificateVerificationError(e.to_string()))?;

        // We have to store verification result in this way
        // as closure is expected to return bool/ErrorStack and ErrorStack
        // is an alien ffi structure that cannot be created directly
        if !verify_result {
            return Err( Error::CertificateVerificationError(verify_error));
        }

        Ok(())
    }
}