use bytes::Bytes;
use memmem::{Searcher, TwoWaySearcher};
use openssl::x509::{X509, X509StoreContext, X509StoreContextRef};
use openssl::stack::{Stack};
use openssl::x509::store::{X509StoreBuilder, X509Store};
use openssl::asn1::Asn1TimeRef;
use chrono::{NaiveDateTime, DateTime, Utc};

use crate::error;

fn parse_openssl_time(time: &Asn1TimeRef) -> Result<DateTime<Utc>, error::Error> {
    let time = time.to_string();
    let time = NaiveDateTime::parse_from_str(&time, "%b %e %H:%M:%S %Y GMT")?;
    Ok(DateTime::<Utc>::from_utc(time, Utc))
}

/// Chain of certificates to be validated
pub struct ServerCertificate {
    certificate: X509,
    chain: Stack<X509>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl ServerCertificate {
    pub fn from_pem(input : &Vec<u8>) -> Result<Self, error::Error> {
        let mut x509_stack = X509::stack_from_pem(&input)
            .map_err(|e| error::Error::CertificateParseError(e.to_string()))?;


        // The first cert is the server cert and the other certs are part of
        // the CA chain; we skip the server cert and build an OpenSSL cert
        // stack with the other certs
        let certificate = x509_stack.remove(0);

        let not_before = parse_openssl_time(certificate.not_before())?;
        let not_after = parse_openssl_time(certificate.not_after())?;
        let mut chain_stack = openssl::stack::Stack::<X509>::new().unwrap();
        // Move all elements from a vector to the SSL stack
        while let Some(cert) = x509_stack.pop() {
            chain_stack.push(cert).unwrap();
        }

        let identity = Self {
            certificate,
            chain: chain_stack,
            not_before,
            not_after,
        };

        Ok(identity)
    }

    pub fn verify_ca(&self, ca_store: &mut CAStorage) -> Result<bool, error::Error> {
        let mut nstore_ctx = X509StoreContext::new().
            map_err(|e| error::Error::CAInitError(e.to_string()))?;
        nstore_ctx.init(ca_store.store.as_ref(), self.certificate.as_ref(),
            self.chain.as_ref(), X509StoreContextRef::verify_cert)
            .map_err(|e| error::Error::CertificateVerificationError(e.to_string()))
    }
}


/// CA storage
pub struct CAStorage {
    store: X509Store,
}

impl CAStorage {
    pub fn new() -> Result<Self, error::Error> {
        let mut nstore = X509StoreBuilder::new()
            .map_err(|e| error::Error::CAInitError(e.to_string()))?;
        nstore.set_default_paths()
            .map_err(|e| error::Error::CAInitError(e.to_string()))?;
        Ok(Self {
            store: nstore.build(),
        })
    }
}

lazy_static! {
    static ref HEADER_SRCH : TwoWaySearcher<'static> =
        TwoWaySearcher::new(b"-----BEGIN CERTIFICATE-----");
    static ref FOOTER_SRCH  : TwoWaySearcher<'static> =
        TwoWaySearcher::new(b"-----END CERTIFICATE-----");
}

/// Performs a cheap check for PEM file
fn check_pem(input: &Bytes) -> bool
{
    HEADER_SRCH.search_in(&input[..]).and_then(|s| {
        FOOTER_SRCH.search_in(&input[..])
            .and_then(|e| {
                if s + 1 <= e - 1 {
                    None
                }
                else {
                    Some(true)
                }
            })
    }).unwrap_or(false)
}


pub fn process_cert(input: &Bytes, ca_storage: &mut CAStorage) -> Result<Vec<u8>, error::Error>
{
    if !check_pem(&input) {
        return Err(error::Error::BadPEM);
    }

    let cert = ServerCertificate::from_pem(&input.to_vec())?;
    let res = cert.verify_ca(ca_storage)?;

    if !res {
        error::Error::CertificateVerificationError("Certificate verification error".to_string());
    }

    Ok(Vec::new())
}