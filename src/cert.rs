use bytes::Bytes;
use memmem::{Searcher, TwoWaySearcher};
use openssl::x509::{GeneralName, X509, X509NameRef, X509StoreContext, X509StoreContextRef};
use openssl::stack::{Stack};
use openssl::x509::store::{X509StoreBuilder, X509Store};
use openssl::asn1::Asn1TimeRef;
use openssl::nid;
use chrono::{NaiveDateTime, DateTime, Utc};
use std::net::{IpAddr};

use crate::error::{Error};

fn parse_openssl_time(time: &Asn1TimeRef) -> Result<DateTime<Utc>, Error> {
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
    /// Create a certificate from PEM file (typical usage for BIMI)
    pub fn from_pem(input : &Vec<u8>) -> Result<Self, Error> {
        let mut x509_stack = X509::stack_from_pem(&input)
            .map_err(|e| Error::CertificateParseError(e.to_string()))?;


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

    /// Verify certificate against CA, no other checks are done
    pub fn verify_ca(&self, ca_store: &CAStorage) -> Result<bool, Error> {
        let mut nstore_ctx = X509StoreContext::new().
            map_err(|e| Error::CAInitError(e.to_string()))?;
        nstore_ctx.init(ca_store.store.as_ref(), self.certificate.as_ref(),
            self.chain.as_ref(), X509StoreContextRef::verify_cert)
            .map_err(|e| Error::CertificateVerificationError(e.to_string()))
    }

    /// Verify domain names in certificate to match the expected domain
    /// This function exists because OpenSSL verification is just broken in
    /// old versions of the library
    pub fn verify_name(&self, domain: &str) -> Result<bool, Error> {
        match self.certificate.subject_alt_names() {
            Some(names) => self.verify_subject_alt_names(domain, &names),
            None => self.verify_subject_name(domain, &self.certificate.subject_name()),
        }
    }

    fn verify_subject_alt_names(&self, domain: &str, names: &Stack<GeneralName>)
        -> Result<bool,Error>
    {
        for name in names {
            match name.dnsname() {
                Some(n) => if self.verify_dns(domain, n)? {
                    return Ok(true)
                }
                _ => {
                    return Err(Error::CertificateNameVerificationError("Invalid alt name"
                        .to_string()))
                }
            }
        }

        Err(Error::CertificateNameVerificationError("No matching alt name".to_string()))
    }

    fn verify_subject_name(&self, domain: &str, x509_name: &X509NameRef) -> Result<bool, Error> {
        if let Some(pat) = x509_name.entries_by_nid(nid::Nid::COMMONNAME).next() {
            let pattern = pat.data().as_utf8()
                .map(|ossl_string| ossl_string.to_string())
                .map_err(|_| Error::CertificateNameVerificationError("bad subject name"
                    .to_string()))?;
            match domain.parse::<IpAddr>() {
                Ok(_) => Err(Error::CertificateNameVerificationError("IP address in subject name"
                    .to_string())),
                Err(_) => self.verify_dns(domain, pattern.as_str())
            }
        }
        else {
            Err(Error::CertificateNameVerificationError("no subject names".to_string()))
        }
    }


    fn verify_dns(&self, domain: &str, pattern: &str) -> Result<bool, Error> {

        let domain_to_check = domain.strip_suffix('.')
            .unwrap_or(domain);
        let pattern_to_check = pattern.strip_suffix('.').
            unwrap_or(pattern);

        // Check either wildcard definitions of just the whole name
        let wildcard_location = match pattern_to_check.find('*') {
            Some(positions) => positions,
            None => return Ok(domain_to_check == pattern_to_check),
        };

        let mut dot_idxs = pattern_to_check.match_indices('.')
            .map(|(pos, _)| pos);
        let wildcard_end = match dot_idxs.next() {
            Some(l) => l,
            None => return Err(Error::CertificateNameVerificationError("invalid pattern"
                .to_string())),
        };

        // Wildcard are allowed merely for second or more domain level (not like *.com)
        if dot_idxs.next().is_none() {
            return Err(Error::CertificateNameVerificationError("too short wildcard".to_string()));
        }

        // Wildcards can only be in the first component, not something like foo.*.com
        if wildcard_location > wildcard_end {
            return Err(Error::CertificateNameVerificationError("invalid wildcard".to_string()));
        }

        // Domain could be a single label, but it is not a subject to wildcard
        // matching then
        let first_label_pos = match domain_to_check.find('.') {
            Some(pos) => pos,
            None => return Ok(false),
        };

        // Check that the non-wildcard parts are identical
        if pattern_to_check[wildcard_end..] != domain_to_check[first_label_pos..] {
            return Ok(false);
        }

        let wildcard_prefix = &pattern_to_check[..wildcard_location];
        let wildcard_suffix = &pattern_to_check[wildcard_location + 1..wildcard_end];
        let hostname_label = &domain_to_check[..first_label_pos];

        // Check that part before wildcard is equal and then check the remaining
        return Ok(hostname_label.starts_with(wildcard_prefix) &&
            hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix))
    }
}


/// CA storage
pub struct CAStorage {
    store: X509Store,
}

impl CAStorage {
    pub fn new() -> Result<Self, Error> {
        let mut nstore = X509StoreBuilder::new()
            .map_err(|e| Error::CAInitError(e.to_string()))?;
        nstore.set_default_paths()
            .map_err(|e| Error::CAInitError(e.to_string()))?;
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


pub fn process_cert(input: &Bytes, ca_storage: &CAStorage, domain: &str)
    -> Result<Vec<u8>, Error>
{
    if !check_pem(&input) {
        return Err(Error::BadPEM);
    }

    let cert = ServerCertificate::from_pem(&input.to_vec())?;

    // Verify name first as this check is cheap
    if !cert.verify_name(domain)? {
        return Err(Error::CertificateGenericNameVerificationError);
    }
    // Verify that a cert is signed properly (expensive check)
    if !cert.verify_ca(ca_storage)? {
        return Err(Error::CertificateGenericVerificationError);
    }

    Ok(Vec::new())
}