use bytes::Bytes;
use memmem::{Searcher, TwoWaySearcher};
use openssl::x509::{GeneralName, X509, X509NameRef};
use openssl::stack::{Stack};
use openssl::nid::Nid;
use chrono::{DateTime, Utc};
use std::time::SystemTime;
use std::net::{IpAddr};
use std::str;
use log::{debug};
use data_url::DataUrl;

use crate::error::{AppError};
use crate::mini_pki::CAStorage;
use crate::x509_helpers::*;


/// Chain of certificates to be validated
pub struct BIMICertificate {
    certificate: X509,
    chain: Stack<X509>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    key_usages: Vec<String>
}

const BIMI_KEY_USAGE_OID : &'static str = "1.3.6.1.5.5.7.3.31";

impl BIMICertificate {
    /// Create a certificate from PEM file (typical usage for BIMI)
    pub fn from_pem(input : &Vec<u8>, ca_storage: &CAStorage) -> Result<Self, AppError> {
        let mut x509_stack = X509::stack_from_pem(&input)
            .map_err(|e| AppError::CertificateParseError(e.to_string()))?;


        // The first cert is the server cert and the other certs are part of
        // the CA chain; we skip the server cert and build an OpenSSL cert
        // stack with the other certs
        let certificate = x509_stack.remove(0);

        let not_before = parse_openssl_time(certificate.not_before())?;
        let not_after = parse_openssl_time(certificate.not_after())?;
        debug!("certificate is valid from: {} to {}", not_before.timestamp(),
            not_after.timestamp());
        let mut key_usages : Vec<String> = Vec::new();
        let extensions = get_x509_extended_key_usage( &certificate);
        extensions.map(|exts| {
            for ext in exts {
                debug!("got extended key usage extension: {}", ext);
                match ext.text() {
                    Some(s) => key_usages.push(s),
                    _ => debug!("cannot decode extension")
                }
            }
        });
        let mut chain_stack = openssl::stack::Stack::<X509>::new().unwrap();
        // Move all elements from a vector to the SSL stack
        while let Some(cert) = x509_stack.pop() {
            if !x509_is_ca(&cert) {
                chain_stack.push(cert).unwrap();
            }
            else {
                // Either add trusted CA or add some intermediate CA to the chain
                ca_storage.try_add_ca_cert(&cert)
                    .unwrap_or_else(|_| chain_stack.push(cert).unwrap())
            }
        }

        let identity = Self {
            certificate,
            chain: chain_stack,
            not_before,
            not_after,
            key_usages
        };

        Ok(identity)
    }

    /// Verify domain names in certificate to match the expected domain
    /// This function exists because OpenSSL verification is just broken in
    /// old versions of the library
    pub fn verify_name(&self, domain: &str) -> Result<bool, AppError> {
        match self.certificate.subject_alt_names() {
            Some(names) => self.verify_subject_alt_names(domain, &names),
            None => self.verify_subject_name(domain, &self.certificate.subject_name()),
        }
    }

    /// Verifies expiration of the certificate
    pub fn verify_expiry(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("cannot run if clock are before unix epoch").as_secs() as i64;
        return self.not_after.timestamp() > now && self.not_before.timestamp() <= now;
    }

    /// Verifies that a cert has defined key usage for BIMI:
    /// 1.3.6.1.5.5.7.3.31
    pub fn verify_key_usage(&self) -> bool {
        return self.key_usages.contains(&String::from(BIMI_KEY_USAGE_OID));
    }

    fn verify_subject_alt_names(&self, domain: &str, names: &Stack<GeneralName>)
        -> Result<bool, AppError>
    {
        for name in names {
            match name.dnsname() {
                Some(n) => if self.verify_dns(domain, n)? {
                    return Ok(true)
                }
                _ => {
                    return Err(AppError::CertificateNameVerificationError("Invalid alt name"
                        .to_string()))
                }
            }
        }

        Err(AppError::CertificateNameVerificationError("No matching alt name".to_string()))
    }

    fn verify_subject_name(&self, domain: &str, x509_name: &X509NameRef) -> Result<bool, AppError> {
        if let Some(pat) = x509_name.entries_by_nid(Nid::COMMONNAME).next() {
            let pattern = pat.data().as_utf8()
                .map(|ossl_string| ossl_string.to_string())
                .map_err(|_| AppError::CertificateNameVerificationError("bad subject name"
                    .to_string()))?;
            match domain.parse::<IpAddr>() {
                Ok(_) => Err(AppError::CertificateNameVerificationError("IP address in subject name"
                    .to_string())),
                Err(_) => self.verify_dns(domain, pattern.as_str())
            }
        }
        else {
            Err(AppError::CertificateNameVerificationError("no subject names".to_string()))
        }
    }


    fn verify_dns(&self, domain: &str, pattern: &str) -> Result<bool, AppError> {
        debug!("verify domain {} against pattern {}", domain, pattern);
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
            None => return Err(AppError::CertificateNameVerificationError("invalid pattern"
                .to_string())),
        };

        // Wildcard are allowed merely for second or more domain level (not like *.com)
        if dot_idxs.next().is_none() {
            return Err(AppError::CertificateNameVerificationError("too short wildcard".to_string()));
        }

        // Wildcards can only be in the first component, not something like foo.*.com
        if wildcard_location > wildcard_end {
            return Err(AppError::CertificateNameVerificationError("invalid wildcard".to_string()));
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
                if s + 1 >= e - 1 {
                    None
                }
                else {
                    Some(true)
                }
            })
    }).unwrap_or(false)
}


pub fn process_cert(input: &Bytes, ca_storage: &CAStorage, domain: &str)
    -> Result<Vec<u8>, AppError>
{
    if !check_pem(&input) {
        return Err(AppError::BadPEM);
    }

    debug!("got likely valid pem for domain {}", domain);

    let cert = BIMICertificate::from_pem(&input.to_vec(),
            ca_storage)?;
    debug!("got valid pem for domain {}", domain);

    // Do cheap checks: name, time, extended key usage
    if !cert.verify_name(domain)? {
        return Err(AppError::CertificateGenericNameVerificationError);
    }
    debug!("verified name for domain {}", domain);

    if !cert.verify_expiry() {
        return Err(AppError::CertificateExpired);
    }
    debug!("verified expiry for domain {}", domain);

    if !cert.verify_key_usage() {
        return Err(AppError::CertificateNoKeyUsage);
    }
    debug!("verified key usage for domain {}", domain);

    ca_storage.verify_cert(&cert.certificate, &cert.chain)?;
    debug!("verified PKI for domain {}", domain);

    let image_vec = x509_bimi_get_ext(&cert.certificate)
        .ok_or(AppError::CertificateNoLogoTypeExt)?;

    if image_vec.starts_with("data:".as_bytes()) {
        debug!("got data url for {}", domain);
        let image_str = str::from_utf8(&image_vec)
            .or_else(|_| Err(AppError::CertificateInvalidLogoURL))?;
        debug!("got data url for {}", image_str);
        let image_url = DataUrl::process(image_str)
            .map_err(|_| AppError::CertificateInvalidLogoURL)?;
        let image_data = image_url
            .decode_to_vec()
            .map_err(|_| AppError::CertificateInvalidLogoURL)?;
        Ok(image_data.0)
    }
    else {
        Ok(image_vec)
    }
}