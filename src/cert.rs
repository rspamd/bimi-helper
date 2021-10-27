use bytes::Bytes;
use memmem::{Searcher, TwoWaySearcher};
use openssl::x509::{GeneralName, X509, X509NameRef,
                    X509StoreContext, X509StoreContextRef};
use openssl::stack::{Stack, Stackable};
use openssl::x509::store::{X509StoreBuilder, X509Store};
use openssl::asn1::{Asn1TimeRef, Asn1Object};
use openssl::nid::Nid;
use chrono::{NaiveDateTime, DateTime, Utc};
use std::time::SystemTime;
use std::net::{IpAddr};
use log::{debug, info};
use openssl::error::ErrorStack;

use foreign_types::{ForeignType, ForeignTypeRef};
use std::fmt;
use std::ptr;
use std::ffi::CString;
use libc::{c_int};

use crate::error::{Error};

fn parse_openssl_time(time: &Asn1TimeRef) -> Result<DateTime<Utc>, Error> {
    let time = time.to_string();
    let time = NaiveDateTime::parse_from_str(&time, "%b %e %H:%M:%S %Y GMT")?;
    Ok(DateTime::<Utc>::from_utc(time, Utc))
}

foreign_type! {
    type CType = openssl_ffi::ASN1_OBJECT;
    fn drop = openssl_ffi::ASN1_OBJECT_free;

    pub struct ExtendedKeyUsage;
    pub struct ExtendedKeyUsageRef;
}

impl ExtendedKeyUsage {
    pub fn nid(&self) -> Nid {
        unsafe { Nid::from_raw(openssl_ffi::OBJ_obj2nid(self.as_ptr())) }
    }
    pub fn text(&self) -> Option<String> {
        unsafe {
            let mut buf  :[u8; 80] = [0; 80];
            let len = openssl_ffi::OBJ_obj2txt(
                buf.as_mut_ptr() as *mut _,
                buf.len() as c_int,
                self.as_ptr(),
                0,
            );
            match std::str::from_utf8(&buf[..len as usize]) {
                Err(_) => None,
                Ok(s) => Some(String::from(s))
            }
        }
    }
}

impl fmt::Display for ExtendedKeyUsage {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let mut buf = [0; 80];
            let len = openssl_ffi::OBJ_obj2txt(
                buf.as_mut_ptr() as *mut _,
                buf.len() as c_int,
                self.as_ptr(),
                0,
            );
            match std::str::from_utf8(&buf[..len as usize]) {
                Err(_) => fmt.write_str("error"),
                Ok(s) => fmt.write_str(s),
            }
        }
    }
}

impl Stackable for ExtendedKeyUsage {
    type StackType = openssl_ffi::stack_st_ASN1_OBJECT;
}

fn get_x509_extended_key_usage(cert: &X509) -> Option<Stack<ExtendedKeyUsage>> {
    // This function is not provided by rust-openssl, have to use ffi
    unsafe {
        let stack = openssl_ffi::X509_get_ext_d2i(
            cert.as_ref() as *const _ as *mut _,
            openssl_ffi::NID_ext_key_usage,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if stack.is_null() {
            None
        } else {
            Some(Stack::from_ptr(stack as *mut _))
        }
    }
}

fn x509_is_ca(cert: &X509) -> bool {
    unsafe {
        let flags = openssl_ffi::X509_get_extension_flags(
            cert.as_ref() as *const _ as *mut _,);
        if flags & openssl_ffi::EXFLAG_CA != 0 {
            true
        }
        else {
            false
        }
    }
}


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
    pub fn from_pem(input : &Vec<u8>) -> Result<Self, Error> {
        let mut x509_stack = X509::stack_from_pem(&input)
            .map_err(|e| Error::CertificateParseError(e.to_string()))?;


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

    /// Verify certificate against CA, no other checks are done
    pub fn verify_ca(&self, ca_store: &CAStorage) -> Result<bool, Error> {
        let mut nstore_ctx = X509StoreContext::new().
            map_err(|e| Error::CAInitError(e.to_string()))?;
        nstore_ctx.init(ca_store.store.as_ref(), self.certificate.as_ref(),
            self.chain.as_ref(), |ctx| {
                debug!("calling verify cert method");
                let res = X509StoreContextRef::verify_cert(ctx)?;
                if !res {
                    debug!("verification error: {}", ctx.error().error_string());
                }

                Ok(res)
            }).map_err(|e| Error::CertificateVerificationError(e.to_string()))
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
        if let Some(pat) = x509_name.entries_by_nid(Nid::COMMONNAME).next() {
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
    -> Result<Vec<u8>, Error>
{
    if !check_pem(&input) {
        return Err(Error::BadPEM);
    }

    debug!("got likely valid pem for domain {}", domain);

    let cert = BIMICertificate::from_pem(&input.to_vec())?;
    debug!("got valid pem for domain {}", domain);

    // Do cheap checks: name, time, extended key usage
    if !cert.verify_name(domain)? {
        return Err(Error::CertificateGenericNameVerificationError);
    }
    debug!("verified name for domain {}", domain);

    if !cert.verify_expiry() {
        return Err(Error::CertificateExpired);
    }
    debug!("verified expiry for domain {}", domain);

    if !cert.verify_key_usage() {
        return Err(Error::CertificateNoKeyUsage);
    }
    debug!("verified key usage for domain {}", domain);

    x509_bimi_get_ext(&cert.certificate);

    // Verify that a cert is signed properly (expensive check)
    if !cert.verify_ca(ca_storage)? {
        return Err(Error::CertificateGenericVerificationError);
    }

    debug!("verified CA for domain {}", domain);

    Ok(Vec::new())
}