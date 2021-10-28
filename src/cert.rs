use bytes::Bytes;
use memmem::{Searcher, TwoWaySearcher};
use openssl::x509::{GeneralName, X509, X509NameRef};
use openssl::stack::{Stack, Stackable};
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
use std::slice;

use crate::error::{Error};
use crate::mini_pki::CAStorage;

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


lazy_static! {
    static ref SVG_SEARCHER : TwoWaySearcher<'static> =
        TwoWaySearcher::new(b"data:image/svg+xml");
}

const BIMI_IMAGE_OID : &'static str = "1.3.6.1.5.5.7.1.12";

fn x509_bimi_get_ext(cert: &X509) -> Option<Vec<u8>>
{
    unsafe {
        let c_str_oid = CString::new(BIMI_IMAGE_OID)
            .expect("must be able to construct C string");
        let obj_id = openssl_ffi::OBJ_txt2obj(c_str_oid.as_ptr(), 1);

        if obj_id.is_null() {
            return None;
        }

        let c_cert_ptr = cert.as_ref() as *const _ as *mut _;
        let ext_idx = openssl_ffi::X509_get_ext_by_OBJ(c_cert_ptr, obj_id, 0);

        if ext_idx < 0 {
            return None;
        }

        let ext = openssl_ffi::X509_get_ext(c_cert_ptr, ext_idx);
        if ext.is_null() {
            return None;
        }

        let obj_data = openssl_ffi::X509_EXTENSION_get_data(ext);
        if obj_data.is_null() {
            return None;
        }

        // TODO: In general, we need to parse ASN.1 octets and they have the
        // following structure:
        //    0:d=0  hl=4 l= 886 cons: SEQUENCE
        //     4:d=1  hl=4 l= 882 cons: cont [ 2 ]
        //     8:d=2  hl=4 l= 878 cons: cont [ 0 ]
        //    12:d=3  hl=4 l= 874 cons: SEQUENCE
        //    16:d=4  hl=4 l= 870 cons: SEQUENCE
        //    20:d=5  hl=4 l= 866 cons: SEQUENCE
        //    24:d=6  hl=2 l=  13 prim: IA5STRING         :image/svg+xml
        //    39:d=6  hl=2 l=  35 cons: SEQUENCE
        //    41:d=7  hl=2 l=  33 cons: SEQUENCE
        //    43:d=8  hl=2 l=   9 cons: SEQUENCE
        //    45:d=9  hl=2 l=   5 prim: OBJECT            :sha1
        //    52:d=9  hl=2 l=   0 prim: NULL
        //    54:d=8  hl=2 l=  20 prim: OCTET STRING      <sha1>
        //    76:d=6  hl=4 l= 810 cons: SEQUENCE
        //    80:d=7  hl=4 l= 806 prim: IA5STRING         <real image>
        // But we can observe that real image is always last and it always
        // starts with data:image/svg+xml
        // Hence, for now, we use this hack to get the data without real
        // ASN.1 parsing of the unknown extension
        // Presumably, this should be implemented as C extension
        let ptr = openssl_ffi::ASN1_STRING_get0_data(obj_data as *mut _);

        if ptr.is_null() {
            return None;
        }

        let len = openssl_ffi::ASN1_STRING_length(obj_data as *mut _);
        let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
        let svg_pos = SVG_SEARCHER.search_in(slice)?;

        slice.get(svg_pos..slice.len()).map(|sl| sl.to_vec())
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
    pub fn from_pem(input : &Vec<u8>, ca_storage: &CAStorage) -> Result<Self, Error> {
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

    let cert = BIMICertificate::from_pem(&input.to_vec(),
            ca_storage)?;
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

    ca_storage.verify_cert(&cert.certificate, &cert.chain)?;
    debug!("verified PKI for domain {}", domain);

    return x509_bimi_get_ext(&cert.certificate)
        .ok_or(Error::CertificateNoLogoTypeExt);
}