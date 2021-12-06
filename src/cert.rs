use memmem::{Searcher, TwoWaySearcher};
use openssl::x509::{GeneralName, X509, X509NameRef};
use openssl::stack::{Stack};
use openssl::nid::Nid;
use chrono::{DateTime, Utc};
use std::time::SystemTime;
use std::net::{IpAddr};
use std::str;
use log::{debug, info};
use data_url::DataUrl;
use der_parser::der::{parse_der_ia5string,
                      parse_der_sequence_of,
                      parse_der_sequence_defined_g,
                      der_read_element_header,
                      parse_der_octetstring,
                      parse_der_oid,
                      parse_der_null};
use der_parser::error::{BerError, BerResult};
use nom::combinator::{verify};

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

const BIMI_KEY_USAGE_OID : &str = "1.3.6.1.5.5.7.3.31";

impl BIMICertificate {
    /// Create a certificate from PEM file (typical usage for BIMI)
    pub fn from_pem(input : &[u8], ca_storage: &CAStorage) -> Result<Self, AppError> {
        let mut x509_stack = X509::stack_from_pem(input)
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
        if let Some(exts) = extensions {
            for ext in exts {
                debug!("got extended key usage extension: {}", ext);
                match ext.text() {
                    Some(s) => key_usages.push(s),
                    _ => debug!("cannot decode extension")
                }
            }
        }
        let mut chain_stack = openssl::stack::Stack::<X509>::new().unwrap();
        // Move all elements from a vector to the SSL stack
        while let Some(cert) = x509_stack.pop() {
            if !x509_is_ca(&cert) {
                chain_stack.push(cert).unwrap();
            }
            else {
                // Either add trusted CA or add some intermediate CA to the chain
                ca_storage.try_add_ca_cert(&cert)
                    .unwrap_or_else(|e| {
                        info!("cannot add CA certificate in chain: {:?}", e);
                        chain_stack.push(cert).unwrap()
                    })
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
    pub fn verify_name(&self, domain: &str) -> Result<(), AppError> {
        match self.certificate.subject_alt_names() {
            Some(names) => verify_subject_alt_names(domain, &names),
            None => verify_subject_name(domain, self.certificate.subject_name()),
        }
    }

    /// Verifies expiration of the certificate
    pub fn verify_expiry(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("cannot run if clock are before unix epoch").as_secs() as i64;
        self.not_after.timestamp() > now && self.not_before.timestamp() <= now
    }

    /// Verifies that a cert has defined key usage for BIMI:
    /// 1.3.6.1.5.5.7.3.31
    pub fn verify_key_usage(&self) -> bool {
        self.key_usages.iter().any(|x| x == BIMI_KEY_USAGE_OID)
    }

}

/// Verifies subject name for a certificate
fn verify_subject_name(domain: &str, x509_name: &X509NameRef) -> Result<(), AppError> {
    if let Some(pat) = x509_name.entries_by_nid(Nid::COMMONNAME).next() {
        let pattern = pat.data().as_utf8()
            .map(|ossl_string| ossl_string.to_string())
            .map_err(|_| AppError::CertificateNameVerificationError("bad subject name"
                .to_string()))?;
        match domain.parse::<IpAddr>() {
            Ok(_) => Err(AppError::CertificateNameVerificationError("IP address in subject name"
                .to_string())),
            Err(_) => verify_dns(domain, pattern.as_str())
        }
    }
    else {
        Err(AppError::CertificateNameVerificationError("no subject names".to_string()))
    }
}

/// Verifies a stack of alt names
fn verify_subject_alt_names(domain: &str, names: &Stack<GeneralName>)
                            -> Result<(), AppError>
{
    for name in names {
        match name.dnsname() {
            Some(n) => if verify_dns(domain, n).is_ok() {
                // If any name matches, we assume it as a successful match
                return Ok(());
            },
            _ => {
                return Err(AppError::CertificateNameVerificationError("Invalid alt name"
                    .to_string()))
            }
        }
    }

    Err(AppError::CertificateNameVerificationError("No matching alt name".to_string()))
}

/// Verifies a single domain for a certificate counting wildcards
fn verify_dns(domain: &str, pattern: &str) -> Result<(), AppError> {
    debug!("verify domain {} against pattern {}", domain, pattern);
    let domain_to_check = domain.strip_suffix('.')
        .unwrap_or(domain);
    let pattern_to_check = pattern.strip_suffix('.').
        unwrap_or(pattern);

    // Check either wildcard definitions of just the whole name
    let wildcard_location = match pattern_to_check.find('*') {
        Some(positions) => positions,
        None => if domain_to_check == pattern_to_check {
            return Ok(());
        }
        else {
            return Err(AppError::CertificateNameVerificationError("Cannot verify domain name"
                .to_string()))
        }
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
        None => {
            return Err(AppError::CertificateNameVerificationError("cannot match single label with wildcard"
                .to_string()));
        },
    };

    // Check that the non-wildcard parts are identical
    if pattern_to_check[wildcard_end..] != domain_to_check[first_label_pos..] {
        return Err(AppError::CertificateNameVerificationError("cannot match wildcard".to_string()));
    }

    let wildcard_prefix = &pattern_to_check[..wildcard_location];
    let wildcard_suffix = &pattern_to_check[wildcard_location + 1..wildcard_end];
    let hostname_label = &domain_to_check[..first_label_pos];

    // Check that part before wildcard is equal and then check the remaining
    if hostname_label.starts_with(wildcard_prefix) &&
        hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix) {
        Ok(())
    }
    else {
        Err(AppError::CertificateNameVerificationError("cannot match wildcard".to_string()))
    }
}

lazy_static! {
    static ref HEADER_SRCH : TwoWaySearcher<'static> =
        TwoWaySearcher::new(b"-----BEGIN CERTIFICATE-----");
    static ref FOOTER_SRCH  : TwoWaySearcher<'static> =
        TwoWaySearcher::new(b"-----END CERTIFICATE-----");
}

/// Performs a cheap check for PEM file
fn check_pem(input: &[u8]) -> bool
{
    HEADER_SRCH.search_in(input).and_then(|s| {
        FOOTER_SRCH.search_in(input)
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


pub fn process_cert(input: &[u8], ca_storage: &CAStorage, domain: &str)
    -> Result<Vec<u8>, AppError>
{
    if !check_pem(input) {
        return Err(AppError::BadPEM);
    }

    debug!("got likely valid pem for domain {}", domain);

    let cert = BIMICertificate::from_pem(input,
            ca_storage)?;
    debug!("got valid pem for domain {}", domain);

    // Do cheap checks: name, time, extended key usage
    cert.verify_name(domain)?;
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

    let image_url = parse_logotype_ext(&image_vec[..])?;

    if image_url.starts_with("data:") {
        debug!("got data url for {}", image_url);
        let image_url = DataUrl::process(image_url)
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

// LogotypeExtn ::= SEQUENCE {
//    communityLogos  [0] EXPLICIT SEQUENCE OF LogotypeInfo OPTIONAL,
//    issuerLogo      [1] EXPLICIT LogotypeInfo OPTIONAL,
//    subjectLogo     [2] EXPLICIT LogotypeInfo OPTIONAL,
//    otherLogos      [3] EXPLICIT SEQUENCE OF OtherLogotypeInfo OPTIONAL }
fn parse_logotype_ext(input: &[u8]) -> Result<&str, AppError> {
    let (_, urls) = parse_der_sequence_defined_g(|i:&[u8], _| {
        let (rest, hdr) = verify(der_read_element_header,
                                 |hdr| hdr.is_contextspecific())(i)?;
        match hdr.tag.0 {
            2 => parse_logotype_info_seq(rest),
            _ => {
                info!("unexpected tag: {}", hdr.tag.0);
                Err(nom::Err::Error(BerError::UnknownTag))
            }
        }
    })(input)?;
    let first_url = &urls.as_sequence()?[0]
        .as_sequence()?[0]
        .as_sequence()?[0];
    first_url.as_str().map_err(AppError::BERError)
}

// Parses a sequence of logotype info asn.1 objects
//
// LogotypeInfo ::= CHOICE {
// direct          [0] LogotypeData,
// indirect        [1] LogotypeReference }
fn parse_logotype_info_seq(input: &[u8]) -> BerResult {
    let (rest, hdr) = verify(der_read_element_header,
                             |hdr| hdr.is_contextspecific())(input)?;
    match hdr.tag.0 {
        0 => {
            parse_der_sequence_of(parse_logotype_data)(rest)
        },
        _ => {
            info!("cannot match tag: {}", hdr.tag.0);
            Err(nom::Err::Error(BerError::UnknownTag))
        }
    }
}

// Parse LogoTypeData
// LogotypeData ::= SEQUENCE {
// image           SEQUENCE OF LogotypeImage OPTIONAL,
// audio           [1] SEQUENCE OF LogotypeAudio OPTIONAL }
fn parse_logotype_data(input: &[u8]) -> BerResult {
    parse_der_sequence_defined_g(|i: &[u8], _| {
        parse_der_sequence_of(parse_logotype_image_details)(i)
    })(input)
}


// LogotypeDetails ::= SEQUENCE {
//    mediaType       IA5String,
//    logotypeHash    SEQUENCE OF HashAlgAndValue,
//    logotypeURI     SEQUENCE OF IA5String }
fn parse_logotype_image_details(i: &[u8]) -> BerResult {
    let (i, _) = parse_der_ia5string(i)?; // Content-Type
    let (i, _) = parse_der_sequence_of(parse_logotype_hash_and_value)(i)?;
    let (i, urls) = parse_der_sequence_of(|i| {
        parse_der_ia5string(i)
    })(i)?;
    Ok((i, urls))
}
// HashAlgAndValue ::= SEQUENCE {
//    hashAlg         AlgorithmIdentifier,
//    hashValue       OCTET STRING }
//
fn parse_logotype_hash_and_value(i: &[u8]) -> BerResult {
    parse_der_sequence_defined_g(|i: &[u8], _| {
        let (i, id) = parse_der_sequence_defined_g(|i, _| parse_algorithm_identifier(i))(i)?;
        debug!("got hash oid: {:?}", id.as_oid()?);
        parse_der_octetstring(i)
    })(i)
}

//    AlgorithmIdentifier  ::=  SEQUENCE  {
//         algorithm               OBJECT IDENTIFIER,
//         parameters              ANY DEFINED BY algorithm OPTIONAL  }
fn parse_algorithm_identifier(i: &[u8]) -> BerResult {
    // Algorithm identifier parser
    let (i, oid) = parse_der_oid(i)?;
    // We assume that parameters are always NULL
    let (i, _) = parse_der_null(i)?;
    Ok((i, oid))
}

#[cfg(test)]
mod test {
    use crate::cert::{verify_dns, process_cert};
    use crate::mini_pki::CAStorage;

    #[test]
    fn verify_names() {
        verify_dns("paypal.com", "paypal.com").unwrap();
        verify_dns("paypal.com.", "paypal.com").unwrap();
        verify_dns("paypal.com", "paypal.com.").unwrap();
        verify_dns("paypal.com.", "paypal.com.").unwrap();
        verify_dns("sub.paypal.com", "paypal.com").unwrap_err();

        // Subdomains
        verify_dns("sub.paypal.com", "*.paypal.com").unwrap();
        verify_dns("sub.sub.paypal.com", "*.paypal.com").unwrap_err();
        verify_dns("sub.sub.paypal.com", "*.sub.paypal.com").unwrap();
        // Non-ascii
        verify_dns("paypal.com", "paypal.cоm").unwrap_err();
        // Wildcard vs tld -> should not match
        verify_dns("paypal.com", "*.paypal.com").unwrap_err();
        // Too wide pattern
        verify_dns("paypal.com", "*.com").unwrap_err();
        // Cannot match patterns at the end
        assert!(verify_dns("paypal.com", "paypal.co*").is_err());
    }

    #[test]
    fn verify_assets() {
        let ca_storage = CAStorage::new().unwrap();
        let good_ca_storage = CAStorage::new().unwrap();
        // Valimail cert
        good_ca_storage
            .add_fingerprint("504386c9ee8932fecc95fade427f69c3e2534b7310489e300fee448e33c46b42")
            .unwrap();
        // Expired cert
        process_cert(&read_bytes("test-assets/paypal.pem").unwrap(),
                     &ca_storage, "paypal.com").unwrap_err();
        // Good cert but must use valid fingerprint
        process_cert(&read_bytes("test-assets/paypal.pem").unwrap(),
                     &ca_storage, "paypal.com").unwrap_err();
        process_cert(&read_bytes("test-assets/valimail.pem").unwrap(),
                     &good_ca_storage, "valimail.com").unwrap();
    }

    fn read_bytes(fname : &str) -> Option<Vec<u8>> {
        let bytes_vec = std::fs::read(fname).unwrap();
        Some(Vec::from(bytes_vec))
    }
}