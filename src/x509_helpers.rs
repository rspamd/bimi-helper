use openssl::stack::{Stack, Stackable};
use openssl::asn1::{Asn1TimeRef};
use openssl::x509::{X509};
use chrono::{NaiveDateTime, DateTime, Utc};
use memmem::{Searcher, TwoWaySearcher};
use std::ffi::CString;
use libc::{c_int};
use std::slice;
use std::fmt;
use std::ptr;
use foreign_types::{ForeignType};

use crate::error::{AppError};

/// Missing function to parse ASN.1 time to normal time
pub fn parse_openssl_time(time: &Asn1TimeRef) -> Result<DateTime<Utc>, AppError> {
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

/// Returns a list of extended key usage extensions
pub fn get_x509_extended_key_usage(cert: &X509) -> Option<Stack<ExtendedKeyUsage>> {
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

/// Returns true if certificate has CA usage flag
pub fn x509_is_ca(cert: &X509) -> bool {
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

/// Get BIMI extension by finding a logotype OID and do a (very) naive
/// parsing of it's structure
pub fn x509_bimi_get_ext(cert: &X509) -> Option<Vec<u8>>
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