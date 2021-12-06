use crate::AppError;
use flate2::read::GzDecoder;
use std::io::prelude::*;

// The file size of SVG Tiny PS documents SHOULD be as small as
// possible, and SHOULD NOT exceed 32 kilobytes.  That size should be
// evaluated when the document is uncompressed.
const MAX_SVG_SIZE: usize = 32 * 1024;

/// Process SVG probably with decompressing it from a byte vector
/// This function also checks size and should perform other sanity checks
/// as defined by BIMI standard
pub fn process_svg(input: &[u8]) -> Result<Vec<u8>, AppError> {
    check_svg_size(input)?;
    // Check gzip magic
    if input.starts_with(&[0x1F, 0x8B]) {
        let decompressed = maybe_decompress_svg(input)?;
        check_svg_size(&decompressed)?;
        Ok(decompressed)
    } else {
        Ok(Vec::from(input))
    }
}

// Checks SVG size according to IETF recommendation (should happen after decompression)
fn check_svg_size(input: &[u8]) -> Result<(), AppError> {
    let sz = input.len();
    if !(8..=MAX_SVG_SIZE).contains(&sz) {
        Err(AppError::SVGSizeError(sz))
    } else {
        Ok(())
    }
}

fn maybe_decompress_svg(input: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut gz = GzDecoder::new(input);
    let mut out = vec![0; MAX_SVG_SIZE];

    let nbytes = gz.read(&mut out.as_mut_slice())?;

    if nbytes == out.len() {
        // Too large SVG uncompressed
        return Err(AppError::SVGSizeError(nbytes));
    }

    out.truncate(nbytes);
    Ok(out)
}
