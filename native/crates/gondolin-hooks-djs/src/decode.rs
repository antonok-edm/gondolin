//! Response body decoding for `onResponse` (`content-encoding: gzip`,
//! `deflate`, `br` or `zstd`), so tier-2 hooks see decoded bodies like tier-3
//! hooks (which read them through `DecompressionStream`). Bounded by the
//! response body limit (decompression bombs).

use std::io::Read;

use miniz_oxide::inflate::{decompress_to_vec_with_limit, decompress_to_vec_zlib_with_limit};

/// A content coding the hook sees decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl Coding {
    /// The decoded coding of a `content-encoding` value (others, like
    /// `zstd-dictionary`, stay encoded).
    pub fn of(value: &str) -> Option<Coding> {
        match value.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Coding::Gzip),
            "deflate" => Some(Coding::Deflate),
            "br" => Some(Coding::Brotli),
            "zstd" => Some(Coding::Zstd),
            _ => None,
        }
    }

    /// Decodes `data` to at most `limit` bytes.
    pub fn decode(self, data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
        let too_large = || format!("decoded response body exceeds {limit} bytes");
        match self {
            Coding::Gzip => {
                let raw = gzip_payload(data)?;
                decompress_to_vec_with_limit(raw, limit).map_err(|e| match e.status {
                    miniz_oxide::inflate::TINFLStatus::HasMoreOutput => too_large(),
                    _ => "invalid gzip body".to_string(),
                })
            }
            Coding::Deflate => decompress_to_vec_zlib_with_limit(data, limit)
                // servers sometimes send raw DEFLATE as `deflate`
                .or_else(|_| decompress_to_vec_with_limit(data, limit))
                .map_err(|e| match e.status {
                    miniz_oxide::inflate::TINFLStatus::HasMoreOutput => too_large(),
                    _ => "invalid deflate body".to_string(),
                }),
            Coding::Brotli => {
                let decoder = brotli::Decompressor::new(data, BROTLI_READ_BUF);
                read_bounded(decoder, limit, too_large, "invalid brotli body")
            }
            Coding::Zstd => {
                // StreamingDecoder's default 128 MiB window cap bounds the
                // allocation a hostile frame can trigger
                let decoder =
                    ruzstd::decoding::StreamingDecoder::new(data).map_err(|_| INVALID_ZSTD)?;
                read_bounded(decoder, limit, too_large, INVALID_ZSTD)
            }
        }
    }
}

/// Intermediate buffer of the brotli streaming decoder, in `bytes`.
const BROTLI_READ_BUF: usize = 8 * 1024;
const INVALID_ZSTD: &str = "invalid zstd body";

/// Reads a streaming decoder to at most `limit` bytes: a body decoding to
/// more than `limit` (or failing mid-stream) is rejected.
fn read_bounded(
    mut decoder: impl Read,
    limit: usize,
    too_large: impl FnOnce() -> String,
    invalid: &str,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0u8; BROTLI_READ_BUF];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > limit {
                    return Err(too_large());
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(_) => return Err(invalid.to_string()),
        }
    }
}

/// The DEFLATE data of a gzip member (RFC 1952 header skipped; the trailer
/// and further members are ignored).
fn gzip_payload(data: &[u8]) -> Result<&[u8], String> {
    let bad = || "invalid gzip header".to_string();
    if data.len() < 10 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err(bad());
    }
    let flags = data[3];
    let mut pos = 10;
    if flags & 4 != 0 {
        let len = usize::from(u16::from_le_bytes([
            *data.get(pos).ok_or_else(bad)?,
            *data.get(pos + 1).ok_or_else(bad)?,
        ]));
        pos += 2 + len;
    }
    for flag in [8u8, 16] {
        if flags & flag != 0 {
            let end =
                data.get(pos..).ok_or_else(bad)?.iter().position(|&b| b == 0).ok_or_else(bad)?;
            pos += end + 1;
        }
    }
    if flags & 2 != 0 {
        pos += 2;
    }
    data.get(pos..).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
        out.extend_from_slice(b"name\0");
        out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
        out.extend_from_slice(&[0; 8]);
        out
    }

    #[test]
    fn gzip_and_deflate() {
        assert_eq!(Coding::Gzip.decode(&gzip(b"hello"), 100).unwrap(), b"hello");
        let z = miniz_oxide::deflate::compress_to_vec_zlib(b"zlib", 6);
        assert_eq!(Coding::Deflate.decode(&z, 100).unwrap(), b"zlib");
        let raw = miniz_oxide::deflate::compress_to_vec(b"raw", 6);
        assert_eq!(Coding::Deflate.decode(&raw, 100).unwrap(), b"raw");
        assert!(Coding::Gzip.decode(b"nope", 100).is_err());
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        brotli::CompressorReader::new(data, 4096, 5, 20).read_to_end(&mut out).unwrap();
        out
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    #[test]
    fn brotli_and_zstd() {
        assert_eq!(Coding::Brotli.decode(&brotli(b"hello brotli"), 100).unwrap(), b"hello brotli");
        assert_eq!(Coding::Zstd.decode(&zstd(b"hello zstd"), 100).unwrap(), b"hello zstd");
        assert_eq!(Coding::Brotli.decode(b"nope", 100).unwrap_err(), "invalid brotli body");
        assert_eq!(Coding::Zstd.decode(b"nope", 100).unwrap_err(), "invalid zstd body");
        // truncated zstd stream
        let z = zstd(b"truncated");
        assert_eq!(Coding::Zstd.decode(&z[..z.len() - 1], 100).unwrap_err(), INVALID_ZSTD);
    }

    #[test]
    fn bomb_is_bounded() {
        let big = vec![0u8; 1 << 20];
        let err = Coding::Gzip.decode(&gzip(&big), 1000).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
        let err = Coding::Brotli.decode(&brotli(&big), 1000).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
        let err = Coding::Zstd.decode(&zstd(&big), 1000).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn codings() {
        assert_eq!(Coding::of(" GZIP "), Some(Coding::Gzip));
        assert_eq!(Coding::of("br"), Some(Coding::Brotli));
        assert_eq!(Coding::of("ZSTD"), Some(Coding::Zstd));
        // needs the dictionary the host does not have: stays encoded
        assert_eq!(Coding::of("zstd-dictionary; dict-id=5"), None);
    }
}
