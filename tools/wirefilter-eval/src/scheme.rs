//! The fields an expression may reference here, and nothing more.
//!
//! Deliberately a SUBSET of Cloudflare's. A field is listed only when the platform can
//! actually fill it from a captured request, because a field that parses and is always
//! empty is worse than one that is refused: the expression would evaluate, report no match,
//! and the reader would conclude their rule is wrong.
//!
//! Everything Cloudflare computes at the edge — bot scores, JA4 signals, threat scores,
//! ASN intelligence — is therefore absent by design. Those cannot be reconstructed from a
//! stored request at all, and an expression using one is reported as unevaluatable rather
//! than answered.

use wirefilter::{Scheme, SchemeBuilder, Type};

/// The Bytes fields, in the order they are documented to callers.
pub const BYTE_FIELDS: &[&str] = &[
    "http.host",
    "http.request.method",
    "http.request.uri",
    "http.request.uri.path",
    "http.request.uri.query",
    "http.request.body.raw",
    "http.user_agent",
    "http.referer",
    "http.cookie",
];

/// The IP fields.
pub const IP_FIELDS: &[&str] = &["ip.src"];

/// build assembles the scheme every request is evaluated against.
pub fn build() -> Scheme {
    let mut builder = SchemeBuilder::new();
    for field in BYTE_FIELDS {
        builder
            .add_field(*field, Type::Bytes)
            .expect("byte field names are unique");
    }
    for field in IP_FIELDS {
        builder
            .add_field(*field, Type::Ip)
            .expect("ip field names are unique");
    }
    builder.build()
}

/// supported lists every field name, for the error a caller sees when they use another.
pub fn supported() -> Vec<String> {
    BYTE_FIELDS
        .iter()
        .chain(IP_FIELDS.iter())
        .map(|field| (*field).to_string())
        .collect()
}
