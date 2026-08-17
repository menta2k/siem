//! Parsing and executing one expression against many captured requests.
//!
//! The whole point of this service is that a verdict here means what it means in the
//! Cloudflare dashboard, because it is the same engine. So this module adds no
//! interpretation of its own: it fills fields, runs the filter, and reports what came back.
//!
//! It does add HONESTY about what it cannot answer. A request whose body was captured only
//! as a prefix, or an expression naming a field the platform cannot reconstruct, produce a
//! stated limitation rather than a confident `false` — which is the failure mode that would
//! make the tool worse than useless, since a wrong "no match" is exactly what an operator
//! would act on.

use std::collections::HashMap;
use std::net::IpAddr;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use wirefilter::{ExecutionContext, LhsValue, Scheme};

use crate::scheme;

/// One captured request to evaluate against.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// Opaque to this service; echoed back so the caller can match verdicts to rows.
    pub id: String,
    /// Field values as text. Absent fields are reported, never silently emptied.
    #[serde(default)]
    pub fields: HashMap<String, String>,
    /// Field values that are not text — the raw body, most of all. Base64 so a byte the
    /// JSON encoder would mangle survives the trip intact.
    #[serde(default)]
    pub fields_base64: HashMap<String, String>,
    /// True when the captured value is a PREFIX of what the edge saw. F5 truncates the
    /// request it logs, so a body-matching expression can miss on evidence rather than on
    /// the request, and that difference has to reach the reader.
    #[serde(default)]
    pub body_truncated: bool,
}

/// What one request's evaluation produced.
#[derive(Debug, Serialize, PartialEq)]
pub struct Outcome {
    pub id: String,
    pub matched: bool,
    /// Set when the verdict cannot be trusted as a NO: the expression reads the body and
    /// only a prefix of it was captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<String>,
}

/// The reply to an evaluation request.
#[derive(Debug, Serialize, PartialEq)]
pub struct Evaluation {
    /// False when the expression could not be parsed or uses an unavailable field. The
    /// results are then empty: a broken expression has no verdict, not a false one.
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The fields this service cannot fill, when that is why it refused.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unavailable_fields: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<Outcome>,
}

impl Evaluation {
    fn refused(error: String, unavailable_fields: Vec<String>) -> Self {
        Self {
            valid: false,
            error: Some(error),
            unavailable_fields,
            results: Vec::new(),
        }
    }
}

/// Bounds, because this takes an expression and data from a caller.
///
/// None of these is a guess about what is reasonable: they are the points past which a
/// mistake stops being one request's problem. RE2 has no catastrophic backtracking, so the
/// risk here is size rather than complexity.
pub const MAX_EXPRESSION_BYTES: usize = 8 * 1024;
pub const MAX_REQUESTS: usize = 200;
pub const MAX_FIELD_BYTES: usize = 256 * 1024;

/// evaluate parses the expression once and runs it against every request.
pub fn evaluate(scheme: &Scheme, expression: &str, requests: &[Request]) -> Evaluation {
    if expression.len() > MAX_EXPRESSION_BYTES {
        return Evaluation::refused(
            format!("the expression is longer than {MAX_EXPRESSION_BYTES} bytes"),
            Vec::new(),
        );
    }
    if requests.len() > MAX_REQUESTS {
        return Evaluation::refused(
            format!("more than {MAX_REQUESTS} requests in one call"),
            Vec::new(),
        );
    }

    // Named before parsing, because "unknown field" is the error an operator is most likely
    // to hit and the least likely to understand from the parser's own words.
    let unavailable = unavailable_fields(expression);
    if !unavailable.is_empty() {
        return Evaluation::refused(
            "the expression uses fields this tester cannot reconstruct from a stored request"
                .to_string(),
            unavailable,
        );
    }

    let ast = match scheme.parse(expression) {
        Ok(ast) => ast,
        Err(err) => return Evaluation::refused(err.to_string(), Vec::new()),
    };
    let filter = ast.compile();

    // Whether the expression reads the body decides whether truncation matters. Checked
    // once, not per request.
    let reads_body = expression.contains("http.request.body");

    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        let matched = match execute(scheme, &filter, request) {
            Ok(matched) => matched,
            Err(err) => {
                return Evaluation::refused(format!("request {}: {}", request.id, err), Vec::new())
            }
        };

        // Only a NO is in doubt. A match found in the captured prefix is a match the edge
        // would also have found.
        let caveat = if reads_body && request.body_truncated && !matched {
            Some(
                "only part of the body was captured, so this may match at the edge \
                 even though it does not here"
                    .to_string(),
            )
        } else {
            None
        };
        results.push(Outcome {
            id: request.id.clone(),
            matched,
            caveat,
        });
    }

    Evaluation {
        valid: true,
        error: None,
        unavailable_fields: Vec::new(),
        results,
    }
}

/// execute fills the context for one request and runs the compiled filter.
fn execute(
    scheme: &Scheme,
    filter: &wirefilter::Filter,
    request: &Request,
) -> Result<bool, String> {
    let mut ctx = ExecutionContext::new(scheme);

    // EVERY field is set, whether the caller supplied it or not. An unset field makes
    // wirefilter refuse to execute at all, which would turn "this request had no referer"
    // into a failed evaluation of the whole batch.
    for name in scheme::BYTE_FIELDS {
        let value = field_bytes(request, name)?;
        set(&mut ctx, scheme, name, LhsValue::Bytes(value.into()))?;
    }
    for name in scheme::IP_FIELDS {
        let text = request.fields.get(*name).map(String::as_str).unwrap_or("");
        // Unspecified rather than 0.0.0.0: an address that was never captured must not
        // compare equal to a real one.
        let addr: IpAddr = if text.is_empty() {
            "::".parse().expect("the unspecified address parses")
        } else {
            text.parse()
                .map_err(|_| format!("{name}: {text} is not an IP address"))?
        };
        set(&mut ctx, scheme, name, LhsValue::Ip(addr))?;
    }

    filter.execute(&ctx).map_err(|err| err.to_string())
}

fn set<'a>(
    ctx: &mut ExecutionContext<'a>,
    scheme: &Scheme,
    name: &str,
    value: LhsValue<'a>,
) -> Result<(), String> {
    let field = scheme
        .get_field(name)
        .map_err(|_| format!("{name} is not in the scheme"))?;
    // The previous value is returned and discarded: every field is set exactly once here.
    ctx.set_field_value(field, value)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

/// field_bytes reads one field, preferring the base64 form when both are present.
fn field_bytes(request: &Request, name: &str) -> Result<Vec<u8>, String> {
    if let Some(encoded) = request.fields_base64.get(name) {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| format!("{name}: not valid base64"))?;
        if decoded.len() > MAX_FIELD_BYTES {
            return Err(format!("{name}: longer than {MAX_FIELD_BYTES} bytes"));
        }
        return Ok(decoded);
    }

    let text = request.fields.get(name).map(String::as_str).unwrap_or("");
    if text.len() > MAX_FIELD_BYTES {
        return Err(format!("{name}: longer than {MAX_FIELD_BYTES} bytes"));
    }
    Ok(text.as_bytes().to_vec())
}

/// unavailable_fields finds the Cloudflare fields an expression names that this scheme has
/// no way to fill.
///
/// Textual, and deliberately so. The parser rejects an unknown field with a position and a
/// name, which is accurate and tells an operator nothing about WHY the name is unknown here
/// — the field exists in Cloudflare, and the honest answer is that it cannot be
/// reconstructed from a stored request. Recognising the shape of a field reference is enough
/// to say that, and a false positive costs only a clearer error than the parser's own.
fn unavailable_fields(expression: &str) -> Vec<String> {
    let supported = scheme::supported();
    let mut found = Vec::new();

    for token in expression.split(|c: char| !(c.is_alphanumeric() || c == '.' || c == '_')) {
        let candidate = token.trim_matches('.');
        // A field reference, as opposed to a value or an operator: dotted, lower case, and
        // starting with one of Cloudflare's namespaces.
        let looks_like_field = candidate.contains('.')
            && candidate.starts_with(|c: char| c.is_ascii_lowercase())
            && ["http.", "ip.", "cf.", "ssl.", "tcp.", "udp.", "icmp."]
                .iter()
                .any(|ns| candidate.starts_with(ns));

        if looks_like_field
            && !supported.iter().any(|field| field == candidate)
            && !found.iter().any(|field| field == candidate)
        {
            found.push(candidate.to_string());
        }
    }
    found
}
