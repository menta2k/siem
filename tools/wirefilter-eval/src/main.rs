//! A local evaluator for Cloudflare rule expressions.
//!
//! Stage 1 of the WAF migration asks the operator to write a Cloudflare rule that would
//! catch the requests F5 blocked. Until now the only way to find out whether it does was to
//! deploy it in log mode and wait, and a mistake cost hours: one production rule differed
//! from a working one by a single backslash -- `\\.` reaching the regex engine as a literal
//! backslash -- and matched nothing for a day while looking correct.
//!
//! This service answers the question before the rule is deployed, using Cloudflare's OWN
//! expression engine, so a verdict here means what it means in the dashboard.
//!
//! It has no state, no database and no outbound calls: an expression and some captured
//! fields in, a verdict per request out.

mod eval;
mod scheme;

use std::io::Read;
use std::net::SocketAddr;

use serde::Deserialize;
use tiny_http::{Header, Method, Request as HttpRequest, Response, Server};
use wirefilter::Scheme;

/// The body POST /evaluate takes.
#[derive(Debug, Deserialize)]
struct EvaluateBody {
    expression: String,
    #[serde(default)]
    requests: Vec<eval::Request>,
}

/// Bounds the request body, because this is a network boundary.
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

fn main() {
    let addr: SocketAddr = std::env::var("WIREFILTER_EVAL_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8010".to_string())
        .parse()
        .expect("WIREFILTER_EVAL_BIND must be host:port");

    // Built once. The scheme is fixed, and rebuilding it per request would be the only
    // expensive thing this service does.
    let scheme = scheme::build();

    let server = Server::http(addr).expect("bind the evaluator port");
    eprintln!("wirefilter-eval listening on {addr}");

    for request in server.incoming_requests() {
        handle(request, &scheme);
    }
}

fn handle(mut request: HttpRequest, scheme: &Scheme) {
    let route = (request.method().clone(), request.url().to_string());
    let response = match (route.0, route.1.as_str()) {
        // Liveness for the compose healthcheck. Reports the fields a caller may use, so
        // the surface is discoverable without reading this source.
        (Method::Get, "/healthz") => json(
            200,
            &serde_json::json!({
                "status": "ok",
                "supported_fields": scheme::supported(),
            }),
        ),
        (Method::Post, "/evaluate") => evaluate(&mut request, scheme),
        _ => json(404, &serde_json::json!({ "error": "not found" })),
    };

    if let Err(err) = request.respond(response) {
        eprintln!("respond: {err}");
    }
}

fn evaluate(request: &mut HttpRequest, scheme: &Scheme) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if let Err(err) = request
        .as_reader()
        .take(MAX_BODY_BYTES)
        .read_to_string(&mut body)
    {
        return json(
            400,
            &serde_json::json!({ "error": format!("read body: {err}") }),
        );
    }

    let parsed: EvaluateBody = match serde_json::from_str(&body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return json(
                400,
                &serde_json::json!({ "error": format!("decode body: {err}") }),
            )
        }
    };

    // A 200 carrying valid=false, not a 4xx. An expression that does not parse is the
    // ANSWER this endpoint exists to give — the caller asked whether it works — and dressing
    // it as a transport error would make every client treat a normal outcome as a failure.
    json(
        200,
        &eval::evaluate(scheme, &parsed.expression, &parsed.requests),
    )
}

fn json<T: serde::Serialize>(status: u16, body: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let encoded = serde_json::to_vec(body)
        .unwrap_or_else(|err| format!("{{\"error\":\"encode response: {err}\"}}").into_bytes());
    Response::from_data(encoded)
        .with_status_code(status)
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                .expect("a static header parses"),
        )
}
