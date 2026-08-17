//! What this service must get right, driven by the incident that prompted it.
//!
//! A production rule differed from a working one by a single backslash and matched nothing
//! for a day while looking correct. Every case below is either that bug, or one of the ways
//! this tester could give a confidently wrong answer about it.

use std::collections::HashMap;

use base64::Engine as _;

// The binary's modules, included directly: this is a small service and a library crate
// alongside it would exist only to be tested.
#[path = "../src/eval.rs"]
mod eval;
#[path = "../src/scheme.rs"]
mod scheme;

/// The real upload, as F5 captured it: a multipart body whose file part names an .html file.
fn html_upload() -> eval::Request {
    let body = "------WebKitFormBoundaryDXGWqBZf7lQYUBak\r\n\
Content-Disposition: form-data; name=\"subm\"\r\n\r\n1\r\n\
------WebKitFormBoundaryDXGWqBZf7lQYUBak\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"test.html\"\r\n\
Content-Type: text/html\r\n\r\n<!DOCTYPE html>\r\n<html>\r\n";

    let mut fields = HashMap::new();
    fields.insert("http.host".to_string(), "app2.jobs.bg".to_string());
    fields.insert("http.request.method".to_string(), "POST".to_string());
    fields.insert(
        "http.request.uri.path".to_string(),
        "/js_file.php".to_string(),
    );
    fields.insert(
        "http.request.uri.query".to_string(),
        "subm=1&ajax=1".to_string(),
    );
    fields.insert("ip.src".to_string(), "87.243.106.179".to_string());

    let mut encoded = HashMap::new();
    encoded.insert(
        "http.request.body.raw".to_string(),
        base64::engine::general_purpose::STANDARD.encode(body),
    );

    eval::Request {
        id: "html-upload".to_string(),
        fields,
        fields_base64: encoded,
        body_truncated: false,
    }
}

/// A legitimate CV whose CONTENT mentions .html" — the false positive to avoid.
fn pdf_upload() -> eval::Request {
    let body = "------WebKitFormBoundaryX\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"CV_Ivana.pdf\"\r\n\
Content-Type: application/pdf\r\n\r\n%PDF-1.4 <a href=\"portfolio.html\">see</a>\r\n";

    let mut request = html_upload();
    request.id = "pdf-upload".to_string();
    request.fields_base64.insert(
        "http.request.body.raw".to_string(),
        base64::engine::general_purpose::STANDARD.encode(body),
    );
    request
}

fn matched(evaluation: &eval::Evaluation, id: &str) -> bool {
    assert!(
        evaluation.valid,
        "expression was refused: {:?}",
        evaluation.error
    );
    evaluation
        .results
        .iter()
        .find(|outcome| outcome.id == id)
        .unwrap_or_else(|| panic!("no verdict for {id}"))
        .matched
}

// THE BUG THIS SERVICE EXISTS FOR. `\\.` in a wirefilter string literal collapses to one
// literal backslash, so the pattern asks the body for a backslash before .html — which no
// multipart body contains. Deployed, it matched nothing for a day and looked correct.
#[test]
fn the_double_backslash_that_matched_nothing() {
    let scheme = scheme::build();
    let requests = vec![html_upload()];

    let broken = r#"(http.request.uri.path eq "/js_file.php" and http.request.method eq "POST") and (http.request.body.raw matches "(?i)filename=\"[^\"]*\\.html?\"")"#;
    let fixed = r#"(http.request.uri.path eq "/js_file.php" and http.request.method eq "POST") and (http.request.body.raw matches "(?i)filename=\"[^\"]*\.html?\"")"#;

    assert!(
        !matched(&eval::evaluate(&scheme, broken, &requests), "html-upload"),
        "the double-backslash form must reproduce its production behaviour: no match"
    );
    assert!(
        matched(&eval::evaluate(&scheme, fixed, &requests), "html-upload"),
        "the single-backslash form must match the upload"
    );
}

// Raw strings are how real rules are written, and the published 0.6.1 crate cannot parse
// them. Pinning to git is the only reason this passes, and a regression in that pin would
// make the tester reject rules that work in production.
#[test]
fn raw_strings_parse() {
    let scheme = scheme::build();
    let evaluation = eval::evaluate(
        &scheme,
        r#"http.request.uri.path matches r"\.(swf|htm|gz)$""#,
        &[html_upload()],
    );

    assert!(
        evaluation.valid,
        "raw strings must parse: {:?}",
        evaluation.error
    );
}

// The uploaded file's bytes are in the body too, so a bare substring test matches a PDF that
// merely links to an .html page. Anchoring on filename= is what separates them, and the
// tester has to be able to show that difference.
#[test]
fn anchoring_on_the_filename_avoids_the_false_positive() {
    let scheme = scheme::build();
    let requests = vec![html_upload(), pdf_upload()];

    let anchored = r#"http.request.body.raw matches "(?i)filename=\"[^\"]*\.html?\"""#;
    let loose = r#"http.request.body.raw contains ".html\"""#;

    let anchored_result = eval::evaluate(&scheme, anchored, &requests);
    assert!(matched(&anchored_result, "html-upload"));
    assert!(
        !matched(&anchored_result, "pdf-upload"),
        "the anchored form must ignore the PDF"
    );

    let loose_result = eval::evaluate(&scheme, loose, &requests);
    assert!(matched(&loose_result, "html-upload"));
    assert!(
        matched(&loose_result, "pdf-upload"),
        "the loose form matches the PDF, which is why it is unsafe to enforce"
    );
}

// An expression naming a field Cloudflare computes at the edge cannot be answered here, and
// saying "no match" would be a lie an operator would act on.
#[test]
fn a_field_we_cannot_fill_is_refused_by_name() {
    let scheme = scheme::build();
    let evaluation = eval::evaluate(
        &scheme,
        r#"cf.bot_management.score < 30 and http.request.method eq "POST""#,
        &[html_upload()],
    );

    assert!(
        !evaluation.valid,
        "an unavailable field must not produce a verdict"
    );
    assert!(
        evaluation
            .unavailable_fields
            .iter()
            .any(|f| f == "cf.bot_management.score"),
        "the field must be named: {:?}",
        evaluation.unavailable_fields
    );
    assert!(
        evaluation.results.is_empty(),
        "a refused expression has no results"
    );
}

// F5 logs a bounded prefix of the request. A body expression that misses may be missing on
// the evidence rather than on the request, and only a NO is in doubt.
#[test]
fn truncated_bodies_qualify_only_the_misses() {
    let scheme = scheme::build();

    let mut miss = html_upload();
    miss.id = "truncated-miss".to_string();
    miss.body_truncated = true;
    miss.fields_base64.insert(
        "http.request.body.raw".to_string(),
        base64::engine::general_purpose::STANDARD.encode("Content-Disposition: form-data;"),
    );

    let mut hit = html_upload();
    hit.id = "truncated-hit".to_string();
    hit.body_truncated = true;

    let expression = r#"http.request.body.raw matches "(?i)filename=\"[^\"]*\.html?\"""#;
    let evaluation = eval::evaluate(&scheme, expression, &[miss, hit]);

    let caveat = |id: &str| {
        evaluation
            .results
            .iter()
            .find(|o| o.id == id)
            .expect("a verdict")
            .caveat
            .is_some()
    };
    assert!(
        caveat("truncated-miss"),
        "a miss on a truncated body must be qualified"
    );
    assert!(
        !caveat("truncated-hit"),
        "a match found in the captured prefix is a match at the edge, with no caveat"
    );
}

// An expression that reads no body needs no caveat, however truncated the capture was.
#[test]
fn a_non_body_expression_is_never_qualified() {
    let scheme = scheme::build();
    let mut request = html_upload();
    request.body_truncated = true;

    let evaluation = eval::evaluate(&scheme, r#"http.request.method eq "GET""#, &[request]);

    assert!(evaluation.valid);
    assert!(evaluation.results[0].caveat.is_none());
}

// A broken expression is the ANSWER this endpoint gives, not an internal failure, so it
// reports invalid with the parser's own words and no verdicts.
#[test]
fn a_malformed_expression_is_reported_not_panicked() {
    let scheme = scheme::build();
    let evaluation = eval::evaluate(&scheme, "http.request.method eq", &[html_upload()]);

    assert!(!evaluation.valid);
    assert!(evaluation.error.is_some());
    assert!(evaluation.results.is_empty());
}

// Bounds exist because this takes an expression and data from a caller.
#[test]
fn oversized_input_is_refused() {
    let scheme = scheme::build();

    let long = format!(
        r#"http.request.uri.path eq "{}""#,
        "x".repeat(eval::MAX_EXPRESSION_BYTES)
    );
    assert!(
        !eval::evaluate(&scheme, &long, &[]).valid,
        "an oversized expression is refused"
    );

    let many: Vec<eval::Request> = (0..eval::MAX_REQUESTS + 1).map(|_| html_upload()).collect();
    assert!(
        !eval::evaluate(&scheme, r#"http.request.method eq "POST""#, &many).valid,
        "too many requests in one call is refused"
    );
}

// A request that names no fields at all must still evaluate: an unset field would otherwise
// fail the whole batch, turning "this request had no referer" into no answer for anyone.
#[test]
fn missing_fields_are_empty_not_fatal() {
    let scheme = scheme::build();
    let bare = eval::Request {
        id: "bare".to_string(),
        fields: HashMap::new(),
        fields_base64: HashMap::new(),
        body_truncated: false,
    };

    let evaluation = eval::evaluate(&scheme, r#"http.referer eq "https://x/""#, &[bare]);
    assert!(
        evaluation.valid,
        "a request with no fields must evaluate: {:?}",
        evaluation.error
    );
    assert!(!evaluation.results[0].matched);
}
