//! The basic read-only(-plus-pause/resume) dashboard: one self-contained
//! HTML file (inline CSS/JS, no build step, no external asset fetches)
//! compiled directly into this binary via `include_str!` and served as a
//! static response. Simple on purpose -- see the crate root doc comment.
//!
//! The one thing generated per request rather than baked in at compile time
//! is a `Content-Security-Policy` nonce: a fresh, unguessable value is
//! substituted into the page's `<script nonce="...">` tag and into the
//! `script-src` directive of the CSP header sent alongside it, so the
//! page's own inline script runs (the nonces match) but nothing an
//! attacker could inject would (a different, unpredictable nonce is
//! generated on every request, so there is no fixed value to smuggle into
//! injected markup). `style-src` allows `'unsafe-inline'` instead of a
//! nonce -- CSS injection is a far narrower risk than script injection, and
//! nonce-ing the `<style>` block too would need the same per-request
//! substitution for no meaningful hardening gain. `connect-src 'self'`
//! matches the page's own real behavior (it only ever calls same-origin
//! `/api/*`); `frame-ancestors 'none'`/`base-uri 'none'`/`form-action
//! 'none'` close off clickjacking/base-tag/form-hijack vectors this page
//! has no legitimate use for.

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};

const INDEX_HTML_TEMPLATE: &str = include_str!("../webui/index.html");

pub async fn index() -> Response {
    let nonce = crate::token::random_hex(16);
    let html = INDEX_HTML_TEMPLATE.replacen("%%CSP_NONCE%%", &nonce, 1);
    let csp = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; \
         connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let mut res = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
    if let Ok(value) = HeaderValue::from_str(&csp) {
        res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, value);
    }
    res
}
