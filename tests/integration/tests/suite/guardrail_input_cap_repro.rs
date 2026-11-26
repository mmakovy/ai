// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Reproducer: the input guardrail's 1 MiB request cap is lost when a separate
//! response-only guardrail is in the same chain.
//!
//! An input-phase `ai_guardrails` filter enforces its cap only through the
//! request buffer it declares (`StreamBuffer { max_bytes: 1 MiB }`). A
//! response-only `ai_guardrails` filter also declares a request buffer, of
//! `MAX_JSON_BODY_BYTES` (64 MiB), so it can read `stream`. The pipeline merges
//! the chain's request buffers and the largest wins (64 MiB). The pipeline then
//! clamps that to the server's `body_limits.max_request_bytes` (10 MiB by
//! default), so the effective request limit becomes 10 MiB and a request just
//! over 1 MiB is no longer rejected.
//!
//! `input_guardrail_alone_enforces_its_1_mib_cap` is the control and passes.
//! `input_guardrail_keeps_its_1_mib_cap_next_to_a_response_guardrail` asserts
//! the expected behaviour (413) and fails while the defect exists.
//! `input_guardrail_keeps_its_1_mib_cap_when_the_response_guardrail_is_not_selected`
//! gates both guardrails by header, as ai-gateway-controller does, and selects
//! only the input one: the response guardrail never runs on the request, yet
//! the buffer sizes are merged once when the chain is built, without looking at
//! conditions.

use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, BackendGuard, StatefulCapturingBackend, StatefulCapturingGuard, free_port, http_post, http_send,
    json_post_with_header, parse_body, parse_status, start_proxy,
};

/// The input guardrail's request cap (`DEFAULT_MAX_BODY_BYTES` in
/// `filters/src/guardrails/filter.rs`).
const GUARD_LIMIT: usize = 1_048_576;

/// Selection header for the input guardrail in the gated chain. The
/// controller uses `x-aigateway-guardrail-<hash>`; the name does not matter
/// to praxis.
const INPUT_HEADER: &str = "x-aigateway-guardrail-input";

/// Selection header for the response guardrail in the gated chain. Never sent.
const OUTPUT_HEADER: &str = "x-aigateway-guardrail-output";

/// A valid chat completion for the fake upstream to return.
const CHAT_COMPLETION: &str = r#"{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// A `NeMo` verdict that passes the check.
const NEMO_PASS: &str = r#"{"status":"passed","content":"ok"}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Control: with only the input guardrail, a body at the cap passes and one
/// byte over is rejected with 413.
#[test]
fn input_guardrail_alone_enforces_its_1_mib_cap() {
    let (_backend, _nemo, proxy_config) = setup(false);
    let proxy = start_proxy(&proxy_config);

    let (status, body) = http_post(proxy.addr(), "/v1/chat/completions", &padded_chat_body(GUARD_LIMIT));
    assert_eq!(status, 200, "a body at the cap must pass; body: {}", truncate(&body));

    let (status, body) = http_post(proxy.addr(), "/v1/chat/completions", &padded_chat_body(GUARD_LIMIT + 1));
    assert_eq!(status, 413, "one byte over the cap must be rejected; body: {}", truncate(&body));
}

/// Defect: adding a separate response-only guardrail must not lift the input
/// guardrail's cap. Fails today: the request is accepted (200) because the
/// response guardrail's 64 MiB request buffer wins the merge, leaving only the
/// server's 10 MiB default `body_limits.max_request_bytes` in force.
#[test]
fn input_guardrail_keeps_its_1_mib_cap_next_to_a_response_guardrail() {
    let (_backend, _nemo, proxy_config) = setup(true);
    let proxy = start_proxy(&proxy_config);

    let (status, body) = http_post(proxy.addr(), "/v1/chat/completions", &padded_chat_body(GUARD_LIMIT + 1));
    assert_eq!(
        status,
        413,
        "one byte over the input guardrail's 1 MiB cap must still be rejected when a response-only \
         guardrail is in the chain; body: {}",
        truncate(&body)
    );
}

/// Defect, header-gated variant: both guardrails carry a header condition and
/// only the input guardrail is selected, so the response guardrail never runs
/// on the request. Its 64 MiB request buffer must still not lift the input
/// guardrail's cap. Fails today with 200.
///
/// The first request (at the cap) checks the gating itself: exactly one
/// `NeMo` call proves the input guardrail ran and the response guardrail did
/// not (it would add a second call on the response).
///
/// Note: praxis's own pipeline validation rejects request `conditions:` on
/// security filters such as `ai_guardrails`, so standalone praxis-ai would
/// refuse this config at startup; the test harness builds the pipeline without
/// that step. It is the shape ai-gateway-controller generates for
/// praxis-extproc, which does not run that validation.
#[test]
fn input_guardrail_keeps_its_1_mib_cap_when_the_response_guardrail_is_not_selected() {
    let backend = StatefulCapturingBackend::new(vec![(200, CHAT_COMPLETION.to_owned()); 2]).start_with_shutdown();
    let nemo = StatefulCapturingBackend::new(vec![(200, NEMO_PASS.to_owned()); 4]).start_with_shutdown();
    let yaml = chain_yaml(free_port(), backend.port(), nemo.port(), true, true);
    let proxy_config = Config::from_yaml(&yaml).expect("reproducer config must parse");
    let proxy = start_proxy(&proxy_config);

    let (status, body) = post_selecting_input(proxy.addr(), GUARD_LIMIT);
    assert_eq!(status, 200, "a body at the cap must pass; body: {}", truncate(&body));
    assert_eq!(
        post_count(&nemo),
        1,
        "only the selected input guardrail may call NeMo; the response guardrail must be skipped"
    );
    assert_eq!(post_count(&backend), 1, "the body at the cap must reach the backend");

    let (status, body) = post_selecting_input(proxy.addr(), GUARD_LIMIT + 1);
    let nemo_calls = post_count(&nemo) - 1;
    let backend_requests = post_count(&backend) - 1;
    assert_eq!(
        status,
        413,
        "one byte over the input guardrail's 1 MiB cap must be rejected even though the response guardrail \
         is not selected; NeMo calls for this request: {nemo_calls}, backend requests: {backend_requests}; \
         body: {}",
        truncate(&body)
    );
    assert_eq!(nemo_calls, 0, "a rejected body must not be evaluated");
    assert_eq!(backend_requests, 0, "a rejected body must not reach the backend");
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// POST a padded chat body of `len` bytes with only the input guardrail's
/// selection header set.
fn post_selecting_input(addr: &str, len: usize) -> (u16, String) {
    let request = json_post_with_header(
        "/v1/chat/completions",
        &padded_chat_body(len),
        &format!("{INPUT_HEADER}: true"),
    );
    let raw = http_send(addr, &request);
    (parse_status(&raw), parse_body(&raw))
}

/// Number of POST requests a capturing backend has received. Health probes
/// (GET and HEAD) are captured too and are excluded.
fn post_count(backend: &StatefulCapturingGuard) -> usize {
    backend.requests().iter().filter(|request| request.method == "POST").count()
}

/// Start a fake upstream and a fake NeMo, and build the proxy config.
///
/// The upstream returns a valid chat completion so the response-phase
/// guardrail has something well-formed to evaluate; NeMo passes every check.
fn setup(with_response_guardrail: bool) -> (BackendGuard, BackendGuard, Config) {
    let backend = Backend::status(200, CHAT_COMPLETION)
        .header("Content-Type", "application/json")
        .start_with_shutdown();
    let nemo = Backend::status(200, NEMO_PASS)
        .header("Content-Type", "application/json")
        .start_with_shutdown();

    let yaml = chain_yaml(free_port(), backend.port(), nemo.port(), with_response_guardrail, false);
    let config = Config::from_yaml(&yaml).expect("reproducer config must parse");
    (backend, nemo, config)
}

/// The `nemo-guardrails.yaml` example chain, with an optional second, separate
/// response-only guardrail, as ai-gateway-controller generates one filter per
/// check and phase. With `gated`, each guardrail runs only when its selection
/// header is `"true"`, as the controller's generated filters do.
fn chain_yaml(
    proxy_port: u16,
    backend_port: u16,
    nemo_port: u16,
    with_response_guardrail: bool,
    gated: bool,
) -> String {
    let guardrail = |request: bool, response: bool, header: &str| {
        let conditions = if gated {
            format!(
                r#"
        conditions:
          - when:
              headers:
                {header}: "true""#
            )
        } else {
            String::new()
        };
        format!(
            r#"
      - filter: ai_guardrails{conditions}
        outbound_chain: nemo-outbound
        provider:
          type: nemo
          endpoint: "http://127.0.0.1:{nemo_port}/v1/checks"
          guardrails:
            config_ids: ["test-config"]
          timeout_ms: 5000
          max_message_checks: 32
        phase:
          request: {request}
          response: {response}"#
        )
    };
    let response_guardrail = if with_response_guardrail {
        guardrail(false, true, OUTPUT_HEADER)
    } else {
        String::new()
    };
    let input_guardrail = guardrail(true, false, INPUT_HEADER);

    format!(
        r#"
listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - nemo-guardrails
filter_chains:
  - name: nemo-guardrails
    filters:
      - filter: ai_operation{input_guardrail}{response_guardrail}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: provider
      - filter: load_balancer
        clusters:
          - name: provider
            endpoints:
              - "127.0.0.1:{backend_port}"
  - name: nemo-outbound
    filters:
      - filter: request_id
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
"#
    )
}

/// A valid chat-completions body padded with trailing spaces to exactly
/// `len` bytes. Trailing whitespace keeps it valid JSON, so the guardrail
/// extracts the same prompt regardless of size.
fn padded_chat_body(len: usize) -> String {
    let mut body = r#"{"model":"test","messages":[{"role":"user","content":"hello"}]}"#.to_owned();
    assert!(body.len() <= len, "padding target is smaller than the base body");
    body.extend(std::iter::repeat_n(' ', len - body.len()));
    body
}

/// Keep assertion messages readable when a response body is large.
fn truncate(body: &str) -> &str {
    body.get(..300).unwrap_or(body)
}
