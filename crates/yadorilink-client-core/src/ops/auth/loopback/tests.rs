#![cfg(test)]

use super::*;

const ISSUER: &str = "https://as.test";

async fn get(uri: &str, target: &str) -> String {
    let authority = uri.trim_start_matches("http://").split('/').next().expect("authority");
    let mut stream = TcpStream::connect(authority).await.expect("connect");
    stream
        .write_all(format!("GET {target} HTTP/1.1\r\nhost: localhost\r\n\r\n").as_bytes())
        .await
        .expect("write");
    let mut body = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut body).await.expect("read");
    String::from_utf8_lossy(&body).into_owned()
}

#[tokio::test]
async fn the_registered_uri_names_the_port_the_kernel_gave_and_the_loopback_address() {
    let listener = Listener::bind().await.expect("bind");
    let uri = Url::parse(listener.redirect_uri()).expect("a URL");
    assert_eq!(uri.host_str(), Some("127.0.0.1"));
    assert_eq!(uri.path(), CALLBACK_PATH);
    assert!(uri.port().expect("a port") > 0);
}

#[tokio::test]
async fn the_code_is_returned_when_the_state_is_the_one_this_process_pushed() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    let page =
        get(&uri, &format!("{CALLBACK_PATH}?code=the-code&state=the-state&iss={ISSUER}")).await;
    assert!(page.contains("200 OK"), "{page}");
    assert_eq!(waiting.await.expect("join").expect("a code"), "the-code");
}

/// Anything on this machine can open the redirect URL. `state` is what says
/// the code that arrived belongs to the request this process made, so a
/// mismatch must not be exchanged -- and must not be reported as a success
/// that simply found no code.
#[tokio::test]
async fn a_code_arriving_with_someone_elses_state_is_refused_rather_than_exchanged() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    let page = get(&uri, &format!("{CALLBACK_PATH}?code=injected&state=somebody-elses")).await;
    assert!(page.contains("400 Bad Request"), "{page}");

    let err = waiting.await.expect("join").expect_err("an injected code must be refused");
    let message = err.to_string();
    assert!(message.contains("does not match"), "{message}");
    assert!(message.contains("nothing was written"), "{message}");
}

/// FAPI 2.0 Final requires the client to verify the `iss` response
/// parameter, precisely because `state` alone does not rule out a
/// mix-up attack: a second Authorization Server that also learned this
/// process's `state` value could redirect here claiming to be the real
/// issuer. A redirect with no `iss` at all -- an older/misconfigured
/// server, or one omitting it entirely -- must be refused the same way
/// a mismatched `state` is, not treated as a success that merely lacks
/// an opinion on the issuer.
#[tokio::test]
async fn a_redirect_with_no_iss_at_all_is_refused() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    let page = get(&uri, &format!("{CALLBACK_PATH}?code=the-code&state=the-state")).await;
    assert!(page.contains("400 Bad Request"), "{page}");

    let err = waiting.await.expect("join").expect_err("a missing iss must be refused");
    let message = err.to_string();
    assert!(message.contains("`iss`"), "{message}");
    assert!(message.contains("nothing was written"), "{message}");
}

/// The same refusal, for an `iss` naming a DIFFERENT issuer than the one
/// this login actually discovered against -- the exact mix-up-attack
/// shape `iss` verification exists to close.
#[tokio::test]
async fn a_redirect_naming_a_different_issuer_is_refused() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    let page = get(
        &uri,
        &format!("{CALLBACK_PATH}?code=the-code&state=the-state&iss=https://not-{ISSUER}"),
    )
    .await;
    assert!(page.contains("400 Bad Request"), "{page}");

    let err = waiting.await.expect("join").expect_err("a wrong iss must be refused");
    let message = err.to_string();
    assert!(message.contains("`iss`"), "{message}");
    assert!(message.contains("nothing was written"), "{message}");
}

/// The positive case: an `iss` that matches exactly is not itself a
/// reason to refuse -- the code is returned same as it always was.
#[tokio::test]
async fn a_redirect_naming_the_correct_issuer_proceeds_normally() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    let page =
        get(&uri, &format!("{CALLBACK_PATH}?code=the-code&state=the-state&iss={ISSUER}")).await;
    assert!(page.contains("200 OK"), "{page}");
    assert_eq!(waiting.await.expect("join").expect("a code"), "the-code");
}

/// A failed sign-in reports the server's own OAuth code, and reports that
/// the store was left alone -- the two things a human needs and the only
/// two.
#[tokio::test]
async fn an_authorization_server_refusal_is_reported_rather_than_waited_out() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    get(&uri, &format!("{CALLBACK_PATH}?error=access_denied&state=the-state&iss={ISSUER}")).await;

    let err = waiting.await.expect("join").expect_err("a refusal is not a login");
    assert!(err.to_string().contains("access_denied"), "{err}");
}

/// A browser asking for `/favicon.ico` must not end a login that has not
/// happened yet.
#[tokio::test]
async fn a_request_that_is_not_the_redirect_does_not_end_the_wait() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    let ignored = get(&uri, "/favicon.ico").await;
    assert!(ignored.contains("404 Not Found"), "{ignored}");

    let page =
        get(&uri, &format!("{CALLBACK_PATH}?code=the-code&state=the-state&iss={ISSUER}")).await;
    assert!(page.contains("200 OK"), "{page}");
    assert_eq!(waiting.await.expect("join").expect("a code"), "the-code");
}

/// The page a browser is looking at must not carry bytes the request chose.
#[tokio::test]
async fn nothing_from_the_request_is_echoed_into_the_page() {
    let listener = Listener::bind().await.expect("bind");
    let uri = listener.redirect_uri().to_owned();
    let waiting = tokio::spawn(async move {
        listener.wait_for_code("the-state", ISSUER, Duration::from_secs(5)).await
    });

    let hostile = "%3Cscript%3Ealert(1)%3C/script%3E";
    let page = get(&uri, &format!("{CALLBACK_PATH}?code=c&state={hostile}")).await;
    assert!(!page.contains("<script"), "{page}");
    assert!(!page.contains("alert(1)"), "{page}");
    let _ = waiting.await.expect("join");
}

/// A login nobody finishes has to end, and has to say what to do next.
#[tokio::test]
async fn a_sign_in_that_never_arrives_times_out_with_an_actionable_message() {
    let listener = Listener::bind().await.expect("bind");
    let err = listener
        .wait_for_code("the-state", ISSUER, Duration::from_millis(50))
        .await
        .expect_err("nothing arrived");
    let message = err.to_string();
    assert!(message.contains("no sign-in arrived"), "{message}");
    assert!(message.contains("yadorilink login"), "{message}");
}
