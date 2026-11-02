//! Following the authorization endpoint without a browser: what is followed, what is refused.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
use yadorilink_fapi_client::{Error, Es256Key, FapiClient};

const REDIRECT: &str = "http://127.0.0.1:41234/cli/callback";

async fn client(server: &MockServer) -> FapiClient {
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "pushed_authorization_request_endpoint": format!("{issuer}/request"),
            "require_pushed_authorization_requests": true,
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
        })))
        .mount(server)
        .await;
    FapiClient::discover(
        reqwest::Client::new(),
        &issuer,
        "ylk-AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .await
    .expect("discovery")
}

#[tokio::test]
async fn relative_and_absolute_redirects_are_followed_with_their_cookies_to_the_registered_redirect(
) {
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/auth"))
        .respond_with(
            ResponseTemplate::new(303)
                .insert_header("location", "/interaction/u1")
                .insert_header("set-cookie", "_i=1; path=/interaction"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/interaction/u1"))
        .respond_with(move |request: &Request| {
            let has_cookie = request.headers.get("cookie").is_some_and(|c| c == "_i=1");
            if has_cookie {
                ResponseTemplate::new(303)
                    .insert_header("location", format!("{issuer}/resume").as_str())
            } else {
                ResponseTemplate::new(400)
            }
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/resume"))
        .respond_with(
            ResponseTemplate::new(303)
                .insert_header("location", format!("{REDIRECT}?code=c1&state=s1").as_str()),
        )
        .mount(&server)
        .await;
    let client = client(&server).await;

    let landed = client.authorize_without_browser("urn:par:1", REDIRECT).await.expect("a redirect");

    assert_eq!(landed.as_str(), format!("{REDIRECT}?code=c1&state=s1"));
}

#[tokio::test]
async fn a_page_instead_of_a_redirect_needs_a_person() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<form>sign in</form>"))
        .mount(&server)
        .await;
    let client = client(&server).await;

    let error = client.authorize_without_browser("urn:par:1", REDIRECT).await.expect_err("a page");

    assert!(matches!(error, Error::BrowserRequired(_)), "{error}");
}

#[tokio::test]
async fn a_redirect_to_another_site_is_not_followed_and_only_its_host_is_reported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auth"))
        .respond_with(ResponseTemplate::new(303).insert_header(
            "location",
            "https://accounts.google.com/o/oauth2/v2/auth?state=do-not-report",
        ))
        .mount(&server)
        .await;
    let client = client(&server).await;

    let error = client.authorize_without_browser("urn:par:1", REDIRECT).await.expect_err("away");

    let text = error.to_string();
    assert!(text.contains("accounts.google.com") && !text.contains("do-not-report"), "{text}");
}

#[tokio::test]
async fn a_redirect_loop_ends() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auth"))
        .respond_with(ResponseTemplate::new(303).insert_header("location", "/auth"))
        .mount(&server)
        .await;
    let client = client(&server).await;

    let error = client.authorize_without_browser("urn:par:1", REDIRECT).await.expect_err("a loop");

    assert!(matches!(error, Error::BrowserRequired(_)), "{error}");
}
