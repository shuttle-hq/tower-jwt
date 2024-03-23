Tower middleware to parse JWT tokens off the Authorization Bearer of requests and store the deserialized claims on the
request extension.

This is build on top of the [jsonwebtoken](https://docs.rs/jsonwebtoken) crate and support all the algorithms supported by that crate.

Since this is a Tower middleware it can be used on any framework like Axum, Tonic, etc.

# Symmetric example using Hyper

``` rust
use chrono::{DateTime, Utc};
use http::{header::AUTHORIZATION, Request, Response, StatusCode};
use hyper::Body;
use jsonwebtoken::{DecodingKey, Validation};
use serde::Deserialize;
use std::convert::Infallible;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_jwt::{JwtLayer, RequestClaim};

// Setup your claim with the fields you want to extract
#[derive(Clone, Deserialize, Debug)]
struct Claim {
    /// Subject (whom the token refers to)
    pub sub: String,

    /// Name of the claim owner
    pub name: String,

    #[serde(with = "chrono::serde::ts_seconds")]
    /// Issued at (timestamp)
    pub iat: DateTime<Utc>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let claim = req.extensions().get::<RequestClaim<Claim>>();

        if let Some(claim) = claim {
            // Use the claim here...
            assert_eq!(claim.claim.sub, "1234567890");
            assert_eq!(claim.claim.name, "John Doe");
            assert_eq!(
                claim.claim.iat,
                DateTime::parse_from_rfc3339("2018-01-18T01:30:00Z").unwrap()
            );

            Ok(Response::new(Body::empty()))
        } else {
            // Claim was not set so this request is unauthorized
            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .unwrap())
        }
    }

    let mut validation = Validation::default();
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    // Make a new JWT layer which will validate the tokens on requests
    let jwt_layer = JwtLayer::<Claim>::new(
        validation,
        DecodingKey::from_secret("symmetric secret".as_bytes()),
    );

    let mut service = ServiceBuilder::new().layer(jwt_layer).service_fn(handle);

    // Call the service without a claim
    let request = Request::builder().uri("/").body(Body::empty())?;

    let status = service.ready().await?.call(request).await?.status();

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "request did not have a token while endpoint expected one"
    );

    // Call the service with a claim
    let request = Request::builder()
        .uri("/")
        .header(AUTHORIZATION, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDAwfQ.CHiQ0VbodaR55aiN_0JJB7nWJBO__rt_7ur1WO-jZxg")
        .body(Body::empty())?;

    let status = service.ready().await?.call(request).await?.status();

    assert_eq!(
        status,
        StatusCode::OK,
        "request should extract the token correctly"
    );

    Ok(())
}
```

# Assymmetric example using Axum
```rust
use axum::{routing::get, Extension, Router};
use http::{Request, StatusCode};
use hyper::Body;
use jsonwebtoken::{DecodingKey, Validation};
use ring::{
    rand,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde::Deserialize;
use tower::ServiceExt;
use tower_jwt::{JwtLayer, RequestClaim};

// Setup your claim with the fields you want to extract
#[derive(Deserialize, Clone)]
pub struct Claim {
    /// Subject (whom token refers to).
    pub sub: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Make a asymmetric key pair
    // This will mostly be done outside of the code using like `openssl` to generate the key pair
    let doc = signature::Ed25519KeyPair::generate_pkcs8(&rand::SystemRandom::new()).unwrap();
    // let encoding_key = EncodingKey::from_ed_der(doc.as_ref());
    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let public_key = pair.public_key().as_ref().to_vec();
    let decoding_key = DecodingKey::from_ed_der(&public_key);

    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);

    // Only allow tokens from the test-issuer
    validation.set_issuer(&["test-issuer"]);

    let router = Router::new()
        .route(
            "/",
            get(|claim: Option<Extension<RequestClaim<Claim>>>| async move {
                if let Some(Extension(claim)) = claim {
                    (StatusCode::OK, format!("Hello, {}", claim.claim.sub))
                } else {
                    (StatusCode::UNAUTHORIZED, "Not authorized".to_string())
                }
            }),
        )
        .layer(JwtLayer::<Claim, _>::new(validation, move || {
            let decoding_key = decoding_key.clone();

            async {
                // In practice a network call will happen here to get the public key
                decoding_key
            }
        }));

    // Call the service without a claim
    let response = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}
```