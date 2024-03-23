Tower middleware to parse JWT tokens off the Authorization Bearer of requests and store the deserialized claims on the
request extension.

This is build on top of the [jsonwebtoken](https://docs.rs/jsonwebtoken) crate and support all the algorithms supported by that crate.

Since this is a Tower middleware it can be used on any framework like Axum, Tonic, etc.

# Example

``` rust
use http::{header::AUTHORIZATION, Request, Response, StatusCode};
use hyper::Body;
use jsonwebtoken::{DecodingKey, Validation};
use serde::Deserialize;
use std::convert::Infallible;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_jwt::{JwtLayer, RequestClaim};

#[derive(Clone, Deserialize, Debug)]
struct Claim {
    /// Subject (whom the token refers to).
    pub sub: String,

    /// Name of the claim owner
    pub name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let claim = req.extensions().get::<RequestClaim<Claim>>();

        if let Some(claim) = claim {
            // Use the claim here...
            assert_eq!(claim.claim.sub, "1234567890");
            assert_eq!(claim.claim.name, "John Doe");

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
        .header(AUTHORIZATION, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.nXfm1PNEPuIUrLlneiDd3LFcQ9ACxD3f97rfVu0xgdc")
        .body(Body::empty())?;

    let status = service.ready().await?.call(request).await?.status();

    assert_eq!(
        status,
        StatusCode::OK,
        "request did not have a token while endpoint expected one"
    );

    Ok(())
}
```
