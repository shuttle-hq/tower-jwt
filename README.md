Tower middleware to parse JWT tokens off the Authorization Bearer of requests and store the deserialized claims on the
request extension.

Since this is a Tower middleware it can be used on any framework like Axum, Tonic, etc.

# Example

``` rust
use http::{Request, Response, StatusCode};
use hyper::Body;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::{convert::Infallible, iter::once};
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_jwt::{JwtLayer, RequestClaim};

#[derive(Clone, Deserialize, Debug)]
struct Claim {
    /// Subject (whom token refers to).
    pub sub: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let claim = req.extensions().get::<RequestClaim<Claim>>();

        if let Some(claim) = claim {
            // Use the claim here...

            Ok(Response::new(Body::empty()))
        } else {
            // Claim was not set so this request is unauthorized
            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .unwrap())
        }
    }

    // Make a new JWT layer which will validate the token were issued by "issuer"
    let jwt_layer = JwtLayer::<Claim, _>::new("issuer", || {
        // Something to get the public key
        let public_key = Vec::new();
        let decoding_key = DecodingKey::from_ed_der(&public_key);

        async { decoding_key }
    });

    let mut service = ServiceBuilder::new().layer(jwt_layer).service_fn(handle);

    // call the service
    let request = Request::builder().uri("/").body(Body::empty())?;

    let status = service.ready().await?.call(request).await?.status();

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "request did not have a token while endpoint expected one"
    );

    Ok(())
}
```
