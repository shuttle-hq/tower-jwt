#![doc = include_str!("../README.md")]

use std::{convert::Infallible, future::Future, marker::PhantomData, pin::Pin, task::Poll};

use async_trait::async_trait;
use headers::{authorization::Bearer, Authorization, HeaderMapExt};
use http::{Request, Response, StatusCode};
use jsonwebtoken::{decode, DecodingKey, Validation};
use pin_project::pin_project;
use serde::Deserialize;
use tower::{Layer, Service};
use tracing::{error, trace};

/// Trait to get a public key asynchronously
#[async_trait]
pub trait PublicKeyFn: Send + Sync + Clone {
    type Error: std::error::Error + Send;

    async fn public_key(&self) -> Result<Vec<u8>, Self::Error>;
}

#[async_trait]
impl<F, O> PublicKeyFn for F
where
    F: Fn() -> O + Sync + Send + Clone,
    O: Future<Output = Vec<u8>> + Send,
{
    type Error = Infallible;

    async fn public_key(&self) -> Result<Vec<u8>, Self::Error> {
        Ok((self)().await)
    }
}

/// Layer to validate JWT tokens with a public key. Valid claims are added to the request extension
///
/// It can also be used with tonic. See:
/// https://github.com/hyperium/tonic/blob/master/examples/src/tower/server.rs
#[derive(Clone)]
pub struct JwtLayer<Claim, F> {
    /// User provided function to get the public key from
    public_key_fn: F,
    /// A valid issuer for the token
    issuer: String,
    _phantom: PhantomData<Claim>,
}

impl<Claim, F: PublicKeyFn> JwtLayer<Claim, F> {
    /// Create a new layer to validate JWT tokens with the given public key
    /// Tokens will only be accepted if the issuer matches the given issuer
    pub fn new(issuer: &str, public_key_fn: F) -> Self {
        Self {
            public_key_fn,
            issuer: issuer.to_string(),
            _phantom: PhantomData,
        }
    }
}

impl<S, Claim, F: PublicKeyFn> Layer<S> for JwtLayer<Claim, F> {
    type Service = Jwt<S, Claim, F>;

    fn layer(&self, inner: S) -> Self::Service {
        Jwt {
            inner,
            public_key_fn: self.public_key_fn.clone(),
            issuer: self.issuer.clone(),
            _phantom: self._phantom,
        }
    }
}

/// Middleware for validating a valid JWT token is present on "authorization: bearer <token>"
#[derive(Clone)]
pub struct Jwt<S, Claim, F> {
    inner: S,
    public_key_fn: F,
    issuer: String,
    _phantom: PhantomData<Claim>,
}

type AsyncTraitFuture<A> = Pin<Box<dyn Future<Output = A> + Send>>;

#[pin_project(project = JwtFutureProj, project_replace = JwtFutureProjOwn)]
pub enum JwtFuture<
    PubKeyFn: PublicKeyFn,
    TService: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody,
    ResBody,
    Claim,
> {
    // If there was an error return a BAD_REQUEST.
    Error,

    // We are ready to call the inner service.
    WaitForFuture {
        #[pin]
        future: TService::Future,
    },

    // We have a token and need to run our logic.
    HasTokenWaitingForPublicKey {
        bearer: Authorization<Bearer>,
        request: Request<ReqBody>,
        #[pin]
        public_key_future: AsyncTraitFuture<Result<Vec<u8>, PubKeyFn::Error>>,
        issuer: String,
        service: TService,
        _phantom: PhantomData<Claim>,
    },
}

impl<PubKeyFn, TService, ReqBody, ResBody, Claim> Future
    for JwtFuture<PubKeyFn, TService, ReqBody, ResBody, Claim>
where
    PubKeyFn: PublicKeyFn + 'static,
    TService: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
    for<'de> Claim: Deserialize<'de> + Send + Sync + 'static,
{
    type Output = Result<TService::Response, TService::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().project() {
            JwtFutureProj::Error => {
                let response = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Default::default())
                    .unwrap();
                Poll::Ready(Ok(response))
            }
            JwtFutureProj::WaitForFuture { future } => future.poll(cx),
            JwtFutureProj::HasTokenWaitingForPublicKey {
                bearer,
                public_key_future,
                issuer,
                ..
            } => {
                match public_key_future.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        error!(
                            error = &error as &dyn std::error::Error,
                            "failed to get public key from auth service"
                        );
                        let response = Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .body(Default::default())
                            .unwrap();

                        Poll::Ready(Ok(response))
                    }
                    Poll::Ready(Ok(public_key)) => {
                        let claim_result = RequestClaim::<Claim>::from_token(
                            bearer.token().trim(),
                            &issuer,
                            &public_key,
                        );
                        match claim_result {
                            Err(code) => {
                                error!(code = %code, "failed to decode JWT");

                                let response = Response::builder()
                                    .status(code)
                                    .body(Default::default())
                                    .unwrap();

                                Poll::Ready(Ok(response))
                            }
                            Ok(claim) => {
                                let owned = self.as_mut().project_replace(JwtFuture::Error);
                                match owned {
                                    JwtFutureProjOwn::HasTokenWaitingForPublicKey {
                                        mut request, mut service, ..
                                    } => {
                                        request.extensions_mut().insert(claim);
                                        let future = service.call(request);
                                        self.as_mut().set(JwtFuture::WaitForFuture { future });
                                        self.poll(cx)
                                    },
                                    _ => unreachable!("We know that we're in the 'HasTokenWaitingForPublicKey' state"),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S, ReqBody, ResBody, Claim, F> Service<Request<ReqBody>> for Jwt<S, Claim, F>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    ResBody: Default,
    F: PublicKeyFn + 'static,
    <F as PublicKeyFn>::Error: 'static,
    for<'de> Claim: Deserialize<'de> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = JwtFuture<F, S, ReqBody, ResBody, Claim>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        match req.headers().typed_try_get::<Authorization<Bearer>>() {
            Ok(Some(bearer)) => {
                let public_key_fn = self.public_key_fn.clone();
                let public_key_future = Box::pin(async move { public_key_fn.public_key().await });
                Self::Future::HasTokenWaitingForPublicKey {
                    bearer,
                    request: req,
                    public_key_future,
                    issuer: self.issuer.clone(),
                    service: self.inner.clone(),
                    _phantom: self._phantom,
                }
            }
            Ok(None) => {
                let future = self.inner.call(req);

                Self::Future::WaitForFuture { future }
            }
            Err(_) => Self::Future::Error,
        }
    }
}

/// Used to hold the validated claim from the JWT token
#[derive(Clone, Debug)]
pub struct RequestClaim<T>
where
    for<'de> T: Deserialize<'de>,
{
    /// The claim from the token
    pub claim: T,

    /// The original token that was parsed
    pub token: String,
}

impl<T> RequestClaim<T>
where
    for<'de> T: Deserialize<'de>,
{
    pub fn from_token(token: &str, issuer: &str, public_key: &[u8]) -> Result<Self, StatusCode> {
        let decoding_key = DecodingKey::from_ed_der(public_key);
        let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);

        trace!("converting token to claim");
        let claim: T = decode(token, &decoding_key, &validation)
            .map_err(|err| {
                error!(
                    error = &err as &dyn std::error::Error,
                    "failed to convert token to claim"
                );
                match err.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        StatusCode::from_u16(499).unwrap() // Expired status code which is safe to unwrap
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature
                    | jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName
                    | jsonwebtoken::errors::ErrorKind::InvalidIssuer
                    | jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
                        StatusCode::UNAUTHORIZED
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidToken
                    | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                    | jsonwebtoken::errors::ErrorKind::Base64(_)
                    | jsonwebtoken::errors::ErrorKind::Json(_)
                    | jsonwebtoken::errors::ErrorKind::Utf8(_) => StatusCode::BAD_REQUEST,
                    jsonwebtoken::errors::ErrorKind::MissingAlgorithm => {
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                    jsonwebtoken::errors::ErrorKind::Crypto(_) => StatusCode::SERVICE_UNAVAILABLE,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                }
            })?
            .claims;

        Ok(Self {
            claim,
            token: token.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::{routing::get, Extension, Router};
    use chrono::{Duration, Utc};
    use hyper::{body, Body};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use ring::{
        rand,
        signature::{self, Ed25519KeyPair, KeyPair},
    };
    use serde::Serialize;
    use std::ops::Add;
    use tower::ServiceExt;

    use super::*;

    #[derive(Deserialize, Clone, Serialize)]
    pub struct Claim {
        /// Expiration time (as UTC timestamp).
        pub exp: usize,
        /// Issued at (as UTC timestamp).
        iat: usize,
        /// Issuer.
        iss: String,
        /// Not Before (as UTC timestamp).
        nbf: usize,
        /// Subject (whom token refers to).
        pub sub: String,
        /// The original token that was parsed
        pub token: Option<String>,
    }

    impl Claim {
        /// Create a new claim for a user with the given scopes and limits.
        pub fn new(sub: String) -> Self {
            let iat = Utc::now();
            let exp = iat.add(Duration::try_minutes(5).unwrap());

            Self {
                exp: exp.timestamp() as usize,
                iat: iat.timestamp() as usize,
                iss: "test-issuer".to_string(),
                nbf: iat.timestamp() as usize,
                sub,
                token: None,
            }
        }

        pub fn into_token(self, encoding_key: &EncodingKey) -> Result<String, StatusCode> {
            if let Some(token) = self.token {
                Ok(token)
            } else {
                encode(
                    &Header::new(jsonwebtoken::Algorithm::EdDSA),
                    &self,
                    encoding_key,
                )
                .map_err(|err| {
                    error!(
                        error = &err as &dyn std::error::Error,
                        "failed to convert claim to token"
                    );
                    match err.kind() {
                        jsonwebtoken::errors::ErrorKind::Json(_) => {
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                        jsonwebtoken::errors::ErrorKind::Crypto(_) => {
                            StatusCode::SERVICE_UNAVAILABLE
                        }
                        _ => StatusCode::INTERNAL_SERVER_ERROR,
                    }
                })
            }
        }
    }

    #[tokio::test]
    async fn authorization_layer() {
        let claim = Claim::new("ferries".to_string());

        let doc = signature::Ed25519KeyPair::generate_pkcs8(&rand::SystemRandom::new()).unwrap();
        let encoding_key = EncodingKey::from_ed_der(doc.as_ref());
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let public_key = pair.public_key().as_ref().to_vec();

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
            .layer(JwtLayer::<Claim, _>::new("test-issuer", move || {
                let public_key = public_key.clone();
                async move { public_key.clone() }
            }));

        //////////////////////////////////////////////////////////////////////////
        // Test token missing
        //////////////////////////////////////////////////////////////////////////
        let response = router
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        //////////////////////////////////////////////////////////////////////////
        // Test bearer missing
        //////////////////////////////////////////////////////////////////////////
        let token = claim.clone().into_token(&encoding_key).unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("authorization", token.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        //////////////////////////////////////////////////////////////////////////
        // Test valid
        //////////////////////////////////////////////////////////////////////////
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        //////////////////////////////////////////////////////////////////////////
        // Test valid extra padding
        //////////////////////////////////////////////////////////////////////////
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Authorization", format!("Bearer   {token}   "))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body()).await.unwrap();

        assert_eq!(&body[..], b"Hello, ferries");
    }
}
