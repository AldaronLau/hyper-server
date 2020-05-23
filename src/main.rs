use std::convert::Infallible;
use std::net::SocketAddr;
use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use std::task::{Poll, Context};
use tokio::net::{TcpListener, TcpStream};
use futures_util::{
    stream::*,
};
use std::pin::Pin;

#[cfg(feature = "https")]
use tokio_rustls::{
    server::TlsStream,
    TlsAcceptor
};

#[cfg(feature = "https")]
use rustls::internal::pemfile;

async fn hello_world(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("Try POSTing data to /echo");
        },
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        },
        // Yet another route inside our match block...
        (&Method::POST, "/echo/uppercase") => {
            // This is actually a new `futures::Stream`...
            let mapping = req
                .into_body()
                .map_ok(|chunk| {
                    chunk.iter()
                        .map(|byte| byte.to_ascii_uppercase())
                        .collect::<Vec<u8>>()
                });

            // Use `Body::wrap_stream` to convert it to a `Body`...
            *response.body_mut() = Body::wrap_stream(mapping);
        },
        // Yet another route inside our match block...
        (&Method::POST, "/echo/reverse") => {
            // Await the full body to be concatenated into a single `Bytes`...
            let full_body = hyper::body::to_bytes(req.into_body()).await?;

            // Iterate the full body in reverse order and collect into a new Vec.
            let reversed = full_body.iter()
                .rev()
                .cloned()
                .collect::<Vec<u8>>();

            *response.body_mut() = reversed.into();
        },
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        },
    };

    Ok(response)
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    async_main().await
}

async fn async_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    // Create a TCP listener via tokio.
    let mut tcp = TcpListener::bind(&addr).await?;

        #[cfg(feature = "https")] let server = {
            // Build TLS configuration.
            let tls_cfg = {
                // Load public certificate.
                let certs = load_certs("sample.pem")?;
                // Load private key.
                let key = load_private_key("sample.rsa")?;
                // Do not use client certificate authentication.
                let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
                // Select a certificate to use.
                cfg.set_single_cert(certs, key).map_err(|e| Box::new(e))?;
                // Configure ALPN to accept HTTP/2, HTTP/1.1 in that order.
                cfg.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
                std::sync::Arc::new(cfg)
            };
            let tls_acceptor = TlsAcceptor::from(tls_cfg);
            let incoming_stream = tcp
                .incoming()
                .map_err(|e| panic!(format!("Incoming failed: {:?}", e)))
                .and_then(move |s| {
                    tls_acceptor.accept(s)
                })
                .boxed();
            Server::builder(HyperAcceptor {
                acceptor: Box::pin(incoming_stream),
            })
        };
        #[cfg(not(feature = "https"))]
        let server = {
            let incoming_stream = tcp.incoming();
            Server::builder(HyperAcceptor {
                acceptor: Box::pin(incoming_stream)
            })
        };

    let server = 
        server.serve(make_service_fn(|_conn| async {
            // service_fn converts our function into a `Service`
            Ok::<_, Infallible>(service_fn(hello_world))
        }));

    // And now add a graceful shutdown signal...
    let graceful = server.with_graceful_shutdown(shutdown_signal());

    // Run this server for... forever!
    if let Err(e) = graceful.await {
        eprintln!("server error: {}", e);
    }

    // Newline on quit.
    println!();

    Ok(())
}

#[cfg(not(feature = "https"))]
struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn Stream<Item = Result<TcpStream, std::io::Error>> + 'a>>,
}

#[cfg(not(feature = "https"))]
impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TcpStream;
    type Error = std::io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

#[cfg(feature = "https")]
struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn Stream<Item = Result<TlsStream<TcpStream>, std::io::Error>> + 'a>>,
}

#[cfg(feature = "https")]
impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TlsStream<TcpStream>;
    type Error = std::io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

#[cfg(feature = "https")]
// Load public certificate from file.
fn load_certs(filename: &str) -> std::io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = std::fs::File::open(filename).unwrap();
    let mut reader = std::io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_| panic!("failed to load certificate"))
}

#[cfg(feature = "https")]
// Load private key from file.
fn load_private_key(filename: &str) -> std::io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = std::fs::File::open(filename).unwrap();
    let mut reader = std::io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::rsa_private_keys(&mut reader).unwrap();
    if keys.len() != 1 {
        panic!("expected a single private key");
    }
    Ok(keys[0].clone())
}
