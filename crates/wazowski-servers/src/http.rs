//! HTTP file server (serves a directory, read-only).

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_http::services::ServeDir;

use crate::{Log, Ready, ServerConfig};

pub(crate) async fn serve(
    cfg: &ServerConfig,
    shutdown: oneshot::Receiver<()>,
    log: Log,
    ready: &Ready,
) -> Result<()> {
    let addr = SocketAddr::new(cfg.bind, cfg.port);
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            let _ = ready.send(Err(crate::bind_error(&e, cfg.port, addr)));
            return Ok(());
        }
    };
    let local = listener.local_addr().context("local_addr")?;
    let _ = ready.send(Ok(format!("http://{local}")));
    log.line(format!("HTTP serving {} on http://{local}", cfg.root.display()));

    let request_log = log.clone();
    let app = Router::new()
        .fallback_service(ServeDir::new(&cfg.root))
        .layer(axum::middleware::from_fn(move |req: Request, next: Next| {
            let log = request_log.clone();
            async move {
                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let response: Response = next.run(req).await;
                log.line(format!("{method} {path} -> {}", response.status().as_u16()));
                response
            }
        }));

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.await;
        })
        .await
        .context("http server error")
}
