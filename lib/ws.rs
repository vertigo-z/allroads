use crate::transport::SyncMessage;
use futures::{SinkExt, StreamExt};
use serde::Serialize;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream,
};
use tokio_rustls::TlsAcceptor;

enum WsStream {
    Client(WebSocketStream<MaybeTlsStream<TcpStream>>),
    PlainServer(WebSocketStream<TcpStream>),
    TlsServer(WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>),
}

pub struct WebSocketTransport {
    stream: WsStream,
    peer: SocketAddr,
}

impl WebSocketTransport {
    pub async fn connect(url: &str) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        let (stream, _resp) = connect_async(url).await?;
        let peer = peer_addr(stream.get_ref());
        Ok(Self { stream: WsStream::Client(stream), peer })
    }

    pub async fn connect_with_stream(
        url: &str,
        stream: TcpStream,
    ) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        let peer = stream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let (stream, _resp) = tokio_tungstenite::client_async(url, MaybeTlsStream::Plain(stream)).await?;
        Ok(Self { stream: WsStream::Client(stream), peer })
    }

    pub async fn accept(listener: &TcpListener) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        let (tcp, _) = listener.accept().await?;
        let peer = tcp
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let stream = accept_async(tcp).await?;
        Ok(Self { stream: WsStream::PlainServer(stream), peer })
    }

    pub async fn accept_tls(
        listener: &TcpListener,
        acceptor: &TlsAcceptor,
    ) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        let (tcp, _) = listener.accept().await?;
        let peer = tcp
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let tls_stream = acceptor
            .accept(tcp)
            .await
            .map_err(tokio_tungstenite::tungstenite::Error::Io)?;
        let stream = accept_async(tls_stream).await?;
        Ok(Self { stream: WsStream::TlsServer(stream), peer })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub async fn send_msg(&mut self, msg: &SyncMessage) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        let text = serde_json::to_string(msg).unwrap_or_else(|_| "{}".to_string());
        match &mut self.stream {
            WsStream::Client(stream) => stream.send(Message::Text(text.clone())).await?,
            WsStream::PlainServer(stream) => stream.send(Message::Text(text.clone())).await?,
            WsStream::TlsServer(stream) => stream.send(Message::Text(text)).await?,
        }
        Ok(())
    }

    pub async fn send_json<T: Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        let text = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
        match &mut self.stream {
            WsStream::Client(stream) => stream.send(Message::Text(text.clone())).await?,
            WsStream::PlainServer(stream) => stream.send(Message::Text(text.clone())).await?,
            WsStream::TlsServer(stream) => stream.send(Message::Text(text)).await?,
        }
        Ok(())
    }

    pub async fn next_text_limit(&mut self, max_bytes: usize) -> Result<Option<String>, String> {
        loop {
            let item = match &mut self.stream {
                WsStream::Client(stream) => stream.next().await,
                WsStream::PlainServer(stream) => stream.next().await,
                WsStream::TlsServer(stream) => stream.next().await,
            };
            let Some(item) = item else { break; };
            if let Ok(message) = item {
                if let Ok(text) = message.into_text() {
                    if text.len() > max_bytes {
                        return Err("message too large".to_string());
                    }
                    return Ok(Some(text));
                }
            }
        }
        Ok(None)
    }
}

fn peer_addr(stream: &MaybeTlsStream<TcpStream>) -> SocketAddr {
    match stream {
        MaybeTlsStream::Plain(tcp) => tcp.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        _ => "0.0.0.0:0".parse().unwrap(),
    }
}
