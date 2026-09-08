use crate::{config, tcp, websocket, ResultType};
#[cfg(feature = "webrtc")]
use crate::webrtc;
use sodiumoxide::crypto::secretbox::Key;
use std::net::SocketAddr;
use tokio::net::TcpStream;

// support Websocket and tcp.
pub enum Stream {
    #[cfg(feature = "webrtc")]
    WebRTC(webrtc::WebRTCStream),
    WebSocket(websocket::WsFramedStream),
    Tcp(tcp::FramedStream),
}

impl Stream {
    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_send_timeout(ms),
            Stream::WebSocket(s) => s.set_send_timeout(ms),
            Stream::Tcp(s) => s.set_send_timeout(ms),
        }
    }

    #[inline]
    pub fn set_raw(&mut self) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_raw(),
            Stream::WebSocket(s) => s.set_raw(),
            Stream::Tcp(s) => s.set_raw(),
        }
    }

    /// The largest message the peer may send. Lowered before authorization, where nothing a peer
    /// legitimately sends is large, so an unauthenticated connection cannot make us hold more than
    /// that. Each transport clamps `n` to its own ceiling, so `usize::MAX` restores the default.
    ///
    /// Set it before the first read of untrusted data. Lowering it later is not a way to constrain
    /// a message already in progress: what that does to one is up to the transport.
    #[inline]
    pub fn set_max_packet_length(&mut self, n: usize) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_max_packet_length(n),
            Stream::WebSocket(s) => s.set_max_packet_length(n),
            Stream::Tcp(s) => s.codec_mut().set_max_packet_length(n),
        }
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: bytes::Bytes) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_bytes(bytes).await,
            Stream::WebSocket(s) => s.send_bytes(bytes).await,
            Stream::Tcp(s) => s.send_bytes(bytes).await,
        }
    }

    #[inline]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_raw(bytes).await,
            Stream::WebSocket(s) => s.send_raw(bytes).await,
            Stream::Tcp(s) => s.send_raw(bytes).await,
        }
    }

    #[inline]
    pub fn set_key(&mut self, key: Key) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_key(key),
            Stream::WebSocket(s) => s.set_key(key),
            Stream::Tcp(s) => s.set_key(key),
        }
    }

    /// An opaque token that changes whenever bytes have arrived from the peer, a fragment of a
    /// message that is still incomplete included. Compare successive samples; the value itself
    /// means nothing. `None` where the transport reports no such thing.
    ///
    /// A message reaches the caller only once it is whole, so `next()` alone cannot distinguish a
    /// peer sending a large one — a clipboard image is the case that occurs — from one that died
    /// mid-message. Sampling this alongside the last received message tells them apart.
    ///
    /// TCP and WebSocket answer `None` on purpose: this change leaves their existing close, error
    /// and 30s-timeout behaviour exactly as it was, and giving them a value would alter it.
    #[inline]
    pub fn rx_progress(&self) -> Option<u64> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => Some(s.rx_progress()),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Whether ICE has stopped hearing from the peer on a WebRTC transport. Transient and
    /// recoverable — it says the peer is worth suspecting, never that the session is over — and
    /// always false for transports this change leaves alone.
    ///
    /// Maintained by ICE's own task, so unlike anything derived from the session's read loop it
    /// stays accurate while that loop is busy sending.
    #[inline]
    pub fn webrtc_disconnected(&self) -> bool {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.is_disconnected(),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.is_secured(),
            Stream::WebSocket(s) => s.is_secured(),
            Stream::Tcp(s) => s.is_secured(),
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        timeout: u64,
    ) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.next_timeout(timeout).await,
            Stream::WebSocket(s) => s.next_timeout(timeout).await,
            Stream::Tcp(s) => s.next_timeout(timeout).await,
        }
    }

    /// establish connect from websocket
    #[inline]
    pub async fn connect_websocket(
        url: impl AsRef<str>,
        local_addr: Option<SocketAddr>,
        proxy_conf: Option<&config::Socks5Server>,
        timeout_ms: u64,
    ) -> ResultType<Self> {
        let ws_stream =
            websocket::WsFramedStream::new(url, local_addr, proxy_conf, timeout_ms).await?;
        log::debug!("WebSocket connection established");
        Ok(Self::WebSocket(ws_stream))
    }

    /// send message
    #[inline]
    pub async fn send(&mut self, msg: &impl protobuf::Message) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.send(msg).await,
            Self::WebSocket(ws) => ws.send(msg).await,
            Self::Tcp(tcp) => tcp.send(msg).await,
        }
    }

    /// receive message
    #[inline]
    pub async fn next(&mut self) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.next().await,
            Self::WebSocket(ws) => ws.next().await,
            Self::Tcp(tcp) => tcp.next().await,
        }
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.local_addr(),
            Self::WebSocket(ws) => ws.local_addr(),
            Self::Tcp(tcp) => tcp.local_addr(),
        }
    }

    #[inline]
    pub fn from(stream: TcpStream, stream_addr: SocketAddr) -> Self {
        Self::Tcp(tcp::FramedStream::from(stream, stream_addr))
    }

    #[inline]
    #[cfg(feature = "webrtc")]
    pub fn get_webrtc_stream(&self) -> Option<webrtc::WebRTCStream> {
        match self {
            Self::WebRTC(s) => Some(s.clone()),
            _ => None,
        }
    }
}
