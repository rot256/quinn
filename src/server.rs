use futures::{Async, AsyncSink, Future, Poll, Sink, Stream, sync::mpsc::{self, Receiver, Sender}};

use super::{QuicError, QuicResult};
use conn_state::ConnectionState;
use crypto::Secret;
use packet::{LongType, Packet};
use parameters::ServerTransportParameters;
use tls;
use types::ConnectionId;

use std::collections::{HashMap, hash_map::Entry};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::{self, net::UdpSocket};

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<tls::ServerConfig>,
    in_buf: Vec<u8>,
    connections: HashMap<ConnectionId, Sender<Vec<u8>>>,
    send_queue: (
        Sender<(SocketAddr, Vec<u8>)>,
        Receiver<(SocketAddr, Vec<u8>)>,
    ),
    hs_to_dst: HashMap<ConnectionId, ConnectionId>,
    dst_to_hs: HashMap<ConnectionId, ConnectionId>,
}

impl Server {
    pub fn new(ip: &str, port: u16, tls_config: tls::ServerConfig) -> QuicResult<Self> {
        let addr = (ip, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| QuicError::General("no address found for host".into()))?;
        Ok(Server {
            socket: UdpSocket::bind(&addr)?,
            tls_config: Arc::new(tls_config),
            in_buf: vec![0u8; 65536],
            connections: HashMap::new(),
            send_queue: mpsc::channel(5),
            hs_to_dst: HashMap::new(),
            dst_to_hs: HashMap::new(),
        })
    }

    pub fn run(&mut self) -> QuicResult<()> {
        self.wait()
    }

    fn received(&mut self, addr: SocketAddr, len: usize) -> QuicResult<()> {
        let connections = &mut self.connections;
        let packet = &mut self.in_buf[..len];

        let (dst_cid, ptype) = {
            let partial = Packet::start_decode(packet)?;
            debug!("incoming packet: {:?} {:?}", addr, partial.header);
            (partial.dst_cid(), partial.header.ptype())
        };

        let cid = if ptype == None {
            dst_cid
        } else if ptype != Some(LongType::Initial) {
            match self.dst_to_hs.remove(&dst_cid) {
                Some(hs_cid) => {
                    self.hs_to_dst.remove(&hs_cid);
                }
                None => {}
            }
            dst_cid
        } else {
            match self.hs_to_dst.get(&dst_cid) {
                Some(cid) => cid.clone(),
                None => {
                    let mut state = ConnectionState::new(
                        tls::server_session(
                            &self.tls_config,
                            &ServerTransportParameters::default(),
                        ),
                        Some(Secret::Handshake(dst_cid)),
                    );

                    let cid =
                        state.pick_unused_cid(|cid| connections.contains_key(&cid));
                    let (recv_tx, recv_rx) = mpsc::channel(5);
                    tokio::executor::current_thread::spawn(
                        Box::new(Connection::new(
                            addr,
                            state,
                            self.send_queue.0.clone(),
                            recv_rx,
                        )).map_err(|e| {
                            error!("error spawning connection: {:?}", e);
                        }),
                    );
                    connections.insert(cid, recv_tx);
                    cid
                }
            }
        };

        match connections.entry(cid) {
            Entry::Occupied(mut inner) => {
                let mut sink = inner.get_mut();
                forward_packet(sink, packet.to_vec())?;
            }
            Entry::Vacant(_) => debug!("connection ID {:?} unknown", cid),
        }

        Ok(())
    }

    fn poll_next(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        match self.send_queue.1.poll() {
            Ok(Async::Ready(msg)) => msg,
            Ok(Async::NotReady) => None,
            Err(e) => {
                error!("error polling send queue: {:?}", e);
                None
            }
        }
    }
}

impl Future for Server {
    type Item = ();
    type Error = QuicError;

    fn poll(&mut self) -> Poll<(), QuicError> {
        let mut waiting;
        loop {
            waiting = true;
            match self.socket.poll_recv_from(&mut self.in_buf) {
                Ok(Async::Ready((len, addr))) => {
                    waiting = false;
                    self.received(addr, len)?;
                }
                Ok(Async::NotReady) => {}
                Err(e) => error!("Server RECV ERROR: {:?}", e),
            }

            if let Some((addr, msg)) = self.poll_next() {
                waiting = false;
                match self.socket.poll_send_to(&msg, &addr) {
                    Ok(Async::Ready(_)) => {}
                    Ok(Async::NotReady) => {}
                    Err(e) => error!("Server poll_send_to ERROR {:?}", e),
                }
            }

            if waiting {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}

fn forward_packet(sink: &mut Sender<Vec<u8>>, msg: Vec<u8>) -> QuicResult<()> {
    match sink.start_send(msg) {
        Ok(AsyncSink::Ready) => {}
        Ok(AsyncSink::NotReady(msg)) => error!("discarding message: {:?}", msg),
        Err(e) => {
            return Err(QuicError::General(format!(
                "error while starting channel send: {:?}",
                e
            )));
        }
    }
    match sink.poll_complete() {
        Ok(Async::Ready(())) => {}
        Ok(Async::NotReady) => {}
        Err(e) => {
            return Err(QuicError::General(format!(
                "error while polling channel complete: {:?}",
                e
            )));
        }
    }
    Ok(())
}

struct Connection {
    addr: SocketAddr,
    state: ConnectionState<tls::ServerSession>,
    send: Sender<(SocketAddr, Vec<u8>)>,
    recv: Receiver<Vec<u8>>,
}

impl Connection {
    fn new(
        addr: SocketAddr,
        state: ConnectionState<tls::ServerSession>,
        send: Sender<(SocketAddr, Vec<u8>)>,
        recv: Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            addr,
            state,
            send,
            recv,
        }
    }
}

impl Future for Connection {
    type Item = ();
    type Error = ();
    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            let mut received = false;
            match self.recv.poll() {
                Ok(Async::Ready(Some(ref mut msg))) => {
                    self.state.handle(msg).unwrap();
                    received = true;
                }
                Ok(Async::Ready(None)) => {}
                Ok(Async::NotReady) => {}
                Err(e) => error!("error from server: {:?}", e),
            }

            let mut sent = false;
            match self.state.queued() {
                Ok(Some(msg)) => match self.send.start_send((self.addr.clone(), msg.clone())) {
                    Ok(AsyncSink::Ready) => {
                        sent = true;
                    }
                    Ok(AsyncSink::NotReady(msg)) => {
                        error!("start send not ready: {:?}", msg);
                    }
                    Err(e) => error!("error sending: {:?}", e),
                },
                Ok(None) => {}
                Err(e) => error!("error from connection state: {:?}", e),
            }
            if sent {
                self.state.pop_queue();
            }

            let flushed = false;
            match self.send.poll_complete() {
                Ok(Async::Ready(())) => {}
                Ok(Async::NotReady) => {}
                Err(e) => error!("error from flushing sender: {:?}", e),
            }

            if !(received || sent || flushed) {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use super::Server;
    use conn_state::tests::client_conn_state;
    use tls::tests::server_config;
    use std::net::SocketAddr;

    #[test]
    fn test_multi_initials() {
        let mut server = Server::new("127.0.0.1", 4434, server_config()).unwrap();
        let mut exec = CurrentThread::new();
        exec.spawn(server.map_err(|_| ()));
        let mut c = client_conn_state();
        c.initial().unwrap();
        let mut initial = c.queued().unwrap().unwrap().clone();
        c.pop_queue();

        let client_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        server.in_buf[..initial.len()].copy_from_slice(&initial);
        server.received(client_addr, initial.len());
        server.received(client_addr, initial.len());

        let next = server.poll_next();
        let next = server.poll_next();
        let next = server.poll_next();
    }
}
