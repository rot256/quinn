use rustls::quic::{ClientQuicExt, ServerQuicExt};
use rustls::{KeyLogFile, NoClientAuth, ProtocolVersion, TLSError};

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use super::{QuicError, QuicResult};
use codec::Codec;
use crypto::Secret;
use parameters::{ClientTransportParameters, ServerTransportParameters};
use types::Side;

use std::collections;
use rustls;

use webpki::{DNSNameRef, TLSServerTrustAnchors};
use webpki_roots;

pub use rustls::{SupportedCipherSuite};
pub use rustls::{Certificate, PrivateKey};
pub use rustls::{ClientSessionValue, ServerSessionValue};
pub use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Session};

static SUITE : usize = 1;

pub struct SingleCacheClient {
    value : Mutex<Vec<u8>>
}

mod danger {
    use rustls;
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(&self,
                              _roots: &rustls::RootCertStore,
                              _presented_certs: &[rustls::Certificate],
                              _dns_name: webpki::DNSNameRef,
                              _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

impl SingleCacheClient {
    fn new() -> Arc<SingleCacheClient> {
        Arc::new(SingleCacheClient {
            value: Mutex::new(vec![]),
        })
    }
}

struct ClientSessionMemoryCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    max_entries: usize,
}

impl ClientSessionMemoryCache {
    /// Make a new ClientSessionMemoryCache.  `size` is the maximum
    /// number of stored sessions.
    pub fn new(size: usize) -> Arc<ClientSessionMemoryCache> {
        debug_assert!(size > 0);
        Arc::new(ClientSessionMemoryCache {
            cache: Mutex::new(collections::HashMap::new()),
            max_entries: size,
        })
    }

    fn limit_size(&self) {
        let mut cache = self.cache.lock().unwrap();
        println!("ClientSessionMemoryCache, size: {}", cache.len());
        while cache.len() > self.max_entries {
            let k = cache.keys().next().unwrap().clone();
            cache.remove(&k);
        }
    }
}

impl rustls::StoresClientSessions for ClientSessionMemoryCache {

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        println!("ClientSessionMemoryCache, put: {:?}", key.clone());
        self.cache.lock()
            .unwrap()
            .insert(key, value);
        self.limit_size();
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        println!("ClientSessionMemoryCache, get: {:?}", key.clone());
        let res = self.cache.lock()
            .unwrap()
            .get(key).cloned();
        res
    }
}


impl rustls::StoresClientSessions for SingleCacheClient {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        println!("SingleCacheClient, store: {:?} -> {:?}", key, &value);
        let mut guard = self.value.lock().unwrap();
        *guard = value;
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let guard = self.value.lock().unwrap();
        println!("SingleCacheClient, fetch: {:?} -> {:?}", key, guard.clone());
        Some(guard.clone())
    }
}

pub fn client_session(
    config: Option<Arc<ClientConfig>>,
    hostname: &str,
    params: &ClientTransportParameters,
) -> QuicResult<ClientSession> {
    let pki_server_name = DNSNameRef::try_from_ascii_str(hostname)
        .map_err(|_| QuicError::InvalidDnsName(hostname.into()))?;
    Ok(ClientSession::new_quic(
        &config.unwrap_or_else(|| build_client_config(None)),
        pki_server_name,
        to_vec(params),
    ))
}

pub fn build_client_config(anchors: Option<&TLSServerTrustAnchors>) -> Arc<ClientConfig> {
    let mut config = ClientConfig::new();
    let anchors = anchors.unwrap_or(&webpki_roots::TLS_SERVER_ROOTS);
    config.root_store.add_server_trust_anchors(anchors);
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.alpn_protocols = vec![ALPN_PROTOCOL.into()];
    config.key_log = Arc::new(KeyLogFile::new());
    Arc::new(config)
}

pub fn build_client_config_psk() -> Arc<ClientConfig> {
    let mut config = ClientConfig::new();
    config.key_log = Arc::new(KeyLogFile::new());
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.alpn_protocols = vec![ALPN_PROTOCOL.into()];
    // config.ciphersuites = vec![rustls::ALL_CIPHERSUITES[SUITE]];
    config.dangerous().set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    config.set_persistence(ClientSessionMemoryCache::new(256));
    Arc::new(config)
}

pub fn server_session(
    config: &Arc<ServerConfig>,
    params: &ServerTransportParameters,
) -> ServerSession {
    ServerSession::new_quic(config, to_vec(params))
}

pub fn build_server_config(
    cert_chain: Vec<Certificate>,
    key: PrivateKey,
) -> QuicResult<Arc<ServerConfig>> {
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.key_log = Arc::new(KeyLogFile::new());
    config.set_protocols(&[ALPN_PROTOCOL.into()]);
    config.set_single_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

pub fn build_server_config_psk(
    cert_chain: Vec<Certificate>,
    key: PrivateKey,
) -> QuicResult<Arc<ServerConfig>> {
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.key_log = Arc::new(KeyLogFile::new());
    // config.ciphersuites = vec![rustls::ALL_CIPHERSUITES[SUITE]];
    config.set_persistence(rustls::ServerSessionMemoryCache::new(256));
    config.set_protocols(&[ALPN_PROTOCOL.into()]);
    config.set_single_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

pub fn process_handshake_messages<T>(session: &mut T, msgs: Option<&[u8]>) -> QuicResult<TlsResult>
where
    T: Session,
{
    if let Some(data) = msgs {
        let mut read = Cursor::new(data);
        let did_read = session.read_tls(&mut read)?;
        debug_assert_eq!(did_read, data.len());
        session.process_new_packets()?;
    }

    let key_ready = if !session.is_handshaking() {
        Some(session
            .get_negotiated_ciphersuite()
            .ok_or(TLSError::HandshakeNotComplete)?)
    } else {
        None
    };

    let mut messages = Vec::new();
    loop {
        let size = session.write_tls(&mut messages)?;
        if size == 0 {
            break;
        }
    }

    let secret = if let Some(suite) = key_ready {
        let mut client_secret = vec![0u8; suite.enc_key_len];
        session.export_keying_material(&mut client_secret, b"EXPORTER-QUIC client 1rtt", None)?;
        let mut server_secret = vec![0u8; suite.enc_key_len];
        session.export_keying_material(&mut server_secret, b"EXPORTER-QUIC server 1rtt", None)?;

        let (aead_alg, hash_alg) = (suite.get_aead_alg(), suite.get_hash());
        Some(Secret::For1Rtt(
            aead_alg,
            hash_alg,
            client_secret,
            server_secret,
        ))
    } else {
        None
    };

    Ok((messages, secret))
}

pub trait QuicSide {
    fn side(&self) -> Side;
}

impl QuicSide for ClientSession {
    fn side(&self) -> Side {
        Side::Client
    }
}

impl QuicSide for ServerSession {
    fn side(&self) -> Side {
        Side::Server
    }
}

type TlsResult = (Vec<u8>, Option<Secret>);

fn to_vec<T: Codec>(val: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    val.encode(&mut bytes);
    bytes
}

const ALPN_PROTOCOL: &str = "hq-11";

#[cfg(test)]
pub(crate) mod tests {
    extern crate untrusted;
    use self::untrusted::Input;
    use rustls::internal::pemfile;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use webpki;

    pub fn client_config() -> super::ClientConfig {
        let mut f = File::open("certs/ca.der").expect("cannot open 'certs/ca.der'");
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).expect("error while reading");

        let anchor =
            webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::from(&bytes)).unwrap();
        let anchor_vec = vec![anchor];
        super::build_client_config(Some(&webpki::TLSServerTrustAnchors(&anchor_vec)))
    }

    pub fn server_config() -> super::ServerConfig {
        let certs = {
            let f = File::open("certs/server.chain").expect("cannot open 'certs/server.chain'");
            let mut reader = BufReader::new(f);
            pemfile::certs(&mut reader).expect("cannot read certificates")
        };

        let keys = {
            let f = File::open("certs/server.rsa").expect("cannot open 'certs/server.rsa'");
            let mut reader = BufReader::new(f);
            pemfile::rsa_private_keys(&mut reader).expect("cannot read private keys")
        };

        super::build_server_config(certs, keys[0].clone()).unwrap()
    }
}
