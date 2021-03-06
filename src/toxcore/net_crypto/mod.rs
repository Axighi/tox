/*! Net crypto module allows to send data between two friends and provides
encryption, ordered delivery, and perfect forward secrecy.

It can use both UDP and TCP (over relays) transport protocols to send data and
can switch between them without the peers needing to disconnect and reconnect.
For example two Tox friends might first connect over TCP and a few seconds later
switch to UDP when a direct UDP connection becomes possible. Direct UDP is
preferred over TCP because it is direct and isn't limited by possibly congested
TCP relays.

*/

mod crypto_connection;
mod packets_array;
pub mod errors;

pub use self::crypto_connection::*;
use self::packets_array::*;
use self::errors::*;

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::u16;

use failure::Fail;
use futures::{Future, Stream};
use futures::future;
use futures::future::Either;
use futures::sync::mpsc;
use parking_lot::RwLock;
use tokio::timer::Interval;
use tokio::timer::timeout::Error as TimeoutError;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;
use crate::toxcore::dht::precomputed_cache::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::time::*;

/// Maximum size of `Packet` when we try to send it to UDP address even if
/// it's considered dead.
const DHT_ATTEMPT_MAX_PACKET_LENGTH: usize = 95;

/// If diff between `Nonce` from received data packet and connection `Nonce` is
/// bigger than 2 * `NONCE_DIFF_THRESHOLD` then increase connection `Nonce` by
/// `NONCE_DIFF_THRESHOLD`.
const NONCE_DIFF_THRESHOLD: u16 = u16::MAX / 3;

/// Packet with this ID contains indices of lossless packets that should be
/// resent.
const PACKET_ID_REQUEST: u8 = 1;

/// Packet with this ID means that this crypto connection should be killed.
const PACKET_ID_KILL: u8 = 2;

/// Packets with ID from 0 to `PACKET_ID_CRYPTO_RANGE_END` are reserved for
/// `net_crypto`.
const PACKET_ID_CRYPTO_RANGE_END: u8 = 15;

/// Packets with ID from `PACKET_ID_LOSSY_RANGE_START` to
/// `PACKET_ID_LOSSY_RANGE_END` are considered lossy packets.
const PACKET_ID_LOSSY_RANGE_START: u8 = 192;

/// Packets with ID from `PACKET_ID_LOSSY_RANGE_START` to
/// `PACKET_ID_LOSSY_RANGE_END` are considered lossy packets.
const PACKET_ID_LOSSY_RANGE_END: u8 = 254;

/// Timeout for packet sending
const NET_CRYPTO_SEND_TIMEOUT: Duration = Duration::from_millis(50);

/// Shorthand for the transmit half of the message channel for sending DHT
/// packets.
type UdpTx = mpsc::Sender<(Packet, SocketAddr)>;

/// Shorthand for the transmit half of the message channel for sending DHT
/// `PublicKey` when it gets known. The first key is a long term key, the second
/// key is a DHT key.
type DhtPkTx = mpsc::UnboundedSender<(PublicKey, PublicKey)>;

/// Shorthand for the transmit half of the message channel for sending lossless
/// packets. The key is a long term public key of the peer that sent this
/// packet.
type LosslessTx = mpsc::UnboundedSender<(PublicKey, Vec<u8>)>;

/// Shorthand for the transmit half of the message channel for sending lossy
/// packets. The key is a long term public key of the peer that sent this
/// packet.
type LossyTx = mpsc::UnboundedSender<(PublicKey, Vec<u8>)>;

/// Arguments for creating new `NetCrypto`.
#[derive(Clone)]
pub struct NetCryptoNewArgs {
    /// Sink to send packet to UDP socket
    pub udp_tx: UdpTx,
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key. `NetCrypto` module can learn DHT
    /// `PublicKey` of peer from `Cookie` obtained from `CryptoHandshake`
    /// packet. If key from `Cookie` is not equal to saved key inside
    /// `CryptoConnection` then `NetCrypto` module will send message to this
    /// sink.
    pub dht_pk_tx: DhtPkTx,
    /// Sink to send lossless packets. The key is a long term public key of the
    /// peer that sent this packet.
    pub lossless_tx: LosslessTx,
    /// Sink to send lossy packets. The key is a long term public key of the
    /// peer that sent this packet.
    pub lossy_tx: LossyTx,
    /// Our DHT `PublicKey`
    pub dht_pk: PublicKey,
    /// Our DHT `SecretKey`
    pub dht_sk: SecretKey,
    /// Our real `PublicKey`
    pub real_pk: PublicKey,
    /// Our real `SecretKey`
    pub real_sk: SecretKey,
    /// Lru cache for precomputed keys. It stores precomputed keys to avoid
    /// redundant calculations.
    pub precomputed_keys: PrecomputedCache,
}

/// Struct that manages crypto connections to friends and handles net crypto
/// packets from both UDP and TCP connections.
#[derive(Clone)]
pub struct NetCrypto {
    /// Sink to send packet to UDP socket
    udp_tx: UdpTx,
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key. `NetCrypto` module can learn DHT
    /// `PublicKey` of peer from `Cookie` obtained from `CryptoHandshake`
    /// packet. If key from `Cookie` is not equal to saved key inside
    /// `CryptoConnection` then `NetCrypto` module will send message to this
    /// sink.
    dht_pk_tx: DhtPkTx,
    /// Sink to send lossless packets. The key is a long term public key of the
    /// peer that sent this packet.
    lossless_tx: LosslessTx,
    /// Sink to send lossy packets. The key is a long term public key of the
    /// peer that sent this packet.
    lossy_tx: LossyTx,
    /// Our DHT `PublicKey`
    dht_pk: PublicKey,
    /// Our DHT `SecretKey`
    dht_sk: SecretKey,
    /// Our real `PublicKey`
    real_pk: PublicKey,
    /// Our real `SecretKey`
    real_sk: SecretKey,
    /// Symmetric key used for cookies encryption
    symmetric_key: secretbox::Key,
    /// List of friends used to check whether should we accept an incoming
    /// `NetCrypto` connection.
    friends: Arc<RwLock<HashSet<PublicKey>>>,
    /// Connection by long term public key of DHT node map
    connections: Arc<RwLock<HashMap<PublicKey, Arc<RwLock<CryptoConnection>>>>>,
    /// Long term keys by IP address of DHT node map. `SocketAddr` can't be used
    /// as a key since it contains additional info for `IPv6` address.
    keys_by_addr: Arc<RwLock<HashMap<(IpAddr, /*port*/ u16), PublicKey>>>,
    /// Lru cache for precomputed keys. It stores precomputed keys to avoid
    /// redundant calculations.
    precomputed_keys: PrecomputedCache,
}

impl NetCrypto {
    /// Create new `NetCrypto` object
    pub fn new(args: NetCryptoNewArgs) -> NetCrypto {
        NetCrypto {
            udp_tx: args.udp_tx,
            dht_pk_tx: args.dht_pk_tx,
            lossless_tx: args.lossless_tx,
            lossy_tx: args.lossy_tx,
            dht_pk: args.dht_pk,
            dht_sk: args.dht_sk,
            real_pk: args.real_pk,
            real_sk: args.real_sk,
            symmetric_key: secretbox::gen_key(),
            friends: Arc::new(RwLock::new(HashSet::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            keys_by_addr: Arc::new(RwLock::new(HashMap::new())),
            precomputed_keys: args.precomputed_keys,
        }
    }

    /// Add a friend to accept incoming connections from him.
    pub fn add_friend(&self, real_pk: PublicKey) {
        self.friends.write().insert(real_pk);
    }

    /// Remove a friend to stop accepting incoming connections from him.
    pub fn remove_friend(&self, real_pk: PublicKey) {
        self.friends.write().remove(&real_pk);
    }

    /// Add connection to a friend when its DHT `PublicKey` is known.
    pub fn add_connection(&self, peer_real_pk: PublicKey, peer_dht_pk: PublicKey) {
        let mut connections = self.connections.write();

        if connections.contains_key(&peer_real_pk) {
            return;
        }

        let dht_precomputed_key = precompute(&peer_dht_pk, &self.dht_sk);
        let connection = CryptoConnection::new(
            &dht_precomputed_key,
            self.dht_pk,
            self.real_pk,
            peer_real_pk,
            peer_dht_pk
        );
        let connection = Arc::new(RwLock::new(connection));
        connections.insert(peer_real_pk, connection);
    }

    /// Clear stored addresses from `keys_by_addr`.
    fn clear_keys_by_addr(&self, connection: &CryptoConnection) {
        if connection.udp_addr_v4.is_some() || connection.udp_addr_v6.is_some() {
            let mut keys_by_addr = self.keys_by_addr.write();
            if let Some(addr) = connection.get_udp_addr_v4() {
                keys_by_addr.remove(&(addr.ip(), addr.port()));
            }
            if let Some(addr) = connection.get_udp_addr_v6() {
                keys_by_addr.remove(&(addr.ip(), addr.port()));
            }
        }
    }

    /// Kill a connection sending `PACKET_ID_KILL` packet and removing it from
    /// the connections list.
    pub fn kill_connection(&self, real_pk: PublicKey) -> impl Future<Item = (), Error = KillConnectionError> {
        if let Some(connection) = self.connections.write().remove(&real_pk) {
            let mut connection = connection.write();
            self.clear_keys_by_addr(&connection);
            if connection.is_established() || connection.is_not_confirmed() {
                let packet_number = connection.send_array.buffer_end;
                Either::A(self.send_data_packet(&mut connection, vec![PACKET_ID_KILL], packet_number)
                    .map_err(|e| e.context(KillConnectionErrorKind::SendTo).into()))
            } else {
                Either::B(future::ok(()))
            }
        } else {
            Either::B(future::err(KillConnectionErrorKind::NoConnection.into()))
        }
    }

    /// Set friend's UDP IP address when it gets known.
    pub fn set_friend_udp_addr(&self, real_pk: PublicKey, saddr: SocketAddr) {
        let connections = self.connections.read();
        let mut connection = if let Some(connection) = connections.get(&real_pk) {
            connection.write()
        } else {
            return
        };

        if connection.get_udp_addr_v4() == Some(saddr) || connection.get_udp_addr_v6() == Some(saddr) {
            return
        }

        let mut keys_by_addr = self.keys_by_addr.write();
        let current_addr = if saddr.is_ipv4() {
            connection.get_udp_addr_v4()
        } else {
            connection.get_udp_addr_v6()
        };
        if let Some(saddr) = current_addr {
            keys_by_addr.remove(&(saddr.ip(), saddr.port()));
        }
        connection.set_udp_addr(saddr);
        keys_by_addr.insert((saddr.ip(), saddr.port()), real_pk);
    }

    /// Send lossless packet to a friend via established connection.
    pub fn send_lossless(&self, real_pk: PublicKey, packet: Vec<u8>) -> impl Future<Item = (), Error = SendLosslessPacketError> {
        if packet.first().map_or(true, |&packet_id| packet_id <= PACKET_ID_CRYPTO_RANGE_END || packet_id >= PACKET_ID_LOSSY_RANGE_START) {
            return Either::B(future::err(SendLosslessPacketErrorKind::InvalidPacketId.into()));
        }

        if let Some(connection) = self.connections.read().get(&real_pk) {
            let mut connection = connection.write();
            let packet_number = connection.send_array.buffer_end;
            if let Err(e) = connection.send_array.push_back(SentPacket::new(packet.clone())) {
                Either::B(future::err(e.context(SendLosslessPacketErrorKind::FullSendArray).into()))
            } else {
                connection.packets_sent += 1;
                Either::A(self.send_data_packet(&mut connection, packet, packet_number)
                    .map_err(|e| e.context(SendLosslessPacketErrorKind::SendTo).into()))
            }
        } else {
            Either::B(future::err(SendLosslessPacketErrorKind::NoConnection.into()))
        }
    }

    /// Send `Packet` packet to UDP socket
    fn send_to_udp(&self, addr: SocketAddr, packet: Packet) -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        send_to_bounded(&self.udp_tx, (packet, addr), NET_CRYPTO_SEND_TIMEOUT)
    }

    /// Get long term `PublicKey` of the peer by its UDP address
    fn key_by_addr(&self, addr: SocketAddr) -> Option<PublicKey> {
        self.keys_by_addr.read().get(&(addr.ip(), addr.port())).cloned()
    }

    /// Get crypto connection by long term `PublicKey`
    fn connection_by_key(&self, pk: PublicKey) -> Option<Arc<RwLock<CryptoConnection>>> {
        self.connections.read().get(&pk).cloned()
    }

    /// Create `CookieResponse` packet with `Cookie` requested by `CookieRequest` packet
    fn handle_cookie_request(&self, packet: &CookieRequest) -> Result<CookieResponse, HandlePacketError> {
        let payload = packet.get_payload(&self.precomputed_keys.get(packet.pk))
            .map_err(|e| e.context(HandlePacketErrorKind::GetPayload))?;

        let cookie = Cookie::new(payload.pk, packet.pk);
        let encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, &cookie);

        let response_payload = CookieResponsePayload {
            cookie: encrypted_cookie,
            id: payload.id,
        };
        let precomputed_key = precompute(&packet.pk, &self.dht_sk);
        let response = CookieResponse::new(&precomputed_key, &response_payload);

        Ok(response)
    }

    /// Handle `CookieRequest` packet received from UDP socket
    pub fn handle_udp_cookie_request(&self, packet: &CookieRequest, addr: SocketAddr) -> impl Future<Item = (), Error = HandlePacketError> + Send {
        match self.handle_cookie_request(packet) {
            Ok(response) => Either::A(self.send_to_udp(addr, Packet::CookieResponse(response))
                .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())),
            Err(e) => Either::B(future::err(e))
        }
    }

    /// Handle `CookieResponse` and if it's correct change connection status to `HandshakeSending`.
    pub fn handle_cookie_response(&self, connection: &mut CryptoConnection, packet: &CookieResponse)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let cookie_request_id = if let ConnectionStatus::CookieRequesting { cookie_request_id, .. } = connection.status {
            cookie_request_id
        } else {
            return Either::A(future::err(HandlePacketError::from(HandlePacketErrorKind::InvalidState)))
        };

        let payload = match packet.get_payload(&self.precomputed_keys.get(connection.peer_dht_pk)) {
            Ok(payload) => payload,
            Err(e) => return Either::A(future::err(e.context(HandlePacketErrorKind::GetPayload).into())),
        };

        if payload.id != cookie_request_id {
            return Either::A(future::err(HandlePacketError::invalid_request_id(cookie_request_id, payload.id)))
        }

        let sent_nonce = gen_nonce();
        let our_cookie = Cookie::new(connection.peer_real_pk, connection.peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, &our_cookie);
        let handshake_payload = CryptoHandshakePayload {
            base_nonce: sent_nonce,
            session_pk: connection.session_pk,
            cookie_hash: payload.cookie.hash(),
            cookie: our_encrypted_cookie,
        };
        let handshake = CryptoHandshake::new(&precompute(&connection.peer_real_pk, &self.real_sk), &handshake_payload, payload.cookie);

        connection.status = ConnectionStatus::HandshakeSending {
            sent_nonce,
            packet: StatusPacket::new_crypto_handshake(handshake)
        };

        Either::B(self.send_status_packet(connection)
                      .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
        )
    }

    /// Handle `CookieResponse` packet received from UDP socket
    pub fn handle_udp_cookie_response(&self, packet: &CookieResponse, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let connection = self.key_by_addr(addr).and_then(|pk| self.connection_by_key(pk));
        if let Some(connection) = connection {
            let mut connection = connection.write();
            connection.set_udp_addr(addr);
            Either::A(self.handle_cookie_response(&mut connection, packet))
        } else {
            Either::B(future::err(
                HandlePacketError::no_connection(addr)))
        }
    }

    /// Check that incoming `CryptoHandshake` request is valid:
    /// - cookie is not timed out
    /// - hash for the cookie inside the payload is correct
    fn validate_crypto_handshake(&self, packet: &CryptoHandshake)
        -> Result<(Cookie, CryptoHandshakePayload, PrecomputedKey), HandlePacketError> {
        let cookie = match packet.cookie.get_payload(&self.symmetric_key) {
            Ok(cookie) => cookie,
            Err(e) => return Err(e.context(HandlePacketErrorKind::GetPayload).into()),
        };

        if cookie.is_timed_out() {
            return Err(HandlePacketErrorKind::CookieTimedOut.into());
        }

        let real_precomputed_key = precompute(&cookie.real_pk, &self.real_sk);

        let payload = match packet.get_payload(&real_precomputed_key) {
            Ok(payload) => payload,
            Err(e) => return Err(e.context(HandlePacketErrorKind::GetPayload).into()),
        };

        if packet.cookie.hash() != payload.cookie_hash {
            return Err(HandlePacketErrorKind::BadSha512.into());
        }

        Ok((cookie, payload, real_precomputed_key))
    }

    /// Handle `CryptoHandshake` and if it's correct change connection status to `NotConfirmed`.
    pub fn handle_crypto_handshake(&self, connection: &mut CryptoConnection, packet: &CryptoHandshake)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        if let ConnectionStatus::Established { .. } = connection.status {
            return Box::new(future::err(HandlePacketError::from(HandlePacketErrorKind::InvalidState)))
                as Box<dyn Future<Item=_, Error=_> + Send>
        }

        let (cookie, payload, real_precomputed_key) = match self.validate_crypto_handshake(packet) {
            Ok(result) => result,
            Err(e) => return Box::new(future::err(e)),
        };

        if cookie.real_pk != connection.peer_real_pk {
            return Box::new(future::err(HandlePacketError::from(HandlePacketErrorKind::InvalidRealPk)))
        }
        if cookie.dht_pk != connection.peer_dht_pk {
            return Box::new(
                send_to(&self.dht_pk_tx, (connection.peer_real_pk, cookie.dht_pk))
                    .map_err(|e| e.context(HandlePacketErrorKind::SendToDhtpk).into())
                    .and_then(|()| future::err(HandlePacketError::from(HandlePacketErrorKind::InvalidDhtPk)))
            )
        }

        connection.status = match connection.status {
            ConnectionStatus::CookieRequesting { .. } => {
                let sent_nonce = gen_nonce();
                let our_cookie = Cookie::new(connection.peer_real_pk, connection.peer_dht_pk);
                let our_encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, &our_cookie);
                let handshake_payload = CryptoHandshakePayload {
                    base_nonce: sent_nonce,
                    session_pk: connection.session_pk,
                    cookie_hash: payload.cookie.hash(),
                    cookie: our_encrypted_cookie,
                };
                let handshake = CryptoHandshake::new(&real_precomputed_key, &handshake_payload, payload.cookie);
                ConnectionStatus::NotConfirmed {
                    sent_nonce,
                    received_nonce: payload.base_nonce,
                    peer_session_pk: payload.session_pk,
                    session_precomputed_key: precompute(&payload.session_pk, &connection.session_sk),
                    packet: StatusPacket::new_crypto_handshake(handshake)
                }
            },
            ConnectionStatus::HandshakeSending { sent_nonce, ref packet, .. }
            | ConnectionStatus::NotConfirmed { sent_nonce, ref packet, .. } => ConnectionStatus::NotConfirmed {
                sent_nonce,
                received_nonce: payload.base_nonce,
                peer_session_pk: payload.session_pk,
                session_precomputed_key: precompute(&payload.session_pk, &connection.session_sk),
                packet: packet.clone()
            },
            ConnectionStatus::Established { .. } => unreachable!("Checked for Established status above"),
        };

        Box::new(self.send_status_packet(connection)
            .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
        )
    }

    /// Handle incoming `CryptoHandshake` in case when we don't have associated
    /// with sender connection.
    fn handle_crypto_handshake_new_connection(&self, packet: &CryptoHandshake, addr: Option<SocketAddr>)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let (cookie, payload, _real_precomputed_key) = match self.validate_crypto_handshake(packet) {
            Ok(result) => result,
            Err(e) => return Either::A(future::err(e)),
        };

        if !self.friends.read().contains(&cookie.real_pk) {
            return Either::A(future::err(HandlePacketErrorKind::UnexpectedCryptoHandshake.into()));
        }

        let mut connection = CryptoConnection::new_not_confirmed(
            &self.real_sk,
            cookie.real_pk,
            cookie.dht_pk,
            payload.base_nonce,
            payload.session_pk,
            payload.cookie,
            &self.symmetric_key,
        );
        if let Some(addr) = addr {
            connection.set_udp_addr(addr);
            self.keys_by_addr.write().insert((addr.ip(), addr.port()), cookie.real_pk);
        }
        let connection = Arc::new(RwLock::new(connection));
        self.connections.write().insert(cookie.real_pk, connection);

        Either::B(send_to(&self.dht_pk_tx, (cookie.real_pk, cookie.dht_pk))
            .map_err(|e| e.context(HandlePacketErrorKind::SendToDhtpk).into()))
    }

    /// Handle `CryptoHandshake` packet received from UDP socket
    pub fn handle_udp_crypto_handshake(&self, packet: &CryptoHandshake, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let connection = self.key_by_addr(addr).and_then(|pk| self.connection_by_key(pk));
        if let Some(connection) = connection {
            let mut connection = connection.write();
            connection.set_udp_addr(addr);
            Either::A(self.handle_crypto_handshake(&mut connection, packet))
        } else {
            Either::B(self.handle_crypto_handshake_new_connection(packet, Some(addr)))
        }
    }

    /** Handle request packet marking requested packets if rtt is elapsed since
    they were sent and removing delivered packets.

    Request array consists of bytes where every byte means offset of the
    requested packet starting from 1. Each 0 means adding 255 to the offset
    until non 0 byte is reached. For example, array of bytes [3 3 0 0 0 253]
    means that packets 2, 5 and 1023 were requested (if the first index is 0).

    */
    fn handle_request_packet(send_array: &mut PacketsArray<SentPacket>, mut data: &[u8], rtt: Duration, last_sent_time: &mut Option<Instant>) {
        // n is a packet number corresponding to numbers from the request
        let mut n = 1;

        // Cycle over sent packets to mark them requested or to delete them if
        // they are not requested which means they are delivered
        for i in send_array.buffer_start .. send_array.buffer_end {
            // Stop if there is no more request numbers to handle
            if data.is_empty() {
                break
            }

            if n == data[0] { // packet is requested
                if let Some(packet) = send_array.get_mut(i) {
                    if clock_elapsed(packet.sent_time) > rtt { // mark it if it wasn't delivered in time
                        packet.requested = true;
                    }
                }
                n = 0;
                data = &data[1..];
            } else if let Some(packet) = send_array.remove(i) { // packet is not requested, delete it
                if last_sent_time.map(|time| time < packet.sent_time).unwrap_or(true) {
                    *last_sent_time = Some(packet.sent_time);
                }
            }

            if n == 255 {
                // n went through all the values except 0
                // which means that request byte is 0
                // which means that requested packet number is greater than 255
                // so just reset n and go farther
                n = 1;
                data = &data[1..];
            } else {
                n += 1;
            }
        }
    }

    /// Build request packet that will contain numbers of missing packets that
    /// we should receive.
    fn generate_request_packet(recv_array: &PacketsArray<RecvPacket>) -> Vec<u8> {
        let mut data = Vec::with_capacity(MAX_CRYPTO_DATA_SIZE);
        data.push(PACKET_ID_REQUEST);

        // n is a packet number relative to the last missing packet
        let mut n = 1;

        // go through all received packets and put numbers of missing packets to the request
        for i in recv_array.buffer_start .. recv_array.buffer_end {
            if !recv_array.contains(i) {
                data.push(n);
                n = 0;
            } else if n == 255 {
                data.push(0);
                n = 0;
            }

            if data.len() == MAX_CRYPTO_DATA_SIZE {
                return data;
            }

            n += 1;
        }

        data
    }

    /// Send received lossless packets from the beginning of the receiving
    /// buffer to lossless sink and delete them
    fn process_ready_lossless_packets(&self, recv_array: &mut PacketsArray<RecvPacket>, pk: PublicKey)
        -> impl Future<Item = (), Error = mpsc::SendError<(PublicKey, Vec<u8>)>> + Send {
        let mut futures = Vec::new();
        while let Some(packet) = recv_array.pop_front() {
            let future = send_to(&self.lossless_tx, (pk, packet.data));
            futures.push(future);
        }
        future::join_all(futures).map(|_| ())
    }

    /// Find the time when the last acknowledged packet was sent. This time is
    /// used to update rtt
    fn last_sent_time(send_array: &PacketsArray<SentPacket>, index: u32) -> Option<Instant> {
        let mut last_sent_time = None;
        for i in send_array.buffer_start .. index {
            if let Some(packet) = send_array.get(i) {
                if last_sent_time.map(|time| time < packet.sent_time).unwrap_or(true) {
                    last_sent_time = Some(packet.sent_time);
                }
            }
        }
        last_sent_time
    }

    /** Handle `CryptoData` packet

    Every data packet contains `buffer_start` index. All packets with index
    lower than `buffer_start` index were received by other side. So we can
    delete all these packets from sent packets array.

    Then depending on type of the data packet we can do:
    - kill type: kill the connection
    - request type: mark packets from the sent packets buffer that they should
      be sent and delete delivered packets
    - lossless type: add packet to the received packets buffer and process
      packets from the beginning of this buffer
    - lossy type: just process the packet
    */
    fn handle_crypto_data(&self, connection: &mut CryptoConnection, packet: &CryptoData, udp: bool)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let (sent_nonce, mut received_nonce, peer_session_pk, session_precomputed_key) = match connection.status {
            ConnectionStatus::NotConfirmed { sent_nonce, received_nonce, peer_session_pk, ref session_precomputed_key, .. }
            | ConnectionStatus::Established { sent_nonce, received_nonce, peer_session_pk, ref session_precomputed_key } => {
                (sent_nonce, received_nonce, peer_session_pk, session_precomputed_key.clone())
            },
            _ => {
                return Box::new(future::err(HandlePacketError::from(HandlePacketErrorKind::CannotHandleCryptoData)))
                    as Box<dyn Future<Item = _, Error = _> + Send>
            }
        };

        let cur_last_bytes = CryptoData::nonce_last_bytes(received_nonce);
        let (diff, _) = packet.nonce_last_bytes.overflowing_sub(cur_last_bytes);
        let mut packet_nonce = received_nonce;
        increment_nonce_number(&mut packet_nonce, u64::from(diff));

        let payload = match packet.get_payload(&session_precomputed_key, &packet_nonce) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(e.context(HandlePacketErrorKind::GetPayload).into()))
        };

        // Find the time when the last acknowledged packet was sent
        let mut last_sent_time = NetCrypto::last_sent_time(&connection.send_array, payload.buffer_start);

        // Remove all acknowledged packets and set new start index to the send buffer
        if let Err(e) = connection.send_array.set_buffer_start(payload.buffer_start) {
            return Box::new(future::err(e.context(HandlePacketErrorKind::PacketsArrayError).into()))
        }

        // And get the ID of the packet
        let packet_id = match payload.data.first() {
            Some(&packet_id) => packet_id,
            None => return Box::new(future::err(HandlePacketError::from(HandlePacketErrorKind::DataEmpty)))
        };

        if packet_id == PACKET_ID_KILL {
            // Kill the connection
            self.connections.write().remove(&connection.peer_real_pk);
            self.clear_keys_by_addr(&connection);
            return Box::new(future::ok(()));
        }

        // Update nonce if diff is big enough
        if diff > NONCE_DIFF_THRESHOLD * 2 {
            increment_nonce_number(&mut received_nonce, u64::from(NONCE_DIFF_THRESHOLD));
        }

        // TODO: connection status notification

        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key
        };

        let result = if packet_id == PACKET_ID_REQUEST {
            // Use const RTT in case of TCP connection
            let rtt = if udp { connection.rtt } else { TCP_RTT };
            NetCrypto::handle_request_packet(&mut connection.send_array, &payload.data[1..], rtt, &mut last_sent_time);
            // Update end index of received buffer ignoring the error - we still
            // want to handle this packet even if connection is too slow
            connection.recv_array.set_buffer_end(payload.packet_number).ok();
            Box::new(future::ok(())) as Box<dyn Future<Item = _, Error = _> + Send>
        } else if packet_id > PACKET_ID_CRYPTO_RANGE_END && packet_id < PACKET_ID_LOSSY_RANGE_START {
            if let Err(e) = connection.recv_array.insert(payload.packet_number, RecvPacket::new(payload.data)) {
                return Box::new(future::err(e.context(HandlePacketErrorKind::PacketsArrayError).into()))
            }
            connection.packets_received += 1;
            Box::new(self.process_ready_lossless_packets(&mut connection.recv_array, connection.peer_real_pk)
                .map_err(|e| e.context(HandlePacketErrorKind::SendToLossless).into()))
        } else if packet_id >= PACKET_ID_LOSSY_RANGE_START && packet_id <= PACKET_ID_LOSSY_RANGE_END {
            // Update end index of received buffer ignoring the error - we still
            // want to handle this packet even if connection is too slow
            connection.recv_array.set_buffer_end(payload.packet_number).ok();
            Box::new(send_to(&self.lossy_tx, (connection.peer_real_pk, payload.data))
                .map_err(|e| e.context(HandlePacketErrorKind::SendToLossy).into()))
                    as Box<dyn Future<Item = _, Error = _> + Send>
        } else {
            return Box::new(future::err(HandlePacketError::packet_id(packet_id)))
        };

        // TODO: update rtt only when udp is true?
        if let Some(last_sent_time) = last_sent_time {
            // Update rtt if it's become lower
            let elapsed = clock_elapsed(last_sent_time);
            if elapsed < connection.rtt {
                connection.rtt = elapsed;
            }
        }

        result
    }

    /// Handle `CryptoData` packet received from UDP socket
    pub fn handle_udp_crypto_data(&self, packet: &CryptoData, addr: SocketAddr) -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let connection = self.key_by_addr(addr).and_then(|pk| self.connection_by_key(pk));
        if let Some(connection) = connection {
            let mut connection = connection.write();
            connection.set_udp_addr(addr);
            Either::A(self.handle_crypto_data(&mut connection, packet, /* udp */ true))
        } else {
            Either::B(future::err(HandlePacketError::no_connection(addr)))
        }
    }

    /// Send packet to crypto connection choosing TCP or UDP protocol
    fn send_packet(&self, packet: Packet, connection: &mut CryptoConnection)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        // TODO: can backpressure be used instead of congestion control? It
        // seems it's possible to implement wrapper for bounded sender with
        // priority queue and just send packets there
        if let Some(addr) = connection.get_udp_addr() {
            if connection.is_udp_alive() {
                return Box::new(self.send_to_udp(addr, packet)) as Box<dyn Future<Item = _, Error = _> + Send>
            }

            let udp_attempt_should_be_made = connection.udp_attempt_should_be_made() && {
                // check if the packet is not too big
                let mut buf = [0; DHT_ATTEMPT_MAX_PACKET_LENGTH];
                packet.to_bytes((&mut buf, 0)).is_ok()
            };

            if udp_attempt_should_be_made {
                connection.update_udp_send_attempt_time();
                Box::new(self.send_to_udp(addr, packet)) as Box<dyn Future<Item = _, Error = _> + Send>
            } else {
                Box::new(future::ok(()))
            }
        } else {
            Box::new(future::ok(()))
        }

        // TODO: send via TCP relay here
    }

    /// Send `CookieRequest` or `CryptoHandshake` packet if needed depending on
    /// connection status and update sent counter
    fn send_status_packet(&self, connection: &mut CryptoConnection)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        match connection.packet_to_send() {
            Some(packet) => Either::A(self.send_packet(packet, connection)),
            None => Either::B(future::ok(())),
        }
    }

    /// Send `CryptoData` packet if the connection is established.
    fn send_data_packet(&self, connection: &mut CryptoConnection, data: Vec<u8>, packet_number: u32)
        -> impl Future<Item = (), Error = SendDataError> + Send {
        let packet = match connection.status {
            ConnectionStatus::NotConfirmed { ref mut sent_nonce, ref session_precomputed_key, .. }
            | ConnectionStatus::Established { ref mut sent_nonce, ref session_precomputed_key, .. } => {
                let payload = CryptoDataPayload {
                    buffer_start: connection.recv_array.buffer_start,
                    packet_number,
                    data,
                };
                let packet = CryptoData::new(session_precomputed_key, *sent_nonce, &payload);
                increment_nonce(sent_nonce);
                packet
            },
            _ => return Either::A(future::err(SendDataError::from(SendDataErrorKind::NoConnection))),
        };
        Either::B(self.send_packet(Packet::CryptoData(packet), connection)
            .map_err(|e| e.context(SendDataErrorKind::SendTo).into()))
    }

    /// Send request packet with indices of not received packets.
    fn send_request_packet(&self, connection: &mut CryptoConnection) -> impl Future<Item = (), Error = SendDataError> + Send {
        let data = NetCrypto::generate_request_packet(&connection.recv_array);
        let packet_number = connection.send_array.buffer_end;
        // TODO: set only if packet was sent successfully?
        connection.request_packet_sent_time = Some(clock_now());
        self.send_data_packet(connection, data, packet_number)
    }

    /// Send packets that were requested.
    fn send_requested_packets(&self, connection: &mut CryptoConnection) -> impl Future<Item = (), Error = SendDataError> + Send {
        let now = clock_now();
        let packets = connection.send_array.iter_mut()
            .filter(|(_, packet)| packet.requested)
            .map(|(i, packet)| {
                packet.requested = false;
                packet.sent_time = now;
                (i, packet.data.clone())
            }).collect::<Vec<_>>();
        let futures = packets.into_iter().map(|(i, data)|
            self.send_data_packet(connection, data, i)
        ).collect::<Vec<_>>();
        future::join_all(futures).map(|_| ())
    }

    /// The main loop that should be run at least 20 times per second
    fn main_loop(&self) -> impl Future<Item = (), Error = SendDataError> + Send {
        let mut connections = self.connections.write();
        let mut keys_by_addr = self.keys_by_addr.write();
        let mut futures: Vec<Box<dyn Future<Item = _, Error = _> + Send>> = Vec::new();

        // Only one cycle over all connections to prevent many lock acquirements
        connections.retain(|_pk, connection| {
            let mut connection = connection.write();

            if connection.is_timed_out() {
                if let Some(addr) = connection.get_udp_addr_v4() {
                    keys_by_addr.remove(&(addr.ip(), addr.port()));
                }
                if let Some(addr) = connection.get_udp_addr_v6() {
                    keys_by_addr.remove(&(addr.ip(), addr.port()));
                }

                if connection.is_established() || connection.is_not_confirmed() {
                    let packet_number = connection.send_array.buffer_end;
                    futures.push(Box::new(self.send_data_packet(&mut connection, vec![PACKET_ID_KILL], packet_number)));
                }

                return false;
            }

            let send_future = self.send_status_packet(&mut connection)
                .map_err(|e| e.context(SendDataErrorKind::SendTo).into());
            futures.push(Box::new(send_future));

            if connection.is_not_confirmed() || connection.is_established() {
                let should_send = connection.request_packet_sent_time.map_or(true, |time|
                    clock_elapsed(time) > CRYPTO_SEND_PACKET_INTERVAL
                );
                if should_send {
                    futures.push(Box::new(self.send_request_packet(&mut connection)));
                }
            }

            if connection.is_established() {
                if connection.packet_recv_rate > CRYPTO_PACKET_MIN_RATE {
                    let request_packet_interval = connection.request_packet_interval();
                    let should_send = connection.request_packet_sent_time.map_or(true, |time|
                        clock_elapsed(time) > request_packet_interval
                    );
                    if should_send {
                        futures.push(Box::new(self.send_request_packet(&mut connection)));
                    }
                }

                // TODO: either use send_rate or remove it
                connection.update_congestion_stats();

                futures.push(Box::new(self.send_requested_packets(&mut connection)));
            }

            true
        });

        future::join_all(futures).map(|_| ())
    }

    /// Run `net_crypto` periodical tasks. Result future will never be completed
    /// successfully.
    pub fn run(self) -> impl Future<Item = (), Error = RunError> + Send {
        let wakeups = Interval::new(Instant::now(), PACKET_COUNTER_AVERAGE_INTERVAL);

        wakeups
            .map_err(|e| e.context(RunErrorKind::Wakeup).into())
            .for_each(move |_instant| self.main_loop()
                .map_err(|e| e.context(RunErrorKind::SendData).into())
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::Stream;
    use tokio_executor;
    use tokio_timer::clock::*;

    use crate::toxcore::time::ConstNow;

    #[test]
    fn net_crypto_clone() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let _net_crypto_c = net_crypto.clone();
    }

    #[test]
    fn add_remove_friend() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        net_crypto.add_friend(peer_real_pk);
        assert!(net_crypto.friends.read().contains(&peer_real_pk));
        net_crypto.remove_friend(peer_real_pk);
        assert!(!net_crypto.friends.read().contains(&peer_real_pk));
    }

    #[test]
    fn handle_cookie_request() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, &cookie_request_payload);

        let cookie_response = net_crypto.handle_cookie_request(&cookie_request).unwrap();
        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[test]
    fn handle_cookie_request_invalid() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        let res = net_crypto.handle_cookie_request(&cookie_request);
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    #[test]
    fn handle_udp_cookie_request() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, &cookie_request_payload);

        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.handle_udp_cookie_request(&cookie_request, addr).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();
        let cookie_response = unpack!(packet, Packet::CookieResponse);

        assert_eq!(addr_to_send, addr);

        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[test]
    fn handle_udp_cookie_request_invalid() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        let addr = "127.0.0.1:12345".parse().unwrap();

        let res = net_crypto.handle_udp_cookie_request(&cookie_request, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    #[test]
    fn handle_cookie_response() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: cookie_request_id
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        net_crypto.handle_cookie_response(&mut connection, &cookie_response).wait().unwrap();

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&precompute(&real_pk, &peer_real_sk)).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_cookie_response_invalid_status() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk: real_sk.clone(),
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new_not_confirmed(
            &real_sk,
            peer_real_pk,
            peer_dht_pk,
            gen_nonce(),
            gen_keypair().0,
            EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88]
            },
            &net_crypto.symmetric_key
        );

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie,
            id: 12345
        };
        let cookie_response = CookieResponse::new(&precompute(&peer_dht_pk, &dht_sk), &cookie_response_payload);

        let res = net_crypto.handle_cookie_response(&mut connection, &cookie_response).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidState);
    }

    #[test]
    fn handle_cookie_response_invalid_request_id() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie,
            id: cookie_request_id.overflowing_add(1).0
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        assert!(net_crypto.handle_cookie_response(&mut connection, &cookie_response).wait().is_err());
    }


    #[test]
    fn handle_udp_cookie_response() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: cookie_request_id
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        net_crypto.handle_udp_cookie_response(&cookie_response, addr).wait().unwrap();

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&precompute(&real_pk, &peer_real_sk)).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_udp_cookie_response_no_connection() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);

        let addr = "127.0.0.1:12345".parse().unwrap();

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: 12345
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        let res = net_crypto.handle_udp_cookie_response(&cookie_response, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NoConnection { addr: "127.0.0.1:12345".parse().unwrap() });
    }

    #[test]
    fn handle_crypto_handshake_in_cookie_requesting_status() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().unwrap();

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_crypto_handshake_in_not_confirmed_status() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk: real_sk.clone(),
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88]
        };
        let mut connection = CryptoConnection::new_not_confirmed(
            &real_sk,
            peer_real_pk,
            peer_dht_pk,
            gen_nonce(),
            gen_keypair().0,
            cookie.clone(),
            &net_crypto.symmetric_key
        );

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let other_cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: other_cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().unwrap();

        // Nonce and session pk should be taken from the packet
        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        // cookie should not be updated
        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_crypto_handshake_invalid_status() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce: gen_nonce(),
            peer_session_pk,
            session_precomputed_key,
        };

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidState);
    }

    #[test]
    fn handle_crypto_handshake_invalid_hash() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::BadSha512);
    }

    #[test]
    fn handle_crypto_handshake_timed_out_cookie() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let mut our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        our_cookie.time -= COOKIE_TIMEOUT + 1;
        let our_encrypted_cookie = EncryptedCookie::new(&&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::CookieTimedOut);
    }

    #[test]
    fn handle_crypto_handshake_invalid_peer_real_pk() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (another_peer_real_pk, another_peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &another_peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(another_peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidRealPk);
    }

    #[test]
    fn handle_crypto_handshake_invalid_peer_dht_pk() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let (new_dht_pk, _new_dht_sk) = gen_keypair();

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, new_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidDhtPk);

        let (keys, _dht_pk_rx) = dht_pk_rx.into_future().wait().unwrap();
        let (received_real_pk, received_dht_pk) = keys.unwrap();

        assert_eq!(received_real_pk, peer_real_pk);
        assert_eq!(received_dht_pk, new_dht_pk);
    }

    #[test]
    fn handle_udp_crypto_handshake() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_udp_crypto_handshake(&crypto_handshake, addr).wait().unwrap();

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_udp_crypto_handshake_new_connection() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();

        net_crypto.add_friend(peer_real_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.handle_udp_crypto_handshake(&crypto_handshake, addr).wait().unwrap();

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        assert_eq!(connection.get_udp_addr_v4(), Some(addr));

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_udp_crypto_handshake_unexpected() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let addr = "127.0.0.1:12345".parse().unwrap();

        let error = net_crypto.handle_udp_crypto_handshake(&crypto_handshake, addr).wait().err().unwrap();

        assert_eq!(*error.kind(), HandlePacketErrorKind::UnexpectedCryptoHandshake);
    }

    #[test]
    fn handle_crypto_data_lossy() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[test]
    fn handle_crypto_data_lossy_increment_nonce() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        // Make the diff between nonces is bigger than the threshold
        let mut packet_nonce = received_nonce;
        increment_nonce_number(&mut packet_nonce, u64::from(2 * NONCE_DIFF_THRESHOLD + 1));

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, packet_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();

        // The diff between nonces is bigger than the threshold so received
        // nonce should be changed increased
        let mut expected_nonce = received_nonce;
        increment_nonce_number(&mut expected_nonce, u64::from(NONCE_DIFF_THRESHOLD));
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), expected_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[test]
    fn handle_crypto_data_lossy_update_rtt() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let now = Instant::now();

        let sent_packet = SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: false,
        };
        assert!(connection.send_array.insert(0, sent_packet).is_ok());

        connection.rtt = Duration::from_millis(500);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 1,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(now + Duration::from_millis(250)));

        with_default(&clock, &mut enter, |_| {
            net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();
        });

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 1);
        assert_eq!(connection.send_array.buffer_end, 1);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);

        // avoid problems with floating point arithmetic
        assert!(
            connection.rtt > Duration::from_millis(249)
                && connection.rtt < Duration::from_millis(251)
        );
    }

    #[test]
    fn handle_crypto_data_lossy_invalid_buffer_start() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 7, // bigger than end index of sent packets buffer
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::PacketsArrayError);

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_lossless() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload_1 = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]
        };
        let crypto_data_1 = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload_1);

        let crypto_data_payload_2 = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 1,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 4, 5, 6]
        };
        let crypto_data_2 = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload_2);

        let crypto_data_payload_3 = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 2,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 7, 8, 9]
        };
        let crypto_data_3 = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload_3);

        // Send packets in random order
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_2, /* udp */ true).wait().unwrap();
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_3, /* udp */ true).wait().unwrap();
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_1, /* udp */ true).wait().unwrap();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 3);
        assert_eq!(connection.recv_array.buffer_end, 3);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        // We should receive lossless packets according to their numbers

        let (received, lossless_rx) = lossless_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]);

        let (received, lossless_rx) = lossless_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 4, 5, 6]);

        let (received, _lossless_rx) = lossless_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 7, 8, 9]);
    }

    #[test]
    fn handle_crypto_data_lossless_too_big_index() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: CRYPTO_PACKET_BUFFER_SIZE,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::PacketsArrayError);

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_kill() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let connection = Arc::new(RwLock::new(connection));
        net_crypto.connections.write().insert(peer_real_pk, connection.clone());
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_KILL]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection.write(), &crypto_data, /* udp */ true).wait().unwrap();

        assert!(net_crypto.connections.read().is_empty());
        assert!(net_crypto.keys_by_addr.read().is_empty());
    }

    #[test]
    fn handle_crypto_data_request() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let now = Instant::now();

        assert!(connection.send_array.insert(0, SentPacket::new(vec![42; 123])).is_ok());
        // this time will be used to update rtt
        let packet_1 = SentPacket {
            data: vec![43; 123],
            sent_time: now + Duration::from_millis(750),
            requested: false,
        };
        assert!(connection.send_array.insert(1, packet_1).is_ok());
        // this packet will be requested but elapsed time will be less then rtt
        // so it shouldn't be marked
        let packet_5 = SentPacket {
            data: vec![44; 123],
            sent_time: now + Duration::from_millis(750),
            requested: false,
        };
        assert!(connection.send_array.insert(5, packet_5).is_ok());
        assert!(connection.send_array.insert(7, SentPacket::new(vec![45; 123])).is_ok());
        assert!(connection.send_array.insert(1024, SentPacket::new(vec![46; 123])).is_ok());

        connection.rtt = Duration::from_millis(500);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_REQUEST, 1, 5, 0, 0, 0, 254] // request 0, 5 and 1024 packets
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(now + Duration::from_secs(1)));

        with_default(&clock, &mut enter, |_| {
            net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();
        });

        assert!(connection.send_array.get(0).unwrap().requested);
        assert!(connection.send_array.get(1).is_none());
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert!(connection.send_array.get(7).is_none());
        assert!(connection.send_array.get(1024).unwrap().requested);

        // avoid problems with floating point arithmetic
        assert!(
            connection.rtt > Duration::from_millis(249)
                && connection.rtt < Duration::from_millis(251)
        );
    }

    #[test]
    fn handle_crypto_data_empty_request() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        assert!(connection.send_array.insert(0, SentPacket::new(vec![42; 123])).is_ok());
        assert!(connection.send_array.insert(1, SentPacket::new(vec![43; 123])).is_ok());
        assert!(connection.send_array.insert(5, SentPacket::new(vec![44; 123])).is_ok());
        assert!(connection.send_array.insert(7, SentPacket::new(vec![45; 123])).is_ok());
        assert!(connection.send_array.insert(1024, SentPacket::new(vec![46; 123])).is_ok());

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_REQUEST]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();

        assert!(!connection.send_array.get(0).unwrap().requested);
        assert!(!connection.send_array.get(1).unwrap().requested);
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert!(!connection.send_array.get(7).unwrap().requested);
        assert!(!connection.send_array.get(1024).unwrap().requested);
    }

    #[test]
    fn handle_crypto_data_invalid_packet_id() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![255, 1, 2, 3] // only 255 is invalid id
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::PacketId { id: 255 });

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_empty_data() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: Vec::new()
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::DataEmpty);

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_invalid_status() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![0, 0, PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::CannotHandleCryptoData);
    }

    #[test]
    fn handle_udp_crypto_data_lossy() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![0, 0, PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_udp_crypto_data(&crypto_data, addr).wait().unwrap();

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[test]
    fn send_status_packet() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        // send status packet first time - it should be sent
        net_crypto.send_status_packet(&mut connection).wait().unwrap();

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(received, packet.dht_packet());
        assert_eq!(addr_to_send, addr);

        // send status packet again - it shouldn't be sent
        net_crypto.send_status_packet(&mut connection).wait().unwrap();

        let packet = unpack!(connection.status, ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);
    }

    #[test]
    fn send_packet_udp() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);
    }

    #[test]
    fn send_packet_udp_attempt() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH - 3] // 1 byte of packet kind and 2 bytes of nonce
        });

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(Instant::now() + UDP_DIRECT_TIMEOUT + Duration::from_secs(1)));

        with_default(&clock, &mut enter, |_| {
            net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();
        });

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);

        // TODO: check that TCP received the packet
    }

    #[test]
    fn send_packet_no_udp_attempt() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();

        // TODO: check that TCP received the packet
    }

    #[test]
    fn send_packet_tcp() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();

        // TODO: check that TCP received the packet
    }

    #[test]
    fn main_loop_sends_status_packets() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet).dht_packet();

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));

        net_crypto.main_loop().wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);
    }

    #[test]
    fn main_loop_removes_timed_out_connections() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        // make the connection timed out
        let cookie_request_id = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, cookie_request_id);
        let mut packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        packet.num_sent = MAX_NUM_SENDPACKET_TRIES;
        packet.sent_time -= CRYPTO_SEND_PACKET_INTERVAL + Duration::from_secs(1);
        connection.status = ConnectionStatus::CookieRequesting {
            cookie_request_id,
            packet
        };

        assert!(connection.is_timed_out());

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().wait().unwrap();

        assert!(net_crypto.connections.read().is_empty());
        assert!(net_crypto.keys_by_addr.read().is_empty());
    }

    #[test]
    fn main_loop_sends_request_packets() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_REQUEST]);
    }

    #[test]
    fn main_loop_sends_requested_packets() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let now = Instant::now();

        connection.request_packet_sent_time = Some(now);

        let data = vec![42; 123];
        connection.packets_sent = 1;
        connection.send_array.buffer_end = 1;
        assert!(connection.send_array.insert(0, SentPacket {
            data: data.clone(),
            sent_time: now,
            requested: true,
        }).is_ok());

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, data);
    }

    #[test]
    fn send_status_packet_established() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key,
        };

        // send status packet with connection.status is Established
        net_crypto.send_status_packet(&mut connection).wait().unwrap();

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert!(udp_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn send_data_packet() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let mut sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_start = 23;
        connection.recv_array.buffer_end = 25;

        let data = vec![42; 123];
        net_crypto.send_data_packet(&mut connection, data.clone(), 7).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 23);
        assert_eq!(payload.packet_number, 7);
        assert_eq!(payload.data, data);

        increment_nonce(&mut sent_nonce);
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, sent_nonce), sent_nonce);
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);
    }

    #[test]
    fn send_request_packet() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_end = 270;
        assert!(connection.recv_array.insert(2, RecvPacket {
            data: vec![42; 123],
        }).is_ok());
        for i in 5 .. 269 {
            assert!(connection.recv_array.insert(i, RecvPacket {
                data: vec![42; 123],
            }).is_ok());
        }

        let now = Instant::now() + Duration::from_secs(1);
        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(now));

        with_default(&clock, &mut enter, |_| {
            net_crypto.send_request_packet(&mut connection).wait().unwrap();
        });

        assert_eq!(connection.request_packet_sent_time, Some(now));

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_REQUEST, 1, 1, 2, 1, 0, 10]);
    }

    #[test]
    fn send_request_packet_too_many_missing_packets() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_end = MAX_CRYPTO_DATA_SIZE as u32 + 42;

        net_crypto.send_request_packet(&mut connection).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data.len(), MAX_CRYPTO_DATA_SIZE);
    }

    #[test]
    fn send_requested_packets() {
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key,
        };

        let now = Instant::now();
        connection.send_array.buffer_end = 7;
        assert!(connection.send_array.insert(2, SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: true,
        }).is_ok());
        assert!(connection.send_array.insert(4, SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: false,
        }).is_ok());
        assert!(connection.send_array.insert(5, SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: true,
        }).is_ok());

        let next_now = now + Duration::from_secs(1);
        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(next_now));

        with_default(&clock, &mut enter, |_| {
            net_crypto.send_requested_packets(&mut connection).wait().unwrap();
        });

        assert!(!connection.send_array.get(2).unwrap().requested);
        assert!(!connection.send_array.get(4).unwrap().requested);
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert_eq!(connection.send_array.get(2).unwrap().sent_time, next_now);
        assert_eq!(connection.send_array.get(4).unwrap().sent_time, now);
        assert_eq!(connection.send_array.get(5).unwrap().sent_time, next_now);

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert_eq!(udp_rx.collect().wait().unwrap().len(), 2);
    }

    #[test]
    fn send_lossless() {
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let connection = Arc::new(RwLock::new(connection));
        net_crypto.connections.write().insert(peer_real_pk, connection.clone());
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let data = vec![16, 42];

        net_crypto.send_lossless(peer_real_pk, data.clone()).wait().unwrap();

        let connection = connection.read();

        assert_eq!(connection.packets_sent, 1);

        // the packet should be added to send_array

        assert_eq!(connection.send_array.buffer[0].clone().unwrap().data, data);

        // the packet should be sent to node

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, data);
    }

    #[test]
    fn send_lossless_no_connection() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        let error = net_crypto.send_lossless(peer_real_pk, vec![16, 42]).wait().err().unwrap();
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::NoConnection);
    }

    #[test]
    fn send_lossless_invalid_packet_id() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        let error = net_crypto.send_lossless(peer_real_pk, vec![10, 42]).wait().err().unwrap();
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::InvalidPacketId);
    }

    #[test]
    fn add_connection() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk);

        let connections = net_crypto.connections.read();
        let connection = connections[&peer_real_pk].read();

        assert_eq!(connection.peer_real_pk, peer_real_pk);
        assert_eq!(connection.peer_dht_pk, peer_dht_pk);

        let status_packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        let cookie_request = unpack!(status_packet.dht_packet(), Packet::CookieRequest);
        let cookie_request_payload = cookie_request.get_payload(&precompute(&dht_pk, &peer_dht_sk)).unwrap();

        assert_eq!(cookie_request_payload.pk, real_pk);
    }

    #[test]
    fn add_connection_already_exists() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk);

        // adding a friend that already exists won't do anything
        let (another_peer_dht_pk, _another_peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, another_peer_dht_pk);

        let connections = net_crypto.connections.read();
        let connection = connections[&peer_real_pk].read();

        assert_eq!(connection.peer_real_pk, peer_real_pk);
        assert_eq!(connection.peer_dht_pk, peer_dht_pk);
    }

    #[test]
    fn set_friend_udp_addr() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk);

        let addr_v4 = "127.0.0.1:12345".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr_v4);
        let addr_v6 = "[::]:12345".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr_v6);

        let connections = net_crypto.connections.read();
        let connection = connections[&peer_real_pk].read();

        assert_eq!(connection.get_udp_addr_v4(), Some(addr_v4));
        assert_eq!(connection.get_udp_addr_v6(), Some(addr_v6));
        assert_eq!(net_crypto.keys_by_addr.read()[&(addr_v4.ip(), addr_v4.port())], peer_real_pk);
        assert_eq!(net_crypto.keys_by_addr.read()[&(addr_v6.ip(), addr_v6.port())], peer_real_pk);
    }

    #[test]
    fn set_friend_udp_addr_update() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);
        // setting the same address won't do anything
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let addr = "127.0.0.1:12346".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let connections = net_crypto.connections.read();
        let connection = connections[&peer_real_pk].read();

        assert_eq!(connection.get_udp_addr_v4(), Some(addr));

        let keys_by_addr = net_crypto.keys_by_addr.read();
        assert_eq!(keys_by_addr[&(addr.ip(), addr.port())], peer_real_pk);
        assert_eq!(keys_by_addr.len(), 1);
    }

    #[test]
    fn set_friend_udp_addr_no_connection() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let addr = "127.0.0.1:12345".parse().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        // setting an address to nonexistent connection won't do anything
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        assert!(net_crypto.keys_by_addr.read().is_empty());
    }

    #[test]
    fn kill_connection() {
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.kill_connection(peer_real_pk).wait().unwrap();

        assert!(!net_crypto.connections.read().contains_key(&peer_real_pk));
        assert!(!net_crypto.keys_by_addr.read().contains_key(&(addr.ip(), addr.port())));

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_KILL]);
    }

    #[test]
    fn kill_connection_no_connection() {
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        let error = net_crypto.kill_connection(peer_real_pk).wait().err().unwrap();
        assert_eq!(*error.kind(), KillConnectionErrorKind::NoConnection);
    }

    #[test]
    fn kill_connection_not_established() {
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.kill_connection(peer_real_pk).wait().unwrap();

        assert!(!net_crypto.connections.read().contains_key(&peer_real_pk));
        assert!(!net_crypto.keys_by_addr.read().contains_key(&(addr.ip(), addr.port())));

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert!(udp_rx.collect().wait().unwrap().is_empty());
    }
}
