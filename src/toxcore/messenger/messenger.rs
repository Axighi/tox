/*! The temporary friends and messenger module for waiting completion of friends module.
*/

use std::collections::HashMap;
use std::sync::Arc;
use std::ops::{Add, Sub};

use futures::{future, Future};
use futures::future::Either;
use futures::sync::mpsc::*;
use parking_lot::RwLock;
use bitflags::*;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::net_crypto::*;
use crate::toxcore::state_format::old::*;
use crate::toxcore::messenger::packet::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::dht::packet::crypto_data::MAX_CRYPTO_DATA_SIZE;
use crate::toxcore::messenger::errors::*;
use crate::toxcore::messenger::packet::file_data::MAX_FILE_DATA_SIZE;

/// Because `file_id` is `u8` this const can not be larger than 256.
const MAX_CONCURRENT_FILE_PIPES: u32 = 256;

/// File transferring status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferStatus {
    /// Not accepted
    NotAccepted,
    /// Transferring
    Transferring,
    /// Finished
    Finished,
}

bitflags! {
    /// File transferring pause status
    pub struct PauseStatus: u8 {
        /// Not paused
        const FT_NONE = 0;
        /// Paused by us
        const US = 1;
        /// Paused by other
        const OTHER = 2;
        /// Paused by both
        const BOTH = 3;
    }
}

/** File sending

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTransfers {
    /// Size in bytes of a file to transfer.
    pub size: u64,
    /// Size in bytes of a file already transferred.
    pub transferred: u64,
    /// Status of transferring
    pub status: TransferStatus,
    /// Status of pausing
    pub pause: PauseStatus,
    /// Number of last packet sent.
    pub last_packet_number: u32,
    /// Data requested by the request chunk callback.
    pub requested: u64,
    /// Unique file id for this transfer
    pub unique_id: FileUID,
}

impl FileTransfers {
    /// Make new FileTransfers object
    pub fn new() -> Self {
        FileTransfers {
            size: 0,
            transferred: 0,
            status: TransferStatus::NotAccepted,
            pause: PauseStatus::FT_NONE,
            last_packet_number: 0,
            requested: 0,
            unique_id: FileUID::new(),
        }
    }
}

/// Temporary friend object
#[derive(Clone)]
pub struct Friend {
    /// PublicKey of friend.
    pub pk: PublicKey,
    /// Number of files sending.
    pub num_sending_files: u8,
    /// File transfer object for sending.
    pub files_sending: Arc<RwLock<Vec<Option<FileTransfers>>>>,
    /// File transfer object for receiving.
    pub files_receiving: Arc<RwLock<Vec<Option<FileTransfers>>>>,
    /// Status of friend.
    pub status: FriendStatus,
}

impl Friend {
    /// Create new object
    pub fn new(pk: PublicKey) -> Self {
        Friend {
            pk,
            num_sending_files: 0,
            files_sending: Arc::new(RwLock::new(vec![None; MAX_CONCURRENT_FILE_PIPES as usize])),
            files_receiving: Arc::new(RwLock::new(vec![None; MAX_CONCURRENT_FILE_PIPES as usize])),
            status: FriendStatus::Online, // its status is for temporary to provide convenience
        }
    }
}

/// Messenger object
#[derive(Clone)]
pub struct Messenger {
    /// List of friends
    friends_list: Arc<RwLock<HashMap<PublicKey, Friend>>>,
    /// NetCrypto object
    net_crypto: Option<NetCrypto>,
    /// Sink for file control packets
    recv_file_control_tx: Option<UnboundedSender<(PublicKey, Packet)>>,
    /// Sink for file data packts, `u64` is for file position.
    recv_file_data_tx: Option<Sender<(PublicKey, Packet, u64)>>,
}

impl Messenger {
    /// Create new messenger object
    pub fn new() -> Self {
        Messenger {
            friends_list: Arc::new(RwLock::new(HashMap::new())),
            net_crypto: None,
            recv_file_control_tx: None,
            recv_file_data_tx: None,
        }
    }

    /// Set net_crypto object.
    pub fn set_net_crypto(&mut self, net_cryto: NetCrypto) {
        self.net_crypto = Some(net_cryto);
    }

    /// Set tx for receiver's file control packet.
    pub fn set_tx_file_control(&mut self, tx: UnboundedSender<(PublicKey, Packet)>) {
        self.recv_file_control_tx = Some(tx);
    }

    /// Set tx for receiver's file data pacekt.
    pub fn set_tx_file_data(&mut self, tx: Sender<(PublicKey, Packet, u64)>) {
        self.recv_file_data_tx = Some(tx);
    }

    /// Send file control request.
    fn send_file_control_packet(&self, pk: PublicKey, dir: TransferDirection, file_id: u8, control: ControlType)
                                -> impl Future<Item=(), Error=SendPacketError> + Send {
        if let Some(net_crypto) = &self.net_crypto {
            let packet = FileControl::new(dir, file_id, control);
            let mut buf = [0; MAX_CRYPTO_DATA_SIZE];
        match packet.to_bytes((&mut buf, 0)) {
                Ok((data, size)) => Either::A(net_crypto.send_lossless(pk, data[..size].to_vec())
                    .map_err(|e| SendPacketError::from(e))),
                Err(e) => Either::B(future::err(SendPacketError::serialize(e))),
            }
        } else {
            Either::B(future::err(SendPacketErrorKind::NoNetCrypto.into()))
        }
    }

    /// Issue seek file control request
    pub fn send_file_seek(&self, friend_pk: PublicKey, file_id: u8, position: u64) -> impl Future<Item=(), Error=SendPacketError> + Send {
        let friend = self.friends_list.read();
        if let Some(friend) = friend.get(&friend_pk) {
            if friend.status != FriendStatus::Online {
                return Either::A(future::err(SendPacketErrorKind::NotOnline.into()))
            }

            let file_receive = friend.files_receiving.clone();
            let ft = file_receive.read();
            if let Some(ft) = ft.get(file_id as usize) {
                if let Some(ft) = ft {
                    if ft.status != TransferStatus::NotAccepted {
                        return Either::A(future::err(SendPacketErrorKind::NotAccepted.into()))
                    }
                    if position >= ft.size {
                        return Either::A(future::err(SendPacketErrorKind::LargerPosition.into()))
                    }
                    let mut ft_c = ft.clone();
                    let file_receive_c = file_receive.clone();
                    let future = self.send_file_control_packet(friend.pk, TransferDirection::Receive, file_id, ControlType::Seek(position))
                        .and_then(move |_| {
                            ft_c.transferred = position;
                            file_receive_c.write()[file_id as usize] = Some(ft_c);
                            future::ok(())
                        });
                    Either::B(future)
                } else {
                    Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
                }
            } else {
                Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::A(future::err(SendPacketErrorKind::NoFriend.into()))
        }
    }

    /// Issue file control request.
    pub fn send_file_control(&self, friend_pk: PublicKey, file_id: u8, dir: TransferDirection, control: ControlType)
                             -> impl Future<Item=(), Error=SendPacketError> + Send {
        let friend_list = self.friends_list.clone();
        let friend_read = friend_list.read();
        if let Some(friend) = friend_read.get(&friend_pk) {
            if friend.status != FriendStatus::Online {
                return Either::A(future::err(SendPacketErrorKind::NotOnline.into()))
            }

            let files = if dir == TransferDirection::Send {
                friend.files_sending.clone()
            } else {
                friend.files_receiving.clone()
            };

            let ft = files.read();
            if let Some(ft) = ft.get(file_id as usize) {
                if let Some(ft) = ft {
                    if control == ControlType::Pause && (ft.pause & PauseStatus::US == PauseStatus::US || ft.status != TransferStatus::Transferring) {
                        return Either::A(future::err(SendPacketErrorKind::InvalidRequest.into()))
                    }

                    if control == ControlType::Accept {
                        if ft.status == TransferStatus::Transferring {
                            if !(ft.pause & PauseStatus::US == PauseStatus::US) {
                                if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                                    return Either::A(future::err(SendPacketErrorKind::InvalidRequest2.into()))
                                }
                                return Either::A(future::err(SendPacketErrorKind::InvalidRequest3.into()))
                            }
                        } else {
                            if ft.status != TransferStatus::NotAccepted {
                                return Either::A(future::err(SendPacketErrorKind::InvalidRequest4.into()))
                            }
                            if dir == TransferDirection::Send {
                                return Either::A(future::err(SendPacketErrorKind::InvalidRequest5.into()))
                            }
                        }
                    }

                    let friend_list_c = friend_list.clone();
                    let files_c = files.clone();
                    let mut ft_c = ft.clone();

                    let future = self.send_file_control_packet(friend.pk, dir, file_id, control)
                        .and_then(move |_| {
                            let mut friend_list_c = friend_list_c.write();
                            let friend = friend_list_c.get_mut(&friend_pk).unwrap();
                            if control == ControlType::Kill {
                                if dir == TransferDirection::Send {
                                    friend.num_sending_files = friend.num_sending_files.sub(1);
                                    friend.files_sending.write()[file_id as usize] = None;
                                } else {
                                    friend.files_receiving.write()[file_id as usize] = None;
                                }
                            } else if control == ControlType::Pause {
                                ft_c.pause = ft_c.pause | PauseStatus::US;
                                files_c.write()[file_id as usize] = Some(ft_c);
                            } else if control == ControlType::Accept {
                                ft_c.status = TransferStatus::Transferring;
                                files_c.write()[file_id as usize] = Some(ft_c.clone());
                                if ft_c.pause & PauseStatus::US == PauseStatus::US {
                                    ft_c.pause = ft_c.pause ^ PauseStatus::US;
                                    files_c.write()[file_id as usize] = Some(ft_c);
                                }
                            }
                            future::ok(())
                        });
                    Either::B(future)
                } else {
                    Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
                }
            } else {
                Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::A(future::err(SendPacketErrorKind::NoFriend.into()))
        }
    }

    fn recv_from(&self, friend_pk: PublicKey, packet: Packet) -> impl Future<Item=(), Error=RecvPacketError> + Send {
        if let Some(tx) = self.recv_file_control_tx.clone() {
            Either::A(send_to(&tx, (friend_pk, packet))
                .map_err(|e| RecvPacketError::from(e)))
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoSink.into()))
        }
    }

    fn recv_from_data(&self, friend_pk: PublicKey, packet: Packet, position: u64) -> impl Future<Item=(), Error=RecvPacketError> + Send {
        if let Some(tx) = self.recv_file_data_tx.clone() {
            Either::A(send_to(&tx, (friend_pk, packet, position))
                .map_err(|e| RecvPacketError::from(e)))
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoDataSink.into()))
        }
    }

    fn send_req_kill(&self, friend_pk: PublicKey, file_id: u8, transfer_direction: TransferDirection, control_type: ControlType)
                     -> impl Future<Item=(), Error=RecvPacketError> + Send {
        self.send_file_control_packet(friend_pk, transfer_direction, file_id, control_type)
            .map_err(|e| RecvPacketError::from(e))
    }

    /// Handle file control request packet
    pub fn handle_file_control(&self, friend_pk: PublicKey, packet: FileControl)
                           -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let mut friend = self.friends_list.write();
        let friend = friend.get_mut(&friend_pk);
        if let Some(friend) = friend {
            let mut ft_write = if packet.transfer_direction == TransferDirection::Send {
                friend.files_sending.write()
            } else {
                friend.files_receiving.write()
            };

            if let Some(ft) = ft_write.get_mut(packet.file_id as usize) {
                let future = if let Some(ft) = ft {
                    let up_packet = Packet::FileControl(packet.clone());

                    if packet.control_type == ControlType::Accept {
                        if packet.transfer_direction == TransferDirection::Receive && ft.status == TransferStatus::NotAccepted {
                            ft.status = TransferStatus::Transferring;
                        } else {
                            if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                                ft.pause = ft.pause ^ PauseStatus::OTHER;
                            } else {
                                warn!("file control (friend {:?}, file {}): friend told us to resume file transfer that wasn't paused", friend_pk, packet.file_id);
                                return Either::B(future::err(RecvPacketError::invalid_request(friend_pk, packet.file_id)))
                            }
                        }
                    } else if packet.control_type == ControlType::Pause {
                        if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER || ft.status != TransferStatus::Transferring {
                            warn!("file control (friend {:?}, file {}): friend told us to pause file transfer that is already paused", friend_pk, packet.file_id);
                            return Either::B(future::err(RecvPacketError::invalid_request(friend_pk, packet.file_id)))
                        }

                        ft.pause = ft.pause | PauseStatus::OTHER;
                    } else if packet.control_type == ControlType::Kill {
                        if packet.transfer_direction == TransferDirection::Receive {
                            friend.num_sending_files = friend.num_sending_files.sub(1);
                            ft_write[packet.file_id as usize] = None;
                        } else {
                            ft_write[packet.file_id as usize] = None;
                        }
                    } else if let ControlType::Seek(position) = packet.control_type {
                        if ft.status != TransferStatus::NotAccepted || packet.transfer_direction == TransferDirection::Send {
                            warn!("file control (friend {:?}, file {}): seek was either sent by a sender or by the receiver after accepting", friend_pk, packet.file_id);
                            return Either::B(future::err(RecvPacketError::invalid_request(friend_pk, packet.file_id)))
                        }
                        if position >= ft.size {
                            warn!("file control (friend {:?}, file {}): seek position {} exceeds file size {}", friend_pk, packet.file_id, position, ft.size);
                            return Either::B(future::err(RecvPacketError::exceed_size(friend_pk, packet.file_id, ft.size)))
                        }
                        ft.requested = position;
                        ft.transferred = position;
                    } else { // unknown file control
                        return Either::B(future::err(RecvPacketErrorKind::UnknownControlType.into()))
                    }

                    Either::A(self.recv_from(friend.pk, up_packet))
                } else { // File transfer don't exist; telling the other to kill it
                    warn!("file control (friend {:?}, file {}): file transfer does not exist; telling the other to kill it", friend_pk, packet.file_id);
                    Either::B(self.send_req_kill(friend_pk, packet.file_id, packet.transfer_direction.toggle(), ControlType::Kill))
                };
                Either::A(future)
            } else {
                Either::B(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoFriend.into()))
        }
    }

    /// Handle file send request packet
    pub fn handle_file_send_request(&self, friend_pk: PublicKey, packet: FileSendRequest)
                                -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let friend = self.friends_list.read();
        if let Some(friend) = friend.get(&friend_pk) {
            let mut ft_write = friend.files_receiving.write();
            if let Some(ft) = ft_write.get(packet.file_id as usize) {
                if let Some(_ft) = ft {
                    Either::B(future::err(RecvPacketErrorKind::AlreadyExist.into()))
                } else {
                    let mut ft = FileTransfers::new();

                    ft.status = TransferStatus::NotAccepted;
                    ft.size = packet.file_size;
                    ft.transferred = 0;
                    ft.pause = PauseStatus::FT_NONE;

                    ft_write[packet.file_id as usize] = Some(ft);

                    Either::A(self.recv_from(friend.pk, Packet::FileSendRequest(packet)))
                }
            } else {
                Either::B(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoFriend.into()))
        }
    }

    /// Handle file data packet
    pub fn handle_file_data(&self, friend_pk: PublicKey, packet: FileData)
                        -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let mut packet = packet;
        let friend = self.friends_list.read();
        if let Some(friend) = friend.get(&friend_pk) {
            let mut ft_write = friend.files_receiving.write();
            if let Some(ft) = ft_write.get_mut(packet.file_id as usize) {
                if let Some(ft) = ft {
                    if ft.status != TransferStatus::Transferring {
                        return Either::A(future::err(RecvPacketErrorKind::NotTransferring.into()))
                    }

                    let mut data_len = packet.data.len() as u64;
                    let position = ft.transferred;

                    // Prevent more data than the filesize from being passed to clients.
                    if ft.transferred + data_len > ft.size {
                        data_len = ft.size - ft.transferred;
                        packet.data.drain(..data_len as usize);
                    }

                    ft.transferred = ft.transferred.add(data_len);

                    let mut futures = Vec::new();
                    let up_packet = Packet::FileData(packet.clone());

                    futures.push(self.recv_from_data(friend.pk, up_packet, position));

                    if data_len > 0 && (ft.transferred >= ft.size || data_len != MAX_FILE_DATA_SIZE as u64) {
                        let packet = Packet::FileData(FileData::new(packet.file_id, Vec::new()));
                        futures.push(self.recv_from_data(friend.pk, packet, position));
                    }

                    if data_len == 0 {
                        ft_write[packet.file_id as usize] = None;
                    }

                    Either::B(future::join_all(futures).map(|_| ()))
                } else {
                    Either::A(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
                }
            } else {
                Either::A(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::A(future::err(RecvPacketErrorKind::NoFriend.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::dht::precomputed_cache::*;
    use crate::toxcore::dht::packet::{EncryptedCookie, CryptoHandshake, CryptoHandshakePayload};

    #[test]
    fn file_transfers_clonable() {
        let ft = FileTransfers::new();
        let _ft_c = ft.clone();
    }
    #[test]
    fn messenger_clonalble() {
        let ms = Messenger::new();
        let _ms_c = ms.clone();
    }
    #[test]
    fn messenger_set_net_crypto() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = channel(1);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let mut ms = Messenger::new();
        ms.set_net_crypto(net_crypto);
    }
    #[test]
    fn messenger_set_tx_file_control() {
        let (tx, _rx) = unbounded();
        let mut ms = Messenger::new();
        ms.set_tx_file_control(tx);
    }
    #[test]
    fn messenger_set_tx_file_data() {
        let (tx, _rx) = channel(2);
        let mut ms = Messenger::new();
        ms.set_tx_file_data(tx);
    }
    #[test]
    fn messenger_send_file_seek() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 0,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        ms.send_file_seek(peer_real_pk, 0, 5).wait().unwrap();
        assert_eq!(5, friend.files_receiving.read()[0].clone().unwrap().transferred);
    }
    #[test]
    fn messenger_send_file_seek_no_friend() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend_list = HashMap::new();

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_seek(peer_real_pk, 0, 5).wait().is_err());
    }
    #[test]
    fn messenger_send_file_seek_friend_not_online() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 0,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::NotFriend,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_seek(peer_real_pk, 0, 5).wait().is_err());
    }
    #[test]
    fn messenger_send_file_seek_no_file_transfer() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 0,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![None])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_seek(peer_real_pk, 0, 5).wait().is_err());
    }
    #[test]
    fn messenger_send_file_seek_transferring() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 0,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_seek(peer_real_pk, 0, 5).wait().is_err());
    }
    #[test]
    fn messenger_send_file_seek_position_exceed_size() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 1;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 0,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_seek(peer_real_pk, 0, 5).wait().is_err());
    }
    #[test]
    fn messenger_send_file_seek_no_net_crypto() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 0,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        assert!(ms.send_file_seek(peer_real_pk, 0, 5).wait().is_err());
    }
    #[test]
    fn messenger_send_file_control() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Kill).wait().unwrap();
        assert_eq!(None, friend.files_receiving.read()[0]);
    }
    #[test]
    fn messenger_send_file_control_kill_sending() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(vec![Some(ft)])),
            files_receiving: Arc::new(RwLock::new(Vec::new())),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        ms.send_file_control(peer_real_pk, 0, TransferDirection::Send, ControlType::Kill).wait().unwrap();
        let friend_list = ms.friends_list.read();
        let friend = friend_list.get(&peer_real_pk).unwrap();
        assert_eq!(None, friend.files_sending.read()[0]);
        assert_eq!(1, friend.num_sending_files);
    }
    #[test]
    fn messenger_send_file_control_pause() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Pause).wait().unwrap();
        assert_eq!(PauseStatus::US, friend.files_receiving.read()[0].clone().unwrap().pause);
    }
    #[test]
    fn messenger_send_file_control_accept() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        ft.pause = PauseStatus::US;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Accept).wait().unwrap();
        assert_eq!(PauseStatus::FT_NONE, friend.files_receiving.read()[0].clone().unwrap().pause);
        assert_eq!(TransferStatus::Transferring, friend.files_receiving.read()[0].clone().unwrap().status);
    }
    #[test]
    fn messenger_send_file_control_no_friend() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend_list = HashMap::new();

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Kill).wait().is_err());
    }
    #[test]
    fn messenger_send_file_control_no_file_transfer() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(Vec::new())),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Kill).wait().is_err());
    }
    #[test]
    fn messenger_send_file_control_invalid_request() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        ft.pause = PauseStatus::US;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Pause).wait().is_err());
    }
    #[test]
    fn messenger_send_file_control_invalid_request_2() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        ft.pause = PauseStatus::OTHER;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Accept).wait().is_err());
    }
    #[test]
    fn messenger_send_file_control_invalid_request_3() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        ft.pause = PauseStatus::FT_NONE;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Accept).wait().is_err());
    }
    #[test]
    fn messenger_send_file_control_invalid_request_4() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Finished;
        ft.size = 100;
        ft.pause = PauseStatus::BOTH;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_control(peer_real_pk, 0, TransferDirection::Receive, ControlType::Accept).wait().is_err());
    }
    #[test]
    fn messenger_send_file_control_invalid_request_5() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        ft.pause = PauseStatus::BOTH;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(vec![Some(ft.clone())])),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        assert!(ms.send_file_control(peer_real_pk, 0, TransferDirection::Send, ControlType::Accept).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_control_accept() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Accept);
        ms.handle_file_control(peer_real_pk, packet).wait().unwrap();
        assert_eq!(TransferStatus::Transferring, friend.files_receiving.read()[0].clone().unwrap().status);
    }
    #[test]
    fn messenger_handle_file_control_accept_pause() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        ft.pause = PauseStatus::OTHER;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Accept);
        ms.handle_file_control(peer_real_pk, packet).wait().unwrap();
        assert_eq!(PauseStatus::FT_NONE, friend.files_receiving.read()[0].clone().unwrap().pause);
    }
    #[test]
    fn messenger_handle_file_control_pause() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Pause);
        ms.handle_file_control(peer_real_pk, packet).wait().unwrap();
        assert_eq!(PauseStatus::OTHER, friend.files_receiving.read()[0].clone().unwrap().pause);
    }
    #[test]
    fn messenger_handle_file_control_kill_receive() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Kill);
        ms.handle_file_control(peer_real_pk, packet).wait().unwrap();
        let friend = ms.friends_list.read();
        let friend = friend.get(&peer_real_pk).unwrap();
        assert_eq!(1, friend.num_sending_files);
        assert_eq!(None, friend.files_receiving.read()[0]);
    }
    #[test]
    fn messenger_handle_file_control_kill_send() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(vec![Some(ft)])),
            files_receiving: Arc::new(RwLock::new(Vec::new())),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Send, 0, ControlType::Kill);
        ms.handle_file_control(peer_real_pk, packet).wait().unwrap();
        let friend = ms.friends_list.read();
        let friend = friend.get(&peer_real_pk).unwrap();
        assert_eq!(None, friend.files_sending.read()[0]);
    }
    #[test]
    fn messenger_handle_file_control_seek() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Seek(5));
        ms.handle_file_control(peer_real_pk, packet).wait().unwrap();
        let friend = ms.friends_list.read();
        let friend = friend.get(&peer_real_pk).unwrap();
        let ft = friend.files_receiving.read()[0].clone().unwrap();
        assert_eq!(5, ft.requested);
        assert_eq!(5, ft.transferred);
    }
    #[test]
    fn messenger_handle_file_control_seek_invalid_request() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Seek(5));
        assert!(ms.handle_file_control(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_control_seek_position_exceed_size() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 3;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Seek(5));
        assert!(ms.handle_file_control(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_control_no_file_transfer() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![None])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Seek(5));
        ms.handle_file_control(peer_real_pk, packet).wait().unwrap();
    }
    #[test]
    fn messenger_handle_file_control_no_file_transfer_2() {
        crypto_init().unwrap();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 1,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(Vec::new())),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let (udp_tx, _udp_rx) = channel(5);
        let (dht_pk_tx, _dht_pk_rx) = unbounded();
        let (lossless_tx, _lossless_rx) = unbounded();
        let (lossy_tx, _lossy_rx) = unbounded();
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
        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.add_connection(peer_real_pk, peer_dht_pk);
        net_crypto.set_friend_udp_addr(peer_real_pk, addr);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_encrypted_cookie = net_crypto.get_encrypted_cookie(peer_real_pk, peer_dht_pk);
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

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: Some(net_crypto),
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Seek(5));
        assert!(ms.handle_file_control(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_control_no_friend() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let friend_list = HashMap::new();

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileControl::new(TransferDirection::Receive, 0, ControlType::Seek(5));
        assert!(ms.handle_file_control(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_send_request() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![None])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileSendRequest::new(0, FileType::Data, 100, FileUID::new(), "1234".to_owned());
        ms.handle_file_send_request(peer_real_pk, packet).wait().unwrap();
        assert_eq!(TransferStatus::NotAccepted, friend.files_receiving.read()[0 as usize].clone().unwrap().status);
        assert_eq!(100, friend.files_receiving.read()[0 as usize].clone().unwrap().size);
    }
    #[test]
    fn messenger_handle_file_send_request_already_exist() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::NotAccepted;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileSendRequest::new(0, FileType::Data, 100, FileUID::new(), "1234".to_owned());
        assert!(ms.handle_file_send_request(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_send_request_no_file_transfer() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(Vec::new())),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileSendRequest::new(0, FileType::Data, 100, FileUID::new(), "1234".to_owned());
        assert!(ms.handle_file_send_request(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_send_request_no_friend() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);

        let friend_list = HashMap::new();

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileSendRequest::new(0, FileType::Data, 100, FileUID::new(), "1234".to_owned());
        assert!(ms.handle_file_send_request(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_data() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileData::new(0, vec![37; 10]);
        ms.handle_file_data(peer_real_pk, packet).wait().unwrap();
        assert_eq!(10, friend.files_receiving.read()[0].clone().unwrap().transferred);
    }
    #[test]
    fn messenger_handle_file_data_drain() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 10;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileData::new(0, vec![37; 20]);
        ms.handle_file_data(peer_real_pk, packet).wait().unwrap();
        assert_eq!(10, friend.files_receiving.read()[0].clone().unwrap().transferred);
    }
    #[test]
    fn messenger_handle_file_data_empty() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let mut ft = FileTransfers::new();
        ft.status = TransferStatus::Transferring;
        ft.size = 100;
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![Some(ft)])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileData::new(0, Vec::new());
        ms.handle_file_data(peer_real_pk, packet).wait().unwrap();
        assert_eq!(None, friend.files_receiving.read()[0].clone());
    }
    #[test]
    fn messenger_handle_file_no_file_transfer() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(vec![None])),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileData::new(0, vec![1,2,3,4]);
        assert!(ms.handle_file_data(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_no_file_transfer_2() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);
        let friend = Friend {
            pk: peer_real_pk,
            num_sending_files: 2,
            files_sending: Arc::new(RwLock::new(Vec::new())),
            files_receiving: Arc::new(RwLock::new(Vec::new())),
            status: FriendStatus::Online,
        };
        let mut friend_list = HashMap::new();
        let _friend = friend_list.insert(peer_real_pk, friend.clone());

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileData::new(0, vec![1,2,3,4]);
        assert!(ms.handle_file_data(peer_real_pk, packet).wait().is_err());
    }
    #[test]
    fn messenger_handle_file_no_friend() {
        crypto_init().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (control_tx, _rx) = unbounded();
        let (data_tx, _rx) = channel(5);

        let friend_list = HashMap::new();

        let ms = Messenger {
            friends_list: Arc::new(RwLock::new(friend_list)),
            recv_file_data_tx: Some(data_tx),
            recv_file_control_tx: Some(control_tx),
            net_crypto: None,
        };

        let packet = FileData::new(0, vec![1,2,3,4]);
        assert!(ms.handle_file_data(peer_real_pk, packet).wait().is_err());
    }
}
