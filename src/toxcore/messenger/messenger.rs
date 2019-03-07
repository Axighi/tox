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

            let ft = friend.files_receiving.read();
            if let Some(ft) = ft.get(file_id as usize) {
                if let Some(ft) = ft {
                    if ft.status != TransferStatus::NotAccepted {
                        return Either::A(future::err(SendPacketErrorKind::NotAccepted.into()))
                    }
                    if position >= ft.size {
                        return Either::A(future::err(SendPacketErrorKind::LargerPosition.into()))
                    }
                    let mut ft_c = ft.clone();
                    let future = self.send_file_control_packet(friend.pk, TransferDirection::Receive, file_id, ControlType::Seek(position))
                        .and_then(move |_| {
                            ft_c.transferred = position;
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
        let friend = self.friends_list.read();
        if let Some(friend) = friend.get(&friend_pk) {
            if friend.status != FriendStatus::Online {
                return Either::A(future::err(SendPacketErrorKind::NotOnline.into()))
            }

            let ft = if dir == TransferDirection::Send {
                friend.files_sending.read()
            } else {
                friend.files_receiving.read()
            };

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

                    let mut friend_c = friend.clone();
                    let mut ft_c = ft.clone();

                    let future = self.send_file_control_packet(friend.pk, dir, file_id, control)
                        .and_then(move |_| {
                            if control == ControlType::Kill {
                                if dir == TransferDirection::Send {
                                    friend_c.num_sending_files = friend_c.num_sending_files.sub(1);
                                    friend_c.files_sending.write()[file_id as usize] = None;
                                } else {
                                    friend_c.files_receiving.write()[file_id as usize] = None;
                                }
                            } else if control == ControlType::Pause {
                                ft_c.pause = ft_c.pause | PauseStatus::US;
                            } else if control == ControlType::Accept {
                                ft_c.status = TransferStatus::Transferring;
                                if ft_c.pause & PauseStatus::US == PauseStatus::US {
                                    ft_c.pause = ft_c.pause ^ PauseStatus::US;
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
        self.send_file_control(friend_pk, file_id, transfer_direction, control_type)
            .map_err(|e| RecvPacketError::from(e))
    }

    /// Handle file control request packet
    pub fn handle_file_control(&self, friend_pk: PublicKey, packet: FileControl)
                           -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let mut friend = self.friends_list.write();
        let friend = friend.get_mut(&friend_pk);
        if let Some(friend) = friend {
            let mut ft = if packet.transfer_direction == TransferDirection::Send {
                friend.files_sending.write()
            } else {
                friend.files_receiving.write()
            };

            if let Some(ft) = ft.get_mut(packet.file_id as usize) {
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
                            friend.files_receiving.write()[packet.file_id as usize] = None;
                        } else {
                            friend.files_sending.write()[packet.file_id as usize] = None;
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
                    Either::B(self.send_req_kill(friend_pk, packet.file_id, packet.transfer_direction.toggle(), packet.control_type))
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
            let ft = friend.files_receiving.write();
            if let Some(ft) = ft.get(packet.file_id as usize) {
                if let Some(_ft) = ft {
                    Either::B(future::err(RecvPacketErrorKind::AlreadyExist.into()))
                } else {
                    let mut ft = FileTransfers::new();

                    ft.status = TransferStatus::NotAccepted;
                    ft.size = packet.file_size;
                    ft.transferred = 0;
                    ft.pause = PauseStatus::FT_NONE;

                    friend.files_receiving.write()[packet.file_id as usize] = Some(ft);

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
            let mut ft = friend.files_receiving.write();
            if let Some(ft) = ft.get_mut(packet.file_id as usize) {
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
                        friend.files_receiving.write()[packet.file_id as usize] = None;
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
