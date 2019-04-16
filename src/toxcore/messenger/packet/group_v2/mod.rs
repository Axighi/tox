/*! Group chat version 2 packets
*/

use crate::toxcore::binary_io::*;

mod status;
mod nickname_v2;
mod message_v2;
mod action_v2;
mod private_message;
mod peer_exit;
mod remove_peer;
mod remove_ban;

pub use self::status::*;
pub use self::nickname_v2::*;
pub use self::message_v2::*;
pub use self::action_v2::*;
pub use self::private_message::*;
pub use self::peer_exit::*;
pub use self::remove_peer::*;
pub use self::remove_ban::*;

/// Maximum size in bytes of action string of message packet
pub const MAX_MESSAGE_V2_DATA_SIZE: usize = 1289;


/** Group chat version 2 packet enum that encapsulates all types of group chat v2 packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`Status`](./struct.Status.html) structure.
    Status(Status),
    /// [`NicknameV2`](./struct.NicknameV2.html) structure.
    NicknameV2(NicknameV2),
    /// [`MessageV2`](./struct.MessageV2.html) structure.
    MessageV2(MessageV2),
    /// [`ActionV2`](./struct.ActionV2.html) structure.
    ActionV2(ActionV2),
    /// [`PrivateMessage`](./struct.PrivateMessage.html) structure.
    PrivateMessage(PrivateMessage),
    /// [`PeerExit`](./struct.PeerExit.html) structure.
    PeerExit(PeerExit),
    /// [`RemovePeer`](./struct.RemovePeer.html) structure.
    RemovePeer(RemovePeer),
    /// [`RemoveBan`](./struct.RemoveBan.html) structure.
    RemoveBan(RemoveBan),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Status(ref p) => p.to_bytes(buf),
            Packet::NicknameV2(ref p) => p.to_bytes(buf),
            Packet::MessageV2(ref p) => p.to_bytes(buf),
            Packet::ActionV2(ref p) => p.to_bytes(buf),
            Packet::PrivateMessage(ref p) => p.to_bytes(buf),
            Packet::PeerExit(ref p) => p.to_bytes(buf),
            Packet::RemovePeer(ref p) => p.to_bytes(buf),
            Packet::RemoveBan(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Status::from_bytes, Packet::Status) |
        map!(NicknameV2::from_bytes, Packet::NicknameV2) |
        map!(MessageV2::from_bytes, Packet::MessageV2) |
        map!(ActionV2::from_bytes, Packet::ActionV2) |
        map!(PrivateMessage::from_bytes, Packet::PrivateMessage) |
        map!(PeerExit::from_bytes, Packet::PeerExit) |
        map!(RemovePeer::from_bytes, Packet::RemovePeer) |
        map!(RemoveBan::from_bytes, Packet::RemoveBan)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::crypto_core::*;
    use crate::toxcore::ip_port::*;

    encode_decode_test!(
        packet_status_encode_decode,
        Packet::Status(Status::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, PeerStatusV2::GsAway))
    );

    encode_decode_test!(
        packet_nickname_v2_encode_decode,
        Packet::NicknameV2(NicknameV2::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_message_v2_encode_decode,
        Packet::MessageV2(MessageV2::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_action_v2_encode_decode,
        Packet::ActionV2(ActionV2::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_private_message_encode_decode,
        Packet::PrivateMessage(PrivateMessage::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_peer_exit_encode_decode,
        Packet::PeerExit(PeerExit::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4))
    );

    encode_decode_test!(
        packet_remove_peer_encode_decode,
        Packet::RemovePeer(RemovePeer::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, EventV2::Ban, gen_keypair().0, vec![
            Sanction(SanctionType::BanIpPort(
                BanIpPort::new(
                    gen_keypair().0, 1, 2, IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap())
                )
            )),
            Sanction(SanctionType::BanPublicKey(
                BanPublicKey::new(gen_keypair().0, 3, 4, gen_keypair().0
                )
            )),
            Sanction(SanctionType::BanNickname(
                BanNickname::new(gen_keypair().0, 5, 6, String::from_utf8([32; 128].to_vec()).unwrap()
                )
            )),
            Sanction(SanctionType::Observer(
                Observer::new(gen_keypair().0, 7, gen_keypair().0
                )
            ))
        ]))
    );

    encode_decode_test!(
        packet_remove_ban_encode_decode,
        Packet::RemoveBan(RemoveBan::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, 5,
            vec![
                Sanction(SanctionType::BanIpPort(
                    BanIpPort::new(
                        gen_keypair().0, 1, 2, IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap())
                    )
                ))]
            )
        )
    );
}