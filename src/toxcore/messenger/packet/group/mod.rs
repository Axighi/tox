/*! The implementation of group chat packets.
*/

mod invite;

pub use self::invite::*;

use nom::be_u8;
use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Length of group chat unique bytes
pub const GROUP_UID_BYTES: usize = 32;

/// Unique id used in group chat
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupUID([u8; GROUP_UID_BYTES]);

impl GroupUID {
    /// Create new object
    pub fn random() -> GroupUID {
        let mut array = [0; GROUP_UID_BYTES];
        randombytes_into(&mut array);
        GroupUID(array)
    }

    /// Custom from_slice function of GroupUID
    pub fn from_slice(bs: &[u8]) -> Option<GroupUID> {
        if bs.len() != GROUP_UID_BYTES {
            return None
        }
        let mut n = GroupUID([0; GROUP_UID_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for GroupUID {
    named!(from_bytes<GroupUID>, map_opt!(take!(GROUP_UID_BYTES), GroupUID::from_slice));
}

/// Type of group chat
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupType {
    /// Text group conference.
    Text = 0x00,
    /// Audio group conference.
    Audio,
}

impl FromBytes for GroupType {
    named!(from_bytes<GroupType>,
        switch!(be_u8,
            0 => value!(GroupType::Text) |
            1 => value!(GroupType::Audio)
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_uid_from_bytes() {
        let mut array = [0; GROUP_UID_BYTES];
        randombytes_into(&mut array);
        let (_, guid) = GroupUID::from_bytes(&array).unwrap();
        assert_eq!(GroupUID(array), guid);
    }

    #[test]
    fn group_type_from_bytes() {
        let raw = [0];
        let (_, group_type) = GroupType::from_bytes(&raw).unwrap();
        assert_eq!(GroupType::Text, group_type);
    }
}
