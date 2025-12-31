//! Ergo network types.
//!
//! Network prefix is encoded in the address prefix byte.

#![forbid(unsafe_code)]

/// Ergo network type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Mainnet (prefix 0x00)
    Mainnet,
    /// Testnet (prefix 0x10)
    Testnet,
}

impl Network {
    /// Get the network prefix byte component.
    ///
    /// This is combined with the address type to form the full prefix byte.
    pub const fn prefix(self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            Self::Testnet => 0x10,
        }
    }
}

/// Ergo address types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-Public-Key (P2PK)
    P2PK,
    /// Pay-to-Script-Hash (P2SH)
    P2SH,
    /// Pay-to-Script (P2S)
    P2S,
}

impl AddressType {
    /// Get the address type byte component.
    pub const fn type_byte(self) -> u8 {
        match self {
            Self::P2PK => 0x01,
            Self::P2SH => 0x02,
            Self::P2S => 0x03,
        }
    }
}

/// Compute the full prefix byte from network and address type.
///
/// prefix_byte = network_prefix | address_type
pub const fn prefix_byte(network: Network, addr_type: AddressType) -> u8 {
    network.prefix() | addr_type.type_byte()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_p2pk_prefix() {
        // Mainnet P2PK = 0x00 | 0x01 = 0x01
        assert_eq!(prefix_byte(Network::Mainnet, AddressType::P2PK), 0x01);
    }

    #[test]
    fn test_testnet_p2pk_prefix() {
        // Testnet P2PK = 0x10 | 0x01 = 0x11
        assert_eq!(prefix_byte(Network::Testnet, AddressType::P2PK), 0x11);
    }

    #[test]
    fn test_mainnet_p2sh_prefix() {
        // Mainnet P2SH = 0x00 | 0x02 = 0x02
        assert_eq!(prefix_byte(Network::Mainnet, AddressType::P2SH), 0x02);
    }

    #[test]
    fn test_mainnet_p2s_prefix() {
        // Mainnet P2S = 0x00 | 0x03 = 0x03
        assert_eq!(prefix_byte(Network::Mainnet, AddressType::P2S), 0x03);
    }
}
