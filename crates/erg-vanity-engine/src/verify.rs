//! Independent hit verification via ergo-lib.

use erg_vanity_address::Network;
use ergo_lib::ergotree_ir::chain::address::{Address, NetworkAddress, NetworkPrefix};
use ergo_lib::wallet::derivation_path::DerivationPath;
use ergo_lib::wallet::ext_secret_key::ExtSecretKey;
use ergo_lib::wallet::mnemonic::Mnemonic;
use std::str::FromStr;

use bip39::{Language, Mnemonic as Bip39Mnemonic};

/// Re-derive the address with ergo-lib and compare to the candidate.
pub fn verify_hit_ergo_lib(
    entropy: &[u8; 32],
    address_index: u32,
    address: &str,
    network: Network,
) -> bool {
    let Ok(mnemonic) = Bip39Mnemonic::from_entropy_in(Language::English, entropy) else {
        return false;
    };
    let seed = Mnemonic::to_seed(&mnemonic.to_string(), "");
    let Ok(master) = ExtSecretKey::derive_master(seed) else {
        return false;
    };
    let Ok(path) = DerivationPath::from_str(&format!("m/44'/429'/0'/0/{address_index}")) else {
        return false;
    };
    let Ok(derived) = master.derive(path) else {
        return false;
    };
    let Ok(pk) = derived.public_key() else {
        return false;
    };
    let prefix = match network {
        Network::Mainnet => NetworkPrefix::Mainnet,
        Network::Testnet => NetworkPrefix::Testnet,
    };
    let reference = NetworkAddress::new(prefix, &Address::from(pk)).to_base58();
    reference == address
}

#[cfg(test)]
mod tests {
    use super::*;
    use erg_vanity_cpu::generate_address_from_entropy;

    #[test]
    fn all_zero_entropy_verifies() {
        let entropy = [0u8; 32];
        let ours = generate_address_from_entropy(&entropy, Network::Mainnet).unwrap();
        assert!(verify_hit_ergo_lib(
            &entropy,
            0,
            &ours.address,
            Network::Mainnet
        ));
        assert!(!verify_hit_ergo_lib(
            &entropy,
            0,
            "9notanaddress",
            Network::Mainnet
        ));
    }
}
