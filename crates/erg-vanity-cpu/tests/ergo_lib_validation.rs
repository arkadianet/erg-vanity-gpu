//! Validate our implementation against ergo-lib 0.28.0
//!
//! This is the critical correctness test - both implementations derive
//! from the SAME entropy independently. If they produce different addresses,
//! our implementation is wrong.

use std::str::FromStr;

use erg_vanity_address::Network;
use erg_vanity_cpu::generate_address_from_entropy;

use ergo_lib::ergotree_ir::chain::address::{Address, NetworkAddress, NetworkPrefix};
use ergo_lib::wallet::derivation_path::DerivationPath;
use ergo_lib::wallet::ext_secret_key::ExtSecretKey;
use ergo_lib::wallet::mnemonic::Mnemonic;

use bip39::{Language, Mnemonic as Bip39Mnemonic};

/// Derive address from entropy using bip39 crate + ergo-lib (reference implementations).
fn reference_addr_from_entropy(entropy: &[u8; 32], net: NetworkPrefix) -> String {
    // Use bip39 crate for entropy → mnemonic (independent of our implementation)
    let mnemonic = Bip39Mnemonic::from_entropy_in(Language::English, entropy).unwrap();
    let mnemonic_str = mnemonic.to_string();

    // Use ergo-lib for mnemonic → seed → master → derive → address
    let seed = Mnemonic::to_seed(&mnemonic_str, "");
    let master = ExtSecretKey::derive_master(seed).unwrap();

    let path = DerivationPath::from_str("m/44'/429'/0'/0/0").unwrap();
    let derived = master.derive(path).unwrap();

    let address = Address::from(derived.public_key().unwrap());
    NetworkAddress::new(net, &address).to_base58()
}

#[test]
fn test_abandon_entropy_matches_reference() {
    let entropy = [0u8; 32];

    let ours = generate_address_from_entropy(&entropy, Network::Mainnet).unwrap();
    let reference = reference_addr_from_entropy(&entropy, NetworkPrefix::Mainnet);

    assert_eq!(
        ours.address, reference,
        "Address mismatch!\n  Ours:      {}\n  Reference: {}",
        ours.address, reference
    );
}

#[test]
fn test_various_entropy_matches_reference() {
    let test_cases: &[[u8; 32]] = &[
        [0u8; 32],    // all zeros
        [0xffu8; 32], // all ones
        [0x01u8; 32], // all 0x01
        {
            let mut e = [0u8; 32];
            for i in 0..32 {
                e[i] = i as u8;
            }
            e
        }, // 0,1,2,3,...,31
    ];

    for entropy in test_cases {
        let ours = generate_address_from_entropy(entropy, Network::Mainnet).unwrap();
        let reference = reference_addr_from_entropy(entropy, NetworkPrefix::Mainnet);

        assert_eq!(
            ours.address, reference,
            "Address mismatch for entropy {:02x?}!\n  Ours:      {}\n  Reference: {}",
            &entropy[..4],
            ours.address,
            reference
        );
    }
}

#[test]
fn test_testnet_entropy_matches_reference() {
    let entropy = [0u8; 32];

    let ours = generate_address_from_entropy(&entropy, Network::Testnet).unwrap();
    let reference = reference_addr_from_entropy(&entropy, NetworkPrefix::Testnet);

    assert_eq!(
        ours.address, reference,
        "Testnet address mismatch!\n  Ours:      {}\n  Reference: {}",
        ours.address, reference
    );
}

/// Also validate that our mnemonic matches the bip39 crate output
#[test]
fn test_mnemonic_matches_bip39_crate() {
    let test_cases: &[[u8; 32]] = &[
        [0u8; 32],
        [0xffu8; 32],
        {
            let mut e = [0u8; 32];
            for i in 0..32 {
                e[i] = i as u8;
            }
            e
        },
    ];

    for entropy in test_cases {
        let ours = generate_address_from_entropy(entropy, Network::Mainnet).unwrap();
        let reference = Bip39Mnemonic::from_entropy_in(Language::English, entropy)
            .unwrap()
            .to_string();

        assert_eq!(
            ours.mnemonic, reference,
            "Mnemonic mismatch for entropy {:02x?}!\n  Ours:      {}\n  Reference: {}",
            &entropy[..4],
            ours.mnemonic,
            reference
        );
    }
}
