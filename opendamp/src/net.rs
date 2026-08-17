//! Network parameters: Sequentia testnet and elementsregtest.

use std::str::FromStr;

use simplicityhl::elements::bitcoin::bech32::Hrp;
use simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;
use simplicityhl::elements::{AddressParams, BlockHash};

/// BIP341 nothing-up-my-sleeve internal key; neither covenant has a key path.
pub const NUMS_HEX: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub fn nums_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str(NUMS_HEX).expect("valid NUMS key")
}

/// Sequentia testnet: unblinded addresses are deliberately identical in format
/// to Bitcoin's ("tb"), confidential addresses use the distinct "tsqb" HRP.
pub static SEQ_TESTNET_ADDRESS_PARAMS: AddressParams = AddressParams {
    p2pkh_prefix: 235,
    p2sh_prefix: 75,
    blinded_prefix: 4,
    bech_hrp: Hrp::parse_unchecked("tb"),
    blech_hrp: Hrp::parse_unchecked("tsqb"),
};

/// The `elementsregtest` chain the functional test suite runs on. Sequentia
/// custom chains keep the Elements defaults for address encoding.
pub static ELEMENTS_REGTEST_ADDRESS_PARAMS: AddressParams = AddressParams {
    p2pkh_prefix: 235,
    p2sh_prefix: 75,
    blinded_prefix: 4,
    bech_hrp: Hrp::parse_unchecked("ert"),
    blech_hrp: Hrp::parse_unchecked("el"),
};

/// Genesis hash of the live Sequentia testnet (re-genesis of 2026-07-05).
pub const SEQ_TESTNET_GENESIS: &str =
    "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e";

/// Everything the covenant machinery needs to know about the chain: an
/// Elements sighash commits to the genesis hash, so a witness built against
/// the wrong chain simply will not verify.
#[derive(Clone, Copy)]
pub struct Net {
    pub address_params: &'static AddressParams,
    pub genesis: BlockHash,
}

impl Net {
    pub fn testnet() -> Self {
        Net {
            address_params: &SEQ_TESTNET_ADDRESS_PARAMS,
            genesis: BlockHash::from_str(SEQ_TESTNET_GENESIS).expect("genesis"),
        }
    }

    /// elementsregtest: the genesis hash depends on the node's configuration,
    /// so the caller must supply it (`getblockhash 0`).
    pub fn regtest(genesis: BlockHash) -> Self {
        Net {
            address_params: &ELEMENTS_REGTEST_ADDRESS_PARAMS,
            genesis,
        }
    }

    pub fn from_name(name: &str, genesis: Option<&str>) -> Result<Self, String> {
        match name {
            "testnet" => Ok(Self::testnet()),
            "regtest" | "elementsregtest" => {
                let g = genesis.ok_or("regtest requires --genesis <hash>")?;
                let g = BlockHash::from_str(g).map_err(|e| format!("bad genesis hash: {e}"))?;
                Ok(Self::regtest(g))
            }
            other => Err(format!("unknown network {other} (use testnet|regtest)")),
        }
    }
}
