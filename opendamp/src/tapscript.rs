//! Taproot construction for the two OpenDAMP covenants.
//!
//! Both are P2TR outputs with the BIP341 NUMS internal key (no key path) and
//! Simplicity leaves at tapleaf version 0xbe, using the Elements tagged-hash
//! domains (`TapLeaf/elements`, `TapBranch/elements`, `TapTweak/elements`).
//!
//!   C_U(X)  = P2TR(NUMS, TapBranch(TapLeaf_0xbe(CMR(U)), H_TapData(X)))
//!   C_V(pi) = P2TR(NUMS, TapBranch(TapLeaf_0xbe(CMR(P(pi))), TapLeaf_0xbe(CMR(G))))

use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
use simplicityhl::elements::secp256k1_zkp::{Parity, Secp256k1, XOnlyPublicKey};
use simplicityhl::elements::taproot::{
    ControlBlock, TapLeafHash, TapNodeHash, TaprootMerkleBranch,
};
use simplicityhl::elements::{Address, AddressParams, Script};
use simplicityhl::simplicity::Cmr;

use crate::net::nums_key;

/// Elements tapleaf hash of a Simplicity leaf: the script is the raw 32-byte CMR
/// at leaf version 0xbe.
pub fn simplicity_leaf_hash(cmr: Cmr) -> TapLeafHash {
    let script = Script::from(cmr.as_ref().to_vec());
    TapLeafHash::from_script(&script, simplicityhl::simplicity::leaf_version())
}

/// `H_TapData(data)`: the hidden taproot node that carries covenant state.
/// Matches the C implementation of the `tapdata_init` jet (plain "TapData" tag).
pub fn tap_data_hash(data: &[u8]) -> sha256::Hash {
    let tag = sha256::Hash::hash(b"TapData");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(data);
    sha256::Hash::from_engine(eng)
}

/// `TapBranch/elements` of two child hashes, sorted lexicographically, exactly
/// as the `build_tapbranch` jet does.
pub fn tap_branch(a: [u8; 32], b: [u8; 32]) -> TapNodeHash {
    let mut eng = TapNodeHash::engine();
    if a <= b {
        eng.input(&a);
        eng.input(&b);
    } else {
        eng.input(&b);
        eng.input(&a);
    }
    TapNodeHash::from_engine(eng)
}

/// A fully derived covenant output: everything needed to pay it and spend it.
pub struct CovenantSpendInfo {
    pub merkle_root: TapNodeHash,
    pub output_key: XOnlyPublicKey,
    pub output_parity: Parity,
    pub script_pubkey: Script,
}

impl CovenantSpendInfo {
    fn from_root(merkle_root: TapNodeHash) -> Self {
        let secp = Secp256k1::verification_only();
        let internal = nums_key();
        let tweak = simplicityhl::elements::taproot::TapTweakHash::from_key_and_tweak(
            internal,
            Some(merkle_root),
        )
        .to_scalar();
        let (output_key, output_parity) = internal
            .add_tweak(&secp, &tweak)
            .expect("NUMS tweak is valid");
        let mut spk = Vec::with_capacity(34);
        spk.push(0x51);
        spk.push(0x20);
        spk.extend_from_slice(&output_key.serialize());
        CovenantSpendInfo {
            merkle_root,
            output_key,
            output_parity,
            script_pubkey: Script::from(spk),
        }
    }

    pub fn address(&self, params: &'static AddressParams) -> Address {
        Address::p2tr_tweaked(
            simplicityhl::elements::schnorr::TweakedPublicKey::new(self.output_key),
            None,
            params,
        )
    }

    /// Control block for spending through the Simplicity leaf whose sibling
    /// node hash is `sibling`.
    pub fn control_block(&self, sibling: [u8; 32]) -> ControlBlock {
        ControlBlock {
            leaf_version: simplicityhl::simplicity::leaf_version(),
            output_key_parity: self.output_parity,
            internal_key: nums_key(),
            merkle_branch: TaprootMerkleBranch::from_inner(vec![sha256::Hash::from_byte_array(
                sibling,
            )])
            .expect("depth-1 branch"),
        }
    }
}

/// Derive the user covenant C_U(owner) for the fixed user program `u_cmr`.
/// Returns the spend info plus the control block for the U leaf (its sibling
/// is the hidden TapData(owner) node).
pub fn cu_spend_info(u_cmr: Cmr, owner: &XOnlyPublicKey) -> (CovenantSpendInfo, ControlBlock) {
    let leaf = simplicity_leaf_hash(u_cmr).to_byte_array();
    let data = tap_data_hash(&owner.serialize()).to_byte_array();
    let info = CovenantSpendInfo::from_root(tap_branch(leaf, data));
    let cb = info.control_block(data);
    (info, cb)
}

/// Derive the verifier covenant C_V(pi) from the primary program's CMR (which
/// commits to pi through its arguments) and the issuer leaf's CMR. Returns the
/// spend info plus the control blocks for (primary, issuer) leaves.
pub fn cv_spend_info(p_cmr: Cmr, g_cmr: Cmr) -> (CovenantSpendInfo, ControlBlock, ControlBlock) {
    let p_leaf = simplicity_leaf_hash(p_cmr).to_byte_array();
    let g_leaf = simplicity_leaf_hash(g_cmr).to_byte_array();
    let info = CovenantSpendInfo::from_root(tap_branch(p_leaf, g_leaf));
    let p_cb = info.control_block(g_leaf);
    let g_cb = info.control_block(p_leaf);
    (info, p_cb, g_cb)
}
