//! Taproot construction for the two OpenDAMP covenants.
//!
//! Both are P2TR outputs with the BIP341 NUMS internal key (no key path) and
//! Simplicity leaves at tapleaf version 0xbe, using the Elements tagged-hash
//! domains (`TapLeaf/elements`, `TapBranch/elements`, `TapTweak/elements`).
//!
//!   C_U(X)  = P2TR(NUMS, TapBranch(TapLeaf_0xbe(CMR(U)), H_TapData(X)))
//!   C_V(pi) = P2TR(NUMS, taptree of one P(pi) leaf per SHAPE, plus G(I))
//!
//! The verifier tree carries several primary programs rather than one. They
//! differ only in how many input and output slots they scan, they all commit to
//! the same policy, and each asserts its own bounds, so a spender picking a
//! narrow leaf for a wide transaction is refused by consensus rather than
//! escaping a scan. What that buys is size: Simplicity's cost bound is static
//! over the whole program, so a single program sized for the widest transfer
//! charges every ordinary transfer for slots it never touches.
//!
//! Leaf depths are chosen so the leaf a wallet reaches for most often has the
//! shortest control block: the canonical transfer sits alone at depth 1 (a
//! 65-byte control block) and everything else at depth 3 (129 bytes).

use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
use simplicityhl::elements::secp256k1_zkp::{Parity, Secp256k1, XOnlyPublicKey};
use simplicityhl::elements::taproot::{
    ControlBlock, TapLeafHash, TapNodeHash, TaprootBuilder, TaprootMerkleBranch,
};
use simplicityhl::elements::{Address, AddressParams, Script};
use simplicityhl::simplicity::Cmr;

use crate::net::nums_key;
use crate::programs::Shape;

/// Elements tapleaf hash of a Simplicity leaf: the script is the raw 32-byte CMR
/// at leaf version 0xbe.
pub fn simplicity_leaf_hash(cmr: Cmr) -> TapLeafHash {
    let script = Script::from(cmr.as_ref().to_vec());
    TapLeafHash::from_script(&script, simplicityhl::simplicity::leaf_version())
}

/// The `(script, version)` pair a Simplicity leaf is keyed by in a taptree.
fn simplicity_leaf(cmr: Cmr) -> (Script, simplicityhl::elements::taproot::LeafVersion) {
    (
        Script::from(cmr.as_ref().to_vec()),
        simplicityhl::simplicity::leaf_version(),
    )
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
        CovenantSpendInfo {
            merkle_root,
            output_key,
            output_parity,
            script_pubkey: p2tr_spk(&output_key),
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
    /// node hash is `sibling`. Only valid for a depth-1 tree (C_U).
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

/// `OP_1 PUSH32 <output_key>`.
pub fn p2tr_spk(output_key: &XOnlyPublicKey) -> Script {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51);
    spk.push(0x20);
    spk.extend_from_slice(&output_key.serialize());
    Script::from(spk)
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

/// The verifier covenant: its address, and a control block per leaf.
pub struct VerifierSpendInfo {
    pub info: CovenantSpendInfo,
    /// One entry per `programs::SHAPES` element, in the same order.
    pub shape_control: Vec<ControlBlock>,
    /// Control block for the issuer leaf G(I).
    pub issuer_control: ControlBlock,
}

/// Depth of each leaf in the verifier taptree, in DFS order:
/// the canonical shape alone at depth 1, then the remaining shapes and G(I) at
/// depth 3. With `SHAPES` of length 4 that is 1 + 4 leaves and the weights sum
/// to exactly one, which is what makes it a valid tree.
fn leaf_depths(n_shapes: usize) -> Vec<usize> {
    // [canonical, rest..., G]
    let rest = n_shapes - 1 + 1; // the non-canonical shapes plus the issuer leaf
    let mut depths = vec![1usize];
    let d = depth_for(rest);
    depths.extend(std::iter::repeat(d).take(rest));
    depths
}

/// Smallest uniform depth (relative to the root) that fits `n` leaves into the
/// half of the tree the canonical leaf does not occupy.
fn depth_for(n: usize) -> usize {
    let mut d = 1usize;
    while (1usize << (d - 1)) < n {
        d += 1;
    }
    d
}

/// Derive C_V(pi) from one primary CMR per shape plus the issuer leaf's CMR.
///
/// `shape_cmrs` must be in `programs::SHAPES` order, with the canonical shape
/// first; it is the one given the shallow leaf.
pub fn cv_spend_info(shape_cmrs: &[Cmr], g_cmr: Cmr) -> Result<VerifierSpendInfo, String> {
    if shape_cmrs.is_empty() {
        return Err("the verifier taptree needs at least one primary leaf".into());
    }
    let depths = leaf_depths(shape_cmrs.len());
    let mut builder = TaprootBuilder::new();
    // DFS order: canonical first at depth 1, then the rest and G at the uniform
    // deeper level.
    let mut leaves: Vec<(Script, simplicityhl::elements::taproot::LeafVersion)> = Vec::new();
    for cmr in shape_cmrs {
        leaves.push(simplicity_leaf(*cmr));
    }
    leaves.push(simplicity_leaf(g_cmr));
    for (leaf, depth) in leaves.iter().zip(depths.iter()) {
        builder = builder
            .add_leaf_with_ver(*depth, leaf.0.clone(), leaf.1)
            .map_err(|e| format!("verifier taptree: {e}"))?;
    }
    let secp = Secp256k1::verification_only();
    let spend_info = builder
        .finalize(&secp, nums_key())
        .map_err(|e| format!("verifier taptree: {e:?}"))?;

    let merkle_root = spend_info
        .merkle_root()
        .ok_or("verifier taptree has no merkle root")?;
    let info = CovenantSpendInfo::from_root(merkle_root);

    let mut controls = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        controls.push(
            spend_info
                .control_block(leaf)
                .ok_or_else(|| "no control block for a leaf just added".to_string())?,
        );
    }
    let issuer_control = controls.pop().expect("issuer leaf was pushed last");
    Ok(VerifierSpendInfo {
        info,
        shape_control: controls,
        issuer_control,
    })
}

impl VerifierSpendInfo {
    /// Control block for `shape`, by its index in `programs::SHAPES`.
    pub fn control_for(&self, shape: Shape) -> Result<&ControlBlock, String> {
        let idx = crate::programs::SHAPES
            .iter()
            .position(|s| *s == shape)
            .ok_or_else(|| format!("shape {shape} is not in the menu"))?;
        self.shape_control
            .get(idx)
            .ok_or_else(|| format!("no control block for shape {shape}"))
    }
}
