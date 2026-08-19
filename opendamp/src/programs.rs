//! Compilation of the OpenDAMP SimplicityHL programs and the argument plumbing
//! that instantiates them.
//!
//! Parameterisation decision (documented in STATUS.md): U is *per-asset* - the
//! asset id A, verifier asset id V and verifier amount q enter U through
//! compile-time Arguments, so each regulated asset has its own U (and its own
//! CMR pinned in the template registry). The alternative (a
//! network-wide U that reads A/V/q from the transaction pattern) has no sound
//! construction for q, and per-asset U keeps the program smaller.
//!
//! P(pi) is compiled once per SHAPE. See `SHAPES`.

use std::fmt;
use std::sync::Arc;

use simplicityhl::elements::hashes::{sha256, Hash};
use simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;
use simplicityhl::elements::AssetId;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::{BitMachine, RedeemNode};
use simplicityhl::{Arguments, CompiledProgram, WitnessValues};

pub const USER_SOURCE: &str = include_str!("../programs/user.simf");
pub const VERIFIER_TEMPLATE: &str = include_str!("../programs/verifier.simf.in");
pub const ISSUER_SOURCE: &str = include_str!("../programs/issuer.simf");

/// dmt-v1 proof depth, which is the tree's depth. Mirrored by `dmt::DEPTH`; the
/// template reads it so the covenant and the prover cannot disagree.
pub const DEPTH: usize = crate::dmt::DEPTH;

/// How many input and output slots a verifier program scans.
///
/// `n_in` slots cover inputs `1..=n_in`, so the program asserts
/// `num_inputs <= n_in + 1`; likewise for outputs. Input 0 is always the
/// verifier and output 0 is always its recreation, so those are not slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub n_in: usize,
    pub n_out: usize,
}

impl Shape {
    pub const fn new(n_in: usize, n_out: usize) -> Self {
        Shape { n_in, n_out }
    }
    /// Total inputs the program tolerates, verifier included.
    pub const fn max_inputs(&self) -> usize {
        self.n_in + 1
    }
    /// Total outputs the program tolerates, verifier recreation included.
    pub const fn max_outputs(&self) -> usize {
        self.n_out + 1
    }
    /// Regulated inputs of A this shape can carry: the slots, less the one a
    /// fee input must occupy.
    pub const fn max_regulated_inputs(&self) -> usize {
        self.n_in - 1
    }
    pub fn name(&self) -> String {
        format!("p{}x{}", self.max_inputs(), self.max_outputs())
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}in/{}out", self.max_inputs(), self.max_outputs())
    }
}

/// The leaf menu, in taptree order. `SHAPES[0]` is the canonical transfer and
/// gets the shallow leaf.
///
/// Every shape must leave room for a fee input and a fee output: a transfer
/// cannot pay its fee in A (the covenant forbids it, and so does Rule 1), the
/// verifier input's q of V is returned whole to output 0, so the fee has to come
/// from an ordinary input that is neither. That is why no shape has fewer than
/// three inputs.
///
///   p3x5  verifier + 1 regulated + 1 fee input;
///         verifier + payment + change + fee-change + fee output.   CANONICAL
///   p3x4  the same without fee-asset change (an exact fee UTXO).
///   p4x6  two regulated inputs, or two payments.
///   p5x7  consolidation: three regulated inputs.
pub const SHAPES: [Shape; 4] = [
    Shape::new(2, 4),
    Shape::new(2, 3),
    Shape::new(3, 5),
    Shape::new(4, 6),
];

/// The shape a wallet reaches for unless a transaction needs more room.
pub const CANONICAL: Shape = SHAPES[0];

/// The narrowest shape that fits a transaction of `n_inputs` by `n_outputs`.
pub fn shape_for(n_inputs: usize, n_outputs: usize) -> Result<Shape, String> {
    SHAPES
        .iter()
        .copied()
        .filter(|s| s.max_inputs() >= n_inputs && s.max_outputs() >= n_outputs)
        // Narrowest by total slots, so the cheapest leaf that fits wins.
        .min_by_key(|s| s.n_in + s.n_out)
        .ok_or_else(|| {
            format!(
                "a transaction with {n_inputs} inputs and {n_outputs} outputs exceeds every \
                 verifier shape in the menu (widest is {})",
                SHAPES
                    .iter()
                    .max_by_key(|s| s.n_in + s.n_out)
                    .expect("SHAPES is not empty")
            )
        })
}

/// Render the verifier template for one shape.
pub fn render_verifier(shape: Shape) -> String {
    let mut input_scan = String::new();
    for i in 1..=shape.n_in {
        input_scan.push_str(&format!(
            "    let c{i}: bool = check_input({i}, cu_sender, witness::I{i});\n"
        ));
    }
    // either(c1, either(c2, ...)) -- a right fold, so a single slot renders as
    // the bare `c1` rather than a needless call.
    let mut any = format!("c{}", shape.n_in);
    for i in (1..shape.n_in).rev() {
        any = format!("either(c{i}, {any})");
    }

    let mut output_scan = String::new();
    for i in 1..=shape.n_out {
        if i == 1 {
            output_scan.push_str(
                "    let paid: u64 = check_output(1, cu_sender, witness::W1);\n",
            );
        } else {
            output_scan.push_str(&format!(
                "    let paid: u64 = add_payment(paid, check_output({i}, cu_sender, witness::W{i}));\n"
            ));
        }
    }

    VERIFIER_TEMPLATE
        .replace("%%DEPTH%%", &DEPTH.to_string())
        .replace("%%NUM_INPUTS_LT%%", &(shape.max_inputs() + 1).to_string())
        .replace("%%NUM_OUTPUTS_LT%%", &(shape.max_outputs() + 1).to_string())
        .replace("%%INPUT_SCAN%%", input_scan.trim_end_matches('\n'))
        .replace("%%INPUT_ANY%%", &any)
        .replace("%%OUTPUT_SCAN%%", output_scan.trim_end_matches('\n'))
}

/// Asset id in the *internal* (hash / consensus) byte order, which is what the
/// asset-introspection jets expose. Display hex is the reverse of this.
pub fn asset_internal_bytes(asset: &AssetId) -> [u8; 32] {
    asset.into_inner().to_byte_array()
}

fn u256_value(bytes: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "value": format!("0x{}", crate::hexutil::hex(bytes)),
        "type": "u256",
    })
}

fn pubkey_value(key: &XOnlyPublicKey) -> serde_json::Value {
    serde_json::json!({
        "value": format!("0x{}", crate::hexutil::hex(&key.serialize())),
        "type": "Pubkey",
    })
}

fn u64_value(v: u64) -> serde_json::Value {
    serde_json::json!({
        "value": format!("{v}"),
        "type": "u64",
    })
}

/// The simplicityhl serde visitors borrow strings, which `from_value` cannot
/// provide; round-trip through text instead.
fn from_json<T: for<'de> serde::Deserialize<'de>>(map: &serde_json::Value) -> Result<T, String> {
    let text = serde_json::to_string(map).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("building arguments/witness: {e}"))
}

fn arguments(map: serde_json::Value) -> Result<Arguments, String> {
    from_json(&map)
}

/// Per-asset protocol constants.
#[derive(Clone, Copy, Debug)]
pub struct AssetParams {
    pub asset_a: AssetId,
    pub asset_v: AssetId,
    pub q: u64,
}

pub fn compile_user(params: &AssetParams) -> Result<CompiledProgram, String> {
    let args = arguments(serde_json::json!({
        "ASSET_A": u256_value(&asset_internal_bytes(&params.asset_a)),
        "ASSET_V": u256_value(&asset_internal_bytes(&params.asset_v)),
        "AMOUNT_Q": u64_value(params.q),
    }))?;
    CompiledProgram::new(USER_SOURCE, args, false)
}

/// The LIMIT argument standing for "no limit": no sum of asset amounts can
/// exceed it, and the covenant's overflow check keeps it that way.
pub const NO_LIMIT: u64 = u64::MAX;

#[allow(clippy::too_many_arguments)]
pub fn compile_verifier(
    params: &AssetParams,
    u_cmr: simplicityhl::simplicity::Cmr,
    wl_root: &[u8; 32],
    bl_root: &[u8; 32],
    limit: u64,
    pi: &[u8; 32],
    shape: Shape,
) -> Result<CompiledProgram, String> {
    let mut cmr_bytes = [0u8; 32];
    cmr_bytes.copy_from_slice(u_cmr.as_ref());
    let args = arguments(serde_json::json!({
        "ASSET_A": u256_value(&asset_internal_bytes(&params.asset_a)),
        "ASSET_V": u256_value(&asset_internal_bytes(&params.asset_v)),
        "AMOUNT_Q": u64_value(params.q),
        "U_CMR": u256_value(&cmr_bytes),
        "WL_ROOT": u256_value(wl_root),
        "BL_ROOT": u256_value(bl_root),
        "LIMIT": u64_value(limit),
        "PI": u256_value(pi),
    }))?;
    CompiledProgram::new(render_verifier(shape).as_str(), args, false)
}

pub fn compile_issuer(issuer_key: &XOnlyPublicKey) -> Result<CompiledProgram, String> {
    let args = arguments(serde_json::json!({
        "ISSUER_KEY": pubkey_value(issuer_key),
    }))?;
    CompiledProgram::new(ISSUER_SOURCE, args, false)
}

/// Witness values for a U spend.
pub fn user_witness(owner: &XOnlyPublicKey, sig: &[u8; 64]) -> Result<WitnessValues, String> {
    let v = serde_json::json!({
        "OWNER_KEY": pubkey_value(owner),
        "OWNER_SIG": {
            "value": format!("0x{}", crate::hexutil::hex(sig)),
            "type": "Signature",
        },
    });
    from_json(&v)
}

/// Witness values for a G spend.
pub fn issuer_witness(sig: &[u8; 64]) -> Result<WitnessValues, String> {
    let v = serde_json::json!({
        "ISSUER_SIG": {
            "value": format!("0x{}", crate::hexutil::hex(sig)),
            "type": "Signature",
        },
    });
    from_json(&v)
}

/// One verifier OUTPUT slot witness: the recipient key and its dmt-v1
/// membership proof, or `None` for a slot whose output does not carry A *or*
/// carries A as the sender's own change, which needs no proof.
pub type SlotWitness = Option<(XOnlyPublicKey, crate::dmt::Proof)>;

/// One verifier INPUT slot witness: only the blacklist interval proof for the
/// input's outpoint. The owner is proven once, for the whole transfer, by
/// `SenderWitness`.
pub type InputSlotWitness = Option<crate::dmt::IntervalProof>;

/// The sender, proven once: their key, and the whitelist proof that carries
/// their committed height windows.
#[derive(Clone, Debug)]
pub struct SenderWitness {
    pub key: XOnlyPublicKey,
    pub proof: crate::dmt::Proof,
}

fn path_literal(path: &crate::dmt::Path) -> String {
    let levels: Vec<String> = path
        .levels()
        .iter()
        .map(|(sib, is_right)| format!("(0x{}, {})", crate::hexutil::hex(sib), is_right))
        .collect();
    format!("[{}]", levels.join(", "))
}

/// A whitelist slot literal: the key, its two committed window bounds, and the
/// Merkle path. The bounds travel in the witness because the covenant rebuilds
/// the leaf from them.
fn wl_slot_literal(proof: &crate::dmt::Proof) -> String {
    format!(
        "0x{}, {}, {}, {}",
        crate::hexutil::hex(&proof.entry.key),
        proof.entry.send_after,
        proof.entry.recv_after,
        path_literal(&proof.path)
    )
}

fn out_slot_type() -> String {
    format!("Option<(Pubkey, u32, u32, [(u256, bool); {DEPTH}])>")
}

fn in_slot_type() -> String {
    format!("Option<(u256, u256, [(u256, bool); {DEPTH}])>")
}

fn sender_type() -> String {
    format!("(Pubkey, u32, u32, [(u256, bool); {DEPTH}])")
}

/// Witness values for a P(pi) spend of `shape`.
///
/// There is no budget pad. Under Sequentia's Simplicity budget rule a witness
/// byte buys four weight units of execution, which every shape's functional
/// witness covers; `txbuild::attach_verifier` re-checks that on every build.
pub fn verifier_witness(
    shape: Shape,
    sender: &SenderWitness,
    out_slots: &[SlotWitness],
    in_slots: &[InputSlotWitness],
) -> Result<WitnessValues, String> {
    if out_slots.len() != shape.n_out || in_slots.len() != shape.n_in {
        return Err(format!(
            "shape {shape} wants {} input and {} output slots, got {} and {}",
            shape.n_in,
            shape.n_out,
            in_slots.len(),
            out_slots.len()
        ));
    }
    let mut map = serde_json::Map::new();
    map.insert(
        "SENDER".to_string(),
        serde_json::json!({
            "value": format!("({})", wl_slot_literal(&sender.proof)),
            "type": sender_type(),
        }),
    );
    for (i, slot) in out_slots.iter().enumerate() {
        let value = match slot {
            None => "None".to_string(),
            Some((_key, proof)) => format!("Some(({}))", wl_slot_literal(proof)),
        };
        map.insert(
            format!("W{}", i + 1),
            serde_json::json!({ "value": value, "type": out_slot_type() }),
        );
    }
    for (i, slot) in in_slots.iter().enumerate() {
        let value = match slot {
            None => "None".to_string(),
            Some(interval) => format!(
                "Some((0x{}, 0x{}, {}))",
                crate::hexutil::hex(&interval.lo),
                crate::hexutil::hex(&interval.hi),
                path_literal(&interval.path)
            ),
        };
        map.insert(
            format!("I{}", i + 1),
            serde_json::json!({ "value": value, "type": in_slot_type() }),
        );
    }
    from_json(&serde_json::Value::Object(map))
}

/// Satisfy and (optionally) execute a program against an environment.
/// With `env = Some(..)` the program is run on the BitMachine, so a failing
/// covenant check surfaces here rather than at the node. With `env = None` the
/// witness is attached without local validation - used by tests to build
/// deliberately invalid transactions the node must reject.
///
/// The program IS pruned when an environment is supplied: consensus rejects a
/// redeem program that still contains FAIL nodes, and pruning is what removes
/// the untaken assertion branches.
pub fn satisfy_program(
    program: &CompiledProgram,
    witness: WitnessValues,
    env: Option<&ElementsEnv<Arc<simplicityhl::elements::Transaction>>>,
) -> Result<Arc<RedeemNode<Elements>>, String> {
    let satisfied = program.satisfy_with_env(witness, env)?;
    let node = satisfied.redeem().clone();
    if let Some(env) = env {
        let mut mac = BitMachine::for_program(&node).map_err(|e| format!("bit machine: {e}"))?;
        mac.exec(&node, env)
            .map_err(|e| format!("covenant execution failed: {e}"))?;
    }
    Ok(node)
}

/// SHA256 of a script, as the *_script_hash jets expose it (for debugging).
pub fn script_sha(script: &simplicityhl::elements::Script) -> [u8; 32] {
    sha256::Hash::hash(script.as_bytes()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shape_renders_without_leftover_tokens() {
        for shape in SHAPES {
            let src = render_verifier(shape);
            assert!(!src.contains("%%"), "{shape} left a token unrendered");
            assert!(src.contains(&format!("jet::lt_32(jet::num_inputs(), {})", shape.max_inputs() + 1)));
            assert!(src.contains(&format!("jet::lt_32(jet::num_outputs(), {})", shape.max_outputs() + 1)));
            assert!(src.contains(&format!("check_input({}, cu_sender", shape.n_in)));
            assert!(src.contains(&format!("check_output({}, cu_sender", shape.n_out)));
            assert!(!src.contains(&format!("check_input({}, cu_sender", shape.n_in + 1)));
            assert!(!src.contains(&format!("check_output({}, cu_sender", shape.n_out + 1)));
        }
    }

    #[test]
    fn the_menu_picks_the_narrowest_leaf_that_fits() {
        // The canonical transfer: verifier + regulated + fee in, verifier +
        // payment + change + fee-change + fee out.
        assert_eq!(shape_for(3, 5).unwrap(), CANONICAL);
        // An exact fee UTXO needs one output less and gets a cheaper leaf.
        assert_eq!(shape_for(3, 4).unwrap(), Shape::new(2, 3));
        // Two regulated inputs need a wider one.
        assert_eq!(shape_for(4, 5).unwrap(), Shape::new(3, 5));
        assert_eq!(shape_for(5, 7).unwrap(), Shape::new(4, 6));
        // And past the widest leaf the builder must refuse rather than emit a
        // transaction no leaf can spend.
        assert!(shape_for(6, 7).is_err());
        assert!(shape_for(5, 8).is_err());
    }

    #[test]
    fn every_shape_leaves_room_for_a_fee() {
        for shape in SHAPES {
            // A fee cannot be paid in A and cannot come out of the verifier's q
            // of V, so there must be room for a fee input beside at least one
            // regulated input, and for a fee output beside the recreation.
            assert!(shape.max_inputs() >= 3, "{shape} cannot fund a fee");
            assert!(shape.max_regulated_inputs() >= 1, "{shape} carries no A");
            assert!(shape.max_outputs() >= 3, "{shape} cannot pay a fee");
        }
    }
}
