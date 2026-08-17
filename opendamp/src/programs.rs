//! Compilation of the three OpenDAMP SimplicityHL programs and the argument
//! plumbing that instantiates them.
//!
//! Parameterisation decision (documented in STATUS.md): U is *per-asset* - the
//! asset id A, verifier asset id V and verifier amount q enter U through
//! compile-time Arguments, so each regulated asset has its own U (and its own
//! CMR pinned in the template registry). The alternative (a network-wide U
//! that reads A/V/q from the transaction pattern) has no sound construction
//! for q, and per-asset U keeps the program smaller.

use std::sync::Arc;

use simplicityhl::elements::hashes::{sha256, Hash};
use simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;
use simplicityhl::elements::AssetId;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::{BitMachine, RedeemNode};
use simplicityhl::{Arguments, CompiledProgram, WitnessValues};

pub const USER_SOURCE: &str = include_str!("../programs/user.simf");
pub const VERIFIER_SOURCE: &str = include_str!("../programs/verifier.simf");
pub const ISSUER_SOURCE: &str = include_str!("../programs/issuer.simf");

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

pub fn compile_verifier(
    params: &AssetParams,
    u_cmr: simplicityhl::simplicity::Cmr,
    wl_root: &[u8; 32],
    bl_root: &[u8; 32],
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
    }))?;
    CompiledProgram::new(VERIFIER_SOURCE, args, false)
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

/// One verifier slot witness: a key and its dmt-v1 membership proof, or `None`
/// for a slot whose output/input does not carry A.
pub type SlotWitness = Option<(XOnlyPublicKey, crate::dmt::Proof)>;

/// One verifier INPUT slot witness: the owner key, its whitelist membership
/// proof, and the blacklist interval proof for the input's outpoint.
pub type InputSlotWitness = Option<(XOnlyPublicKey, crate::dmt::Proof, crate::dmt::IntervalProof)>;

/// Output slots the verifier scans: outputs 1..=N_OUT_SLOTS, so
/// N_max_outputs = N_OUT_SLOTS + 1. MUST match `programs/verifier.simf`.
pub const N_OUT_SLOTS: usize = 5;

/// Input slots the verifier scans: inputs 1..=N_IN_SLOTS, so
/// N_max_inputs = N_IN_SLOTS + 1. MUST match `programs/verifier.simf`.
pub const N_IN_SLOTS: usize = 3;

/// Number of 32-byte words in the verifier program's BUDGET_PAD array. MUST
/// match the `[u256; N]` declaration and the `array_fold::<absorb, N>` bound in
/// `programs/verifier.simf`: the pad is part of the program and therefore of
/// its CMR.
pub const BUDGET_PAD_WORDS: usize = 512;

/// Pad size in bytes.
pub const BUDGET_PAD_LEN: usize = BUDGET_PAD_WORDS * 32;

/// Witness values for a P(pi) spend. The BUDGET_PAD array is inert; it exists
/// so the witness stack buys enough Simplicity execution budget for the
/// output scan (see the comment on BUDGET_PAD in verifier.simf).
fn proof_literal(proof: &crate::dmt::Proof) -> String {
    let levels: Vec<String> = proof
        .levels()
        .iter()
        .map(|(sib, is_right)| format!("(0x{}, {})", crate::hexutil::hex(sib), is_right))
        .collect();
    format!("[{}]", levels.join(", "))
}

pub fn verifier_witness(
    out_slots: &[SlotWitness; N_OUT_SLOTS],
    in_slots: &[InputSlotWitness; N_IN_SLOTS],
) -> Result<WitnessValues, String> {
    let out_ty = "Option<(Pubkey, [(u256, bool); 16])>";
    let in_ty = "Option<(Pubkey, [(u256, bool); 16], u256, u256, [(u256, bool); 16])>";
    let mut map = serde_json::Map::new();
    let zero_word = format!("0x{}", "00".repeat(32));
    let pad_items = vec![zero_word; BUDGET_PAD_WORDS].join(", ");
    map.insert(
        "BUDGET_PAD".to_string(),
        serde_json::json!({
            "value": format!("[{pad_items}]"),
            "type": format!("[u256; {BUDGET_PAD_WORDS}]"),
        }),
    );
    for (i, slot) in out_slots.iter().enumerate() {
        let value = match slot {
            None => "None".to_string(),
            Some((key, proof)) => format!(
                "Some((0x{}, {}))",
                crate::hexutil::hex(&key.serialize()),
                proof_literal(proof)
            ),
        };
        map.insert(
            format!("W{}", i + 1),
            serde_json::json!({ "value": value, "type": out_ty }),
        );
    }
    for (i, slot) in in_slots.iter().enumerate() {
        let value = match slot {
            None => "None".to_string(),
            Some((key, owner_proof, interval)) => format!(
                "Some((0x{}, {}, 0x{}, 0x{}, {}))",
                crate::hexutil::hex(&key.serialize()),
                proof_literal(owner_proof),
                crate::hexutil::hex(&interval.lo),
                crate::hexutil::hex(&interval.hi),
                proof_literal(&interval.proof)
            ),
        };
        map.insert(
            format!("I{}", i + 1),
            serde_json::json!({ "value": value, "type": in_ty }),
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
/// the untaken assertion branches. The verifier's BUDGET_PAD is read by
/// `absorb` on every execution precisely so pruning cannot discard it.
pub fn satisfy_program(
    program: &CompiledProgram,
    witness: WitnessValues,
    env: Option<&ElementsEnv<Arc<simplicityhl::elements::Transaction>>>,
) -> Result<Arc<RedeemNode<Elements>>, String> {
    let satisfied = program.satisfy_with_env(witness, env)?;
    let node = satisfied.redeem().clone();
    if let Some(env) = env {
        let mut mac =
            BitMachine::for_program(&node).map_err(|e| format!("bit machine: {e}"))?;
        mac.exec(&node, env)
            .map_err(|e| format!("covenant execution failed: {e}"))?;
    }
    Ok(node)
}

/// SHA256 of a script, as the *_script_hash jets expose it (for debugging).
pub fn script_sha(script: &simplicityhl::elements::Script) -> [u8; 32] {
    sha256::Hash::hash(script.as_bytes()).to_byte_array()
}
