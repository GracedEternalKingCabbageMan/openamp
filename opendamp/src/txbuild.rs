//! Offline construction of OpenDAMP transactions (M3).
//!
//! Everything here works from a policy snapshot plus explicit UTXO data; a
//! node is needed only to broadcast the result.

use std::sync::Arc;

use simplicityhl::elements::confidential;
use simplicityhl::elements::hashes::Hash;
use simplicityhl::elements::secp256k1_zkp::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};
use simplicityhl::elements::sighash::{Prevouts, SighashCache};
use simplicityhl::elements::taproot::TapTweakHash;
use simplicityhl::elements::{
    AssetId, LockTime, OutPoint, SchnorrSighashType, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut,
};
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::CompiledProgram;

use crate::dmt;
use crate::net::Net;
use crate::programs::{
    self, compile_issuer, compile_user, compile_verifier, satisfy_program, AssetParams,
    InputSlotWitness, SenderWitness, Shape, SlotWitness,
};
use crate::tapscript::{cu_spend_info, cv_spend_info, CovenantSpendInfo, VerifierSpendInfo};

/// Everything derived from the per-asset constants and one policy version.
pub struct Ctx {
    pub net: Net,
    pub params: AssetParams,
    pub issuer_key: XOnlyPublicKey,
    pub wl_tree: dmt::Tree,
    pub bl_tree: dmt::IntervalTree,
    pub limit: u64,
    /// The policy commitment, which every verifier leaf commits to. `seq` is
    /// the only thing in it the roots do not already determine, and it is what
    /// makes two policy versions with identical rules distinguishable on chain.
    pub seq: u64,
    pub pi: [u8; 32],
    pub user: CompiledProgram,
    /// One primary program per `programs::SHAPES` entry, in that order.
    pub verifiers: Vec<CompiledProgram>,
    pub issuer: CompiledProgram,
    verifier_spend: VerifierSpendInfo,
}

impl Ctx {
    /// Convenience for the common case: unrestricted whitelist entries, no
    /// blacklist, no transfer limit, policy sequence 0.
    pub fn new(
        net: Net,
        params: AssetParams,
        issuer_key: XOnlyPublicKey,
        wl_keys: &[XOnlyPublicKey],
        bl_outpoint_keys: &[[u8; 32]],
    ) -> Result<Self, String> {
        let entries = wl_keys
            .iter()
            .map(|k| dmt::Entry::unrestricted(k.serialize()))
            .collect();
        Self::with_policy(
            net,
            params,
            issuer_key,
            entries,
            bl_outpoint_keys,
            programs::NO_LIMIT,
            0,
        )
    }

    /// The full policy: whitelist entries (each with its height windows), the
    /// blacklisted outpoint policy keys, the transfer limit, and the policy
    /// sequence number.
    #[allow(clippy::too_many_arguments)]
    pub fn with_policy(
        net: Net,
        params: AssetParams,
        issuer_key: XOnlyPublicKey,
        wl_entries: Vec<dmt::Entry>,
        bl_outpoint_keys: &[[u8; 32]],
        limit: u64,
        seq: u64,
    ) -> Result<Self, String> {
        let wl_tree = dmt::Tree::new(wl_entries)?;
        let bl_tree = dmt::IntervalTree::new(bl_outpoint_keys.to_vec())?;
        let user = compile_user(&params)?;
        let u_cmr = user.commit().cmr();

        let rules_root = crate::policy::rules_root(
            Some(bl_tree.root()),
            Some(wl_tree.root()),
            (limit != programs::NO_LIMIT).then_some(limit),
            None,
        );
        let pi = crate::policy::pi(
            programs::asset_internal_bytes(&params.asset_a),
            seq,
            rules_root,
        );

        let mut verifiers = Vec::with_capacity(programs::SHAPES.len());
        for shape in programs::SHAPES {
            verifiers.push(compile_verifier(
                &params,
                u_cmr,
                &wl_tree.root(),
                &bl_tree.root(),
                limit,
                &pi,
                shape,
            )?);
        }
        let issuer = compile_issuer(&issuer_key)?;
        let shape_cmrs: Vec<_> = verifiers.iter().map(|p| p.commit().cmr()).collect();
        let verifier_spend = cv_spend_info(&shape_cmrs, issuer.commit().cmr())?;

        Ok(Ctx {
            net,
            params,
            issuer_key,
            wl_tree,
            bl_tree,
            limit,
            seq,
            pi,
            user,
            verifiers,
            issuer,
            verifier_spend,
        })
    }

    pub fn u_cmr(&self) -> simplicityhl::simplicity::Cmr {
        self.user.commit().cmr()
    }
    pub fn g_cmr(&self) -> simplicityhl::simplicity::Cmr {
        self.issuer.commit().cmr()
    }
    /// CMR of the primary program for `shape`.
    pub fn p_cmr(&self, shape: Shape) -> Result<simplicityhl::simplicity::Cmr, String> {
        Ok(self.verifier_for(shape)?.commit().cmr())
    }
    pub fn verifier_for(&self, shape: Shape) -> Result<&CompiledProgram, String> {
        let idx = programs::SHAPES
            .iter()
            .position(|s| *s == shape)
            .ok_or_else(|| format!("shape {shape} is not in the menu"))?;
        Ok(&self.verifiers[idx])
    }

    pub fn cu_info(&self, owner: &XOnlyPublicKey) -> CovenantSpendInfo {
        cu_spend_info(self.u_cmr(), owner).0
    }

    pub fn cv_info(&self) -> &CovenantSpendInfo {
        &self.verifier_spend.info
    }

    pub fn verifier_spend(&self) -> &VerifierSpendInfo {
        &self.verifier_spend
    }
}

/// A fully described explicit UTXO.
#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub asset: AssetId,
    pub value: u64,
    pub script_pubkey: Script,
}

impl Utxo {
    pub fn txout(&self) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(self.asset),
            value: confidential::Value::Explicit(self.value),
            nonce: confidential::Nonce::Null,
            script_pubkey: self.script_pubkey.clone(),
            witness: Default::default(),
        }
    }
}

/// Every input uses a non-final sequence. `lockHeight`, which the height-window
/// jet reads, is 0 for a transaction whose every sequence is 0xffffffff - so a
/// final transaction can satisfy no nonzero window bound. Using 0xfffffffe
/// unconditionally means a locktime always means what it says, and a transfer
/// with no windows is unaffected because bound 0 is satisfied by lockHeight 0.
const NON_FINAL: u32 = 0xffff_fffe;

fn plain_input(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::from_consensus(NON_FINAL),
        asset_issuance: Default::default(),
        witness: TxInWitness::default(),
    }
}

fn explicit_out(asset: AssetId, value: u64, spk: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey: spk,
        witness: Default::default(),
    }
}

/// A transfer request: alice pays `amount` of A to `recipient`, change back to
/// herself, fee in an ordinary asset from a P2TR key-path UTXO.
pub struct TransferReq {
    pub sender: XOnlyPublicKey,
    pub sender_utxos: Vec<(OutPoint, u64)>,
    pub recipient: XOnlyPublicKey,
    pub amount: u64,
    pub verifier_outpoint: OutPoint,
    pub fee_utxo: (OutPoint, AssetId, u64),
    /// Internal key of the fee UTXO (P2TR key path, no script tree).
    pub fee_key: XOnlyPublicKey,
    pub fee_amount: u64,
    /// Where fee-asset change goes (a plain address's script pubkey).
    pub fee_change_spk: Script,
    /// The height the transaction commits to through nLockTime. It must be at
    /// least the sender's `send_after` and every recipient's `recv_after`; 0
    /// means no height is claimed, which only works when no window applies.
    pub locktime: u32,
    /// Test hook: send the recipient's A to this script instead of C_U
    /// (used to prove the confinement refusal). Never set in real use.
    pub recipient_spk_override: Option<Script>,
}

/// The built (unsigned) transfer plus everything needed to sign it.
pub struct BuiltTransfer {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    /// (output index, owner key) for every output carrying asset A.
    pub a_outputs: Vec<(usize, XOnlyPublicKey)>,
    /// Input indexes of the sender's C_U inputs.
    pub user_inputs: Vec<usize>,
    /// (input index, owner key, outpoint) for every input carrying asset A. The
    /// verifier proves the owner once and each outpoint unlisted, so the builder
    /// has to know both.
    pub a_inputs: Vec<(usize, XOnlyPublicKey, OutPoint)>,
    /// Input index of the fee UTXO.
    pub fee_input: usize,
    /// The narrowest leaf of the verifier taptree that can spend this shape.
    pub shape: Shape,
}

/// Build a transfer, refusing one the covenant would reject.
///
/// The preflight is a courtesy, not the enforcement: it turns a policy violation
/// into a clear local error instead of an opaque node rejection. Enforcement is
/// P(pi). Use [`build_transfer_unchecked`] only to construct a deliberately
/// invalid transaction for a test that wants the NODE to be the one refusing.
pub fn build_transfer(ctx: &Ctx, req: &TransferReq) -> Result<BuiltTransfer, String> {
    let built = build_transfer_unchecked(ctx, req)?;
    preflight_policy(ctx, req, &built)?;
    Ok(built)
}

/// The policy checks P(pi) will apply, evaluated locally so the builder can
/// explain a refusal.
pub fn preflight_policy(ctx: &Ctx, req: &TransferReq, built: &BuiltTransfer) -> Result<(), String> {
    // Height windows: the covenant requires lockHeight >= each bound. The
    // sender's lockup binds because they own every regulated input; a
    // recipient's receive window binds only on a PAYMENT, never on the sender's
    // own change, which is not an acquisition.
    let mut needed = 0u32;
    let sender_entry = ctx
        .wl_tree
        .entry_of(&req.sender.serialize())
        .ok_or_else(|| {
            format!(
                "owner key {} is not in the whitelist: these coins are frozen",
                req.sender
            )
        })?;
    needed = needed.max(sender_entry.send_after);
    for (_, owner) in &built.a_outputs {
        if *owner == req.sender {
            continue; // change
        }
        if let Some(e) = ctx.wl_tree.entry_of(&owner.serialize()) {
            needed = needed.max(e.recv_after);
        }
    }
    if req.locktime < needed {
        return Err(format!(
            "this transfer needs locktime >= {needed} (a height window applies); \
             the request asks for {}",
            req.locktime
        ));
    }

    // Transfer limit: what leaves the sender's hands. Change does not count.
    let paid = payments_to_others(req.sender, built)?;
    if paid > ctx.limit {
        return Err(format!(
            "this transfer pays {paid} atoms to other owners, over the committed \
             transfer limit of {}",
            ctx.limit
        ));
    }
    Ok(())
}

/// The sum the transfer limit applies to: every A output whose owner is not the
/// sender. Identified by OWNER KEY, never by output position - a spender chooses
/// positions, so treating "the last A output" as change would be an aliasing bug
/// the covenant does not share.
///
/// A payment with a blinded value is an ERROR, not a zero. The covenant refuses
/// one outright (`explicit_value` panics), so scoring it as zero here would let
/// the preflight wave through a transfer the node then rejects for a reason the
/// error message never mentioned - and, worse, would report an under-limit total
/// for a transaction whose real total is unknown.
pub fn payments_to_others(
    sender: XOnlyPublicKey,
    built: &BuiltTransfer,
) -> Result<u64, String> {
    let mut total: u64 = 0;
    for (i, owner) in &built.a_outputs {
        if *owner == sender {
            continue; // change may stay blinded
        }
        let value = built.tx.output[*i].value.explicit().ok_or_else(|| {
            format!(
                "output {i} pays {owner} in the regulated asset with a blinded value; \
                 a payment to another owner must expose its value or the transfer \
                 limit could be evaded behind a commitment"
            )
        })?;
        total = total
            .checked_add(value)
            .ok_or("payments to other owners overflow a u64")?;
    }
    Ok(total)
}

pub fn build_transfer_unchecked(ctx: &Ctx, req: &TransferReq) -> Result<BuiltTransfer, String> {
    let cv = ctx.cv_info();
    let cu_sender = ctx.cu_info(&req.sender);
    let cu_recipient = ctx.cu_info(&req.recipient);

    let total_in: u64 = req.sender_utxos.iter().map(|(_, v)| v).sum();
    if total_in < req.amount {
        return Err(format!(
            "sender UTXOs hold {total_in} atoms of A, need {}",
            req.amount
        ));
    }
    let change = total_in - req.amount;
    let (fee_op, fee_asset, fee_value) = req.fee_utxo.clone();
    if fee_asset == ctx.params.asset_a {
        return Err("fee must not be paid in the regulated asset".into());
    }
    if fee_value < req.fee_amount {
        return Err("fee UTXO smaller than fee".into());
    }
    let fee_change = fee_value - req.fee_amount;

    // Inputs: [0] verifier, [1..] sender C_U inputs, [last] fee.
    let mut inputs = vec![plain_input(req.verifier_outpoint)];
    let mut prevouts = vec![explicit_out(
        ctx.params.asset_v,
        ctx.params.q,
        cv.script_pubkey.clone(),
    )];
    let mut user_inputs = Vec::new();
    let mut a_inputs = Vec::new();
    for (op, v) in &req.sender_utxos {
        a_inputs.push((inputs.len(), req.sender, *op));
        user_inputs.push(inputs.len());
        inputs.push(plain_input(*op));
        prevouts.push(explicit_out(
            ctx.params.asset_a,
            *v,
            cu_sender.script_pubkey.clone(),
        ));
    }
    let fee_input = inputs.len();
    inputs.push(plain_input(fee_op));
    let fee_spk = p2tr_keypath_spk(&req.fee_key);
    prevouts.push(explicit_out(fee_asset, fee_value, fee_spk));

    // Outputs: [0] verifier recreation, [1] payment, [2] A change (if any),
    // [.] fee change (if any), [last] fee.
    let mut outputs = vec![explicit_out(
        ctx.params.asset_v,
        ctx.params.q,
        cv.script_pubkey.clone(),
    )];
    let mut a_outputs = Vec::new();
    let recipient_spk = req
        .recipient_spk_override
        .clone()
        .unwrap_or_else(|| cu_recipient.script_pubkey.clone());
    a_outputs.push((outputs.len(), req.recipient));
    outputs.push(explicit_out(ctx.params.asset_a, req.amount, recipient_spk));
    if change > 0 {
        a_outputs.push((outputs.len(), req.sender));
        outputs.push(explicit_out(
            ctx.params.asset_a,
            change,
            cu_sender.script_pubkey.clone(),
        ));
    }
    if fee_change > 0 {
        outputs.push(explicit_out(fee_asset, fee_change, req.fee_change_spk.clone()));
    }
    outputs.push(TxOut::new_fee(req.fee_amount, fee_asset));

    // The leaf that will spend this. `shape_for` refuses a transaction wider
    // than every leaf in the menu, which is the check the builder used to make
    // for outputs only: N_MAX_INPUTS existed as a constant and was never
    // enforced, so three regulated inputs built cleanly and then died in the
    // BitMachine with an opaque jet failure.
    let shape = programs::shape_for(inputs.len(), outputs.len())?;

    if req.locktime >= 500_000_000 {
        return Err(format!(
            "locktime {} is a timestamp, not a height; the covenant's window \
             check reads heights only",
            req.locktime
        ));
    }

    let tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(req.locktime),
        input: inputs,
        output: outputs,
    };
    Ok(BuiltTransfer {
        tx,
        prevouts,
        a_outputs,
        a_inputs,
        user_inputs,
        fee_input,
        shape,
    })
}

/// The blacklist policy key of an outpoint. `OutPoint`'s txid is stored in
/// internal byte order, which is exactly what the covenant hashes.
pub fn outpoint_policy_key(outpoint: &OutPoint) -> [u8; 32] {
    dmt::outpoint_key(&outpoint.txid.to_byte_array(), outpoint.vout)
}

/// Script pubkey of a P2TR key-path output for `internal_key` (no tree).
pub fn p2tr_keypath_spk(internal_key: &XOnlyPublicKey) -> Script {
    let secp = Secp256k1::verification_only();
    let tweak = TapTweakHash::from_key_and_tweak(*internal_key, None).to_scalar();
    let (out_key, _) = internal_key
        .add_tweak(&secp, &tweak)
        .expect("tweak is valid");
    crate::tapscript::p2tr_spk(&out_key)
}

fn elements_utxos(prevouts: &[TxOut]) -> Vec<ElementsUtxo> {
    prevouts
        .iter()
        .map(|u| ElementsUtxo {
            script_pubkey: u.script_pubkey.clone(),
            asset: u.asset,
            value: u.value,
        })
        .collect()
}

/// Environment for executing/signing a covenant input.
pub fn covenant_env(
    net: &Net,
    tx: &Transaction,
    prevouts: &[TxOut],
    index: usize,
    cmr: simplicityhl::simplicity::Cmr,
    control_block: simplicityhl::elements::taproot::ControlBlock,
) -> ElementsEnv<Arc<Transaction>> {
    ElementsEnv::new(
        Arc::new(tx.clone()),
        elements_utxos(prevouts),
        index as u32,
        cmr,
        control_block,
        None,
        net.genesis.into(),
    )
}

/// The message a covenant input's BIP340 signature commits to (sig_all_hash).
pub fn sig_all_digest(env: &ElementsEnv<Arc<Transaction>>) -> [u8; 32] {
    env.c_tx_env().sighash_all().to_byte_array()
}

pub fn sign_bip340(
    privkey: &[u8; 32],
    digest: &[u8; 32],
) -> Result<([u8; 64], XOnlyPublicKey), String> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(privkey).map_err(|e| format!("bad private key: {e}"))?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest(*digest);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let (xonly, _) = kp.x_only_public_key();
    Ok((*sig.as_ref(), xonly))
}

/// Sequentia grants a Simplicity spend four weight units of execution budget per
/// witness byte (`SIMPLICITY_BUDGET_PER_WITNESS_BYTE`, src/script/script.h in
/// the node), plus a flat 50. Mirrored here so the builder refuses locally
/// rather than emitting a transaction the node will reject.
pub const BUDGET_PER_WITNESS_BYTE: u64 = 4;
const BUDGET_OFFSET: u64 = 50;
const BUDGET_MAX: u64 = 4_000_050;

fn budget_milliweight(stack_bytes: usize) -> u64 {
    (stack_bytes as u64 * BUDGET_PER_WITNESS_BYTE + BUDGET_OFFSET).min(BUDGET_MAX) * 1000
}

fn cost_milliweight(cost: simplicityhl::simplicity::Cost) -> u32 {
    // Cost's inner value is private; its Debug form is `Cost(<milliweight>)`.
    format!("{cost:?}")
        .trim_start_matches("Cost(")
        .trim_end_matches(')')
        .parse()
        .expect("Cost debug format is Cost(<n>)")
}

/// Attach the four-element Simplicity witness stack to input `index`.
/// `env = Some(..)` prunes and locally executes (the honest path); `None`
/// attaches without validation for building deliberately invalid txs.
///
/// Returns the witness stack size in bytes.
pub fn attach_simplicity(
    tx: &mut Transaction,
    index: usize,
    program: &CompiledProgram,
    witness: simplicityhl::WitnessValues,
    env: Option<&ElementsEnv<Arc<Transaction>>>,
    control_block: &simplicityhl::elements::taproot::ControlBlock,
) -> Result<usize, String> {
    let (stack, size, cost) = simplicity_stack(program, witness, env, control_block)?;
    if cost as u64 > budget_milliweight(size) {
        return Err(format!(
            "input {index}: program cost {cost} milli-WU exceeds the {} milli-WU a \
             {size} B witness stack buys",
            budget_milliweight(size)
        ));
    }
    tx.input[index].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: stack,
        pegin_witness: vec![],
    };
    Ok(size)
}

fn simplicity_stack(
    program: &CompiledProgram,
    witness: simplicityhl::WitnessValues,
    env: Option<&ElementsEnv<Arc<Transaction>>>,
    control_block: &simplicityhl::elements::taproot::ControlBlock,
) -> Result<(Vec<Vec<u8>>, usize, u32), String> {
    let node = satisfy_program(program, witness, env)?;
    let (program_bytes, witness_bytes) = node.to_vec_with_witness();
    let cmr = node.cmr();
    let stack = vec![
        witness_bytes,
        program_bytes,
        cmr.as_ref().to_vec(),
        control_block.serialize(),
    ];
    let size: usize = stack.iter().map(Vec::len).sum();
    let cost = cost_milliweight(node.bounds().cost);
    Ok((stack, size, cost))
}

/// Attach the verifier program's witness to input 0 and verify that the
/// resulting stack buys enough Simplicity execution budget.
///
/// There is no padding to size. Under the chain's budget rule every shape's
/// functional witness already covers its own static cost; this check exists so
/// that a change to the program which broke that fails here, loudly, rather
/// than at a node.
///
/// Returns (witness stack size in bytes, cost in milli-WU).
pub fn attach_verifier(
    tx: &mut Transaction,
    program: &CompiledProgram,
    shape: Shape,
    sender: &SenderWitness,
    slots: &VerifierSlots,
    env: Option<&ElementsEnv<Arc<Transaction>>>,
    control_block: &simplicityhl::elements::taproot::ControlBlock,
) -> Result<(usize, u32), String> {
    let witness = programs::verifier_witness(shape, sender, &slots.outputs, &slots.inputs)?;
    let (stack, size, cost) = simplicity_stack(program, witness, env, control_block)?;
    if cost as u64 > budget_milliweight(size) {
        return Err(format!(
            "verifier shape {shape}: cost {cost} milli-WU exceeds the {} milli-WU a \
             {size} B witness stack buys. Either the program grew or this chain is \
             still granting one weight unit per witness byte, under which these \
             covenants are unspendable by design",
            budget_milliweight(size)
        ));
    }
    tx.input[0].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: stack,
        pegin_witness: vec![],
    };
    Ok((size, cost))
}

/// The verifier's per-slot witness, sized for one shape.
pub struct VerifierSlots {
    pub outputs: Vec<SlotWitness>,
    pub inputs: Vec<InputSlotWitness>,
}

impl VerifierSlots {
    pub fn empty(shape: Shape) -> Self {
        VerifierSlots {
            outputs: vec![None; shape.n_out],
            inputs: vec![None; shape.n_in],
        }
    }
}

/// The sender proof the verifier needs: one membership proof for the whole
/// transfer, carrying the committed height windows.
pub fn sender_witness(ctx: &Ctx, sender: &XOnlyPublicKey) -> Result<SenderWitness, String> {
    let proof = ctx.wl_tree.prove(&sender.serialize()).ok_or_else(|| {
        format!("owner key {sender} is not in the whitelist: these coins are frozen")
    })?;
    Ok(SenderWitness {
        key: *sender,
        proof,
    })
}

/// Build the verifier witness slots for a transfer.
///
/// An A output paying the sender's own C_U is CHANGE and needs no slot witness
/// at all: the covenant recognises it by script equality against the sender it
/// already proved, and exempts it from the membership fold, the receive window
/// and the explicit-value requirement.
pub fn verifier_slots(ctx: &Ctx, built: &BuiltTransfer) -> Result<VerifierSlots, String> {
    let mut slots = VerifierSlots::empty(built.shape);
    let sender = built
        .a_inputs
        .first()
        .map(|(_, owner, _)| *owner)
        .ok_or("a transfer must spend at least one regulated input")?;
    let cu_sender_spk = ctx.cu_info(&sender).script_pubkey;

    for (out_idx, owner) in &built.a_outputs {
        if *out_idx == 0 || *out_idx > built.shape.n_out {
            return Err(format!(
                "A output at index {out_idx}; shape {} scans 1..={}",
                built.shape, built.shape.n_out
            ));
        }
        if built.tx.output[*out_idx].script_pubkey == cu_sender_spk {
            continue; // change: proved by the sender proof, no slot witness
        }
        let proof = ctx
            .wl_tree
            .prove(&owner.serialize())
            .ok_or_else(|| format!("recipient key {owner} is not in the whitelist"))?;
        slots.outputs[*out_idx - 1] = Some((*owner, proof));
    }
    for (in_idx, owner, outpoint) in &built.a_inputs {
        if *in_idx == 0 || *in_idx > built.shape.n_in {
            return Err(format!(
                "A input at index {in_idx}; shape {} scans 1..={} (at most {} \
                 regulated inputs per transfer)",
                built.shape,
                built.shape.n_in,
                built.shape.max_regulated_inputs()
            ));
        }
        if *owner != sender {
            return Err(format!(
                "input {in_idx} belongs to {owner}, not to {sender}: every regulated \
                 input of a transfer must have one owner"
            ));
        }
        let k = outpoint_policy_key(outpoint);
        let interval = ctx.bl_tree.prove_absent(&k).ok_or_else(|| {
            format!("outpoint {outpoint} is blacklisted: these coins are frozen")
        })?;
        slots.inputs[*in_idx - 1] = Some(interval);
    }
    Ok(slots)
}

/// Sign the fee input (P2TR key path, SIGHASH_DEFAULT).
pub fn sign_fee_input(
    net: &Net,
    tx: &mut Transaction,
    prevouts: &[TxOut],
    index: usize,
    fee_privkey: &[u8; 32],
) -> Result<(), String> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(fee_privkey).map_err(|e| format!("bad fee key: {e}"))?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (internal, _) = kp.x_only_public_key();
    let tweak = TapTweakHash::from_key_and_tweak(internal, None).to_scalar();
    let tweaked = kp
        .add_xonly_tweak(&secp, &tweak)
        .map_err(|e| format!("tweak: {e}"))?;

    let sighash = SighashCache::new(&mut *tx)
        .taproot_key_spend_signature_hash(
            index,
            &Prevouts::All(prevouts),
            SchnorrSighashType::Default,
            net.genesis,
        )
        .map_err(|e| format!("fee sighash: {e}"))?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
    tx.input[index].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![sig.as_ref().to_vec()],
        pegin_witness: vec![],
    };
    Ok(())
}

/// Per-input witness sizes of a finalized transfer, for budget reporting.
#[derive(Debug)]
pub struct WitnessReport {
    /// Which leaf of the verifier taptree spent it.
    pub shape: Shape,
    /// Verifier input's witness stack size in bytes.
    pub verifier_witness: usize,
    /// Verifier program's static cost in milli-weight-units.
    pub verifier_cost: u32,
    pub user_witnesses: Vec<usize>,
}

impl WitnessReport {
    /// Budget the verifier input buys, in weight units.
    pub fn verifier_budget(&self) -> usize {
        (budget_milliweight(self.verifier_witness) / 1000) as usize
    }

    /// Weight units the verifier program consumes (cost rounded up).
    pub fn verifier_weight(&self) -> usize {
        (self.verifier_cost as usize + 999) / 1000
    }
}

/// One-call path: build, sign and finalize a transfer with supplied keys.
/// `validate` runs every covenant on the BitMachine before returning; pass
/// false only when constructing deliberately invalid transactions.
pub fn complete_transfer(
    ctx: &Ctx,
    req: &TransferReq,
    sender_privkey: &[u8; 32],
    fee_privkey: &[u8; 32],
    validate: bool,
) -> Result<(Transaction, WitnessReport), String> {
    // `validate == false` means "assemble what was asked for and let the node
    // judge it", so the local policy preflight is skipped along with the
    // BitMachine run. Every honest path takes the checked builder.
    let built = if validate {
        build_transfer(ctx, req)?
    } else {
        build_transfer_unchecked(ctx, req)?
    };
    let mut tx = built.tx.clone();
    let shape = built.shape;

    // User inputs: sign and attach.
    let (_, u_cb) = cu_spend_info(ctx.u_cmr(), &req.sender);
    let mut user_witnesses = Vec::new();
    for idx in &built.user_inputs {
        let env = covenant_env(
            &ctx.net,
            &built.tx,
            &built.prevouts,
            *idx,
            ctx.u_cmr(),
            u_cb.clone(),
        );
        let digest = sig_all_digest(&env);
        let (sig, signer) = sign_bip340(sender_privkey, &digest)?;
        if signer != req.sender {
            return Err(format!(
                "sender private key controls {signer}, not {}",
                req.sender
            ));
        }
        let witness = programs::user_witness(&req.sender, &sig)?;
        let size = attach_simplicity(
            &mut tx,
            *idx,
            &ctx.user,
            witness,
            validate.then_some(&env),
            &u_cb,
        )?;
        user_witnesses.push(size);
    }

    // Verifier input 0.
    let p_cmr = ctx.p_cmr(shape)?;
    let p_cb = ctx.verifier_spend().control_for(shape)?.clone();
    let sender_w = sender_witness(ctx, &req.sender)?;
    let slots = if validate {
        verifier_slots(ctx, &built)?
    } else {
        // Invalid-tx path: fill what we can, leave the rest None.
        let mut slots = VerifierSlots::empty(shape);
        let cu_sender_spk = ctx.cu_info(&req.sender).script_pubkey;
        for (out_idx, owner) in &built.a_outputs {
            if (1..=shape.n_out).contains(out_idx)
                && built.tx.output[*out_idx].script_pubkey != cu_sender_spk
            {
                if let Some(proof) = ctx.wl_tree.prove(&owner.serialize()) {
                    slots.outputs[*out_idx - 1] = Some((*owner, proof));
                }
            }
        }
        for (in_idx, _owner, outpoint) in &built.a_inputs {
            if (1..=shape.n_in).contains(in_idx) {
                let k = outpoint_policy_key(outpoint);
                if let Some(interval) = ctx.bl_tree.prove_absent(&k) {
                    slots.inputs[*in_idx - 1] = Some(interval);
                }
            }
        }
        slots
    };
    let p_env = covenant_env(&ctx.net, &built.tx, &built.prevouts, 0, p_cmr, p_cb.clone());
    let (verifier_witness, verifier_cost) = attach_verifier(
        &mut tx,
        ctx.verifier_for(shape)?,
        shape,
        &sender_w,
        &slots,
        validate.then_some(&p_env),
        &p_cb,
    )?;

    // Fee input.
    sign_fee_input(&ctx.net, &mut tx, &built.prevouts, built.fee_input, fee_privkey)?;

    Ok((
        tx,
        WitnessReport {
            shape,
            verifier_witness,
            verifier_cost,
            user_witnesses,
        },
    ))
}

/// Issuer operation: policy update (recreate C_V under `new_ctx`) or halt
/// (send the verifier output to `halt_spk`).
///
/// A HALT MUST BURN V. Confinement rests on an invariant no covenant can check:
/// q units of V never exist outside a verifier covenant (see the header of
/// `programs/user.simf`). Parking V at an ordinary address breaks it, and from
/// that moment whoever holds the key can place it at input zero and let any
/// holder spend their C_U with no policy applied at all. An OP_RETURN output can
/// never be an input, so a burn leaves no such output in existence and A is
/// frozen, which is what a halt is supposed to mean. `halt_to_burn` is the
/// supported path; resuming means reissuing V, which is why the issuer keeps
/// that authority - and why that authority is as sensitive as the issuer key.
pub struct IssuerReq {
    pub verifier_outpoint: OutPoint,
    /// The context whose C_V(pi') receives V; None = halt.
    pub halt_spk: Option<Script>,
    pub fee_utxo: (OutPoint, AssetId, u64),
    pub fee_key: XOnlyPublicKey,
    pub fee_amount: u64,
    pub fee_change_spk: Script,
}

/// A provably unspendable script: a bare `OP_RETURN`. The halt target.
pub fn burn_spk() -> Script {
    Script::from(vec![0x6a])
}

impl IssuerReq {
    /// A halt that burns the verifier asset, which is the only halt that
    /// actually halts. See the note on [`complete_issuer_op`].
    pub fn halt_to_burn(
        verifier_outpoint: OutPoint,
        fee_utxo: (OutPoint, AssetId, u64),
        fee_key: XOnlyPublicKey,
        fee_amount: u64,
        fee_change_spk: Script,
    ) -> Self {
        IssuerReq {
            verifier_outpoint,
            halt_spk: Some(burn_spk()),
            fee_utxo,
            fee_key,
            fee_amount,
            fee_change_spk,
        }
    }

    /// True when this halt leaves a spendable q of V in existence, which is the
    /// one thing confinement cannot survive.
    pub fn halt_leaves_live_verifier_asset(&self) -> bool {
        match &self.halt_spk {
            None => false, // a policy update, not a halt
            Some(spk) => !spk.is_op_return(),
        }
    }
}

pub fn complete_issuer_op(
    old_ctx: &Ctx,
    new_ctx: Option<&Ctx>,
    req: &IssuerReq,
    issuer_privkey: &[u8; 32],
    fee_privkey: &[u8; 32],
) -> Result<Transaction, String> {
    let old_cv = old_ctx.cv_info();
    let dest_spk = match (&req.halt_spk, new_ctx) {
        (Some(spk), _) => spk.clone(),
        (None, Some(ctx)) => ctx.cv_info().script_pubkey.clone(),
        (None, None) => return Err("issuer op needs a new policy context or a halt script".into()),
    };
    let (fee_op, fee_asset, fee_value) = req.fee_utxo.clone();
    if fee_value < req.fee_amount {
        return Err("fee UTXO smaller than fee".into());
    }
    let fee_change = fee_value - req.fee_amount;

    let inputs = vec![plain_input(req.verifier_outpoint), plain_input(fee_op)];
    let prevouts = vec![
        explicit_out(
            old_ctx.params.asset_v,
            old_ctx.params.q,
            old_cv.script_pubkey.clone(),
        ),
        explicit_out(fee_asset, fee_value, p2tr_keypath_spk(&req.fee_key)),
    ];
    let mut outputs = vec![explicit_out(
        old_ctx.params.asset_v,
        old_ctx.params.q,
        dest_spk,
    )];
    if fee_change > 0 {
        outputs.push(explicit_out(fee_asset, fee_change, req.fee_change_spk.clone()));
    }
    outputs.push(TxOut::new_fee(req.fee_amount, fee_asset));

    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    // G(I) reads no windows, so the issuer path needs no locktime.

    // Issuer leaf spend at input 0.
    let g_cb = old_ctx.verifier_spend().issuer_control.clone();
    let env = covenant_env(&old_ctx.net, &tx, &prevouts, 0, old_ctx.g_cmr(), g_cb.clone());
    let digest = sig_all_digest(&env);
    let (sig, signer) = sign_bip340(issuer_privkey, &digest)?;
    if signer != old_ctx.issuer_key {
        return Err(format!(
            "issuer private key controls {signer}, not {}",
            old_ctx.issuer_key
        ));
    }
    let witness = programs::issuer_witness(&sig)?;
    attach_simplicity(&mut tx, 0, &old_ctx.issuer, witness, Some(&env), &g_cb)?;

    // Fee input.
    let prevouts_clone = prevouts.clone();
    sign_fee_input(&old_ctx.net, &mut tx, &prevouts_clone, 1, fee_privkey)?;

    Ok(tx)
}
