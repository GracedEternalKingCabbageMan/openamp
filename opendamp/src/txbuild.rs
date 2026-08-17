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
    SlotWitness,
};
use crate::tapscript::{cu_spend_info, cv_spend_info, CovenantSpendInfo};

/// Maximum inputs and outputs the verifier program tolerates. It asserts both
/// bounds, so a transaction exceeding either cannot be spent at all - an
/// unscanned input or output would otherwise escape the covenant.
pub const N_MAX_OUTPUTS: usize = programs::N_OUT_SLOTS + 1;
pub const N_MAX_INPUTS: usize = programs::N_IN_SLOTS + 1;

/// Everything derived from the per-asset constants and one policy version.
pub struct Ctx {
    pub net: Net,
    pub params: AssetParams,
    pub issuer_key: XOnlyPublicKey,
    pub wl_tree: dmt::Tree,
    pub bl_tree: dmt::IntervalTree,
    pub user: CompiledProgram,
    pub verifier: CompiledProgram,
    pub issuer: CompiledProgram,
}

impl Ctx {
    /// `bl_outpoint_keys` are the blacklisted outpoints' policy keys
    /// (`dmt::outpoint_key`), not the outpoints themselves.
    pub fn new(
        net: Net,
        params: AssetParams,
        issuer_key: XOnlyPublicKey,
        wl_keys: &[XOnlyPublicKey],
        bl_outpoint_keys: &[[u8; 32]],
    ) -> Result<Self, String> {
        let wl_tree = dmt::Tree::new(wl_keys.iter().map(|k| k.serialize()).collect())?;
        let bl_tree = dmt::IntervalTree::new(bl_outpoint_keys.to_vec())?;
        let user = compile_user(&params)?;
        let u_cmr = user.commit().cmr();
        let verifier = compile_verifier(&params, u_cmr, &wl_tree.root(), &bl_tree.root())?;
        let issuer = compile_issuer(&issuer_key)?;
        Ok(Ctx {
            net,
            params,
            issuer_key,
            wl_tree,
            bl_tree,
            user,
            verifier,
            issuer,
        })
    }

    pub fn u_cmr(&self) -> simplicityhl::simplicity::Cmr {
        self.user.commit().cmr()
    }
    pub fn p_cmr(&self) -> simplicityhl::simplicity::Cmr {
        self.verifier.commit().cmr()
    }
    pub fn g_cmr(&self) -> simplicityhl::simplicity::Cmr {
        self.issuer.commit().cmr()
    }

    pub fn cu_info(&self, owner: &XOnlyPublicKey) -> CovenantSpendInfo {
        cu_spend_info(self.u_cmr(), owner).0
    }

    pub fn cv_info(&self) -> CovenantSpendInfo {
        cv_spend_info(self.p_cmr(), self.g_cmr()).0
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

fn plain_input(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
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
    /// verifier proves each owner is whitelisted and each outpoint unlisted, so
    /// the builder has to know both.
    pub a_inputs: Vec<(usize, XOnlyPublicKey, OutPoint)>,
    /// Input index of the fee UTXO.
    pub fee_input: usize,
}

pub fn build_transfer(ctx: &Ctx, req: &TransferReq) -> Result<BuiltTransfer, String> {
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

    if outputs.len() > N_MAX_OUTPUTS {
        return Err(format!(
            "{} outputs exceeds the covenant's N_max of {N_MAX_OUTPUTS}",
            outputs.len()
        ));
    }

    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
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
    })
}

/// The blacklist policy key of an outpoint. `OutPoint`'s txid is stored in
/// internal byte order, which is exactly what the covenant hashes.
pub fn outpoint_policy_key(outpoint: &OutPoint) -> [u8; 32] {
    dmt::outpoint_key(
        &outpoint.txid.to_byte_array(),
        outpoint.vout,
    )
}

/// Script pubkey of a P2TR key-path output for `internal_key` (no tree).
pub fn p2tr_keypath_spk(internal_key: &XOnlyPublicKey) -> Script {
    let secp = Secp256k1::verification_only();
    let tweak = TapTweakHash::from_key_and_tweak(*internal_key, None).to_scalar();
    let (out_key, _) = internal_key
        .add_tweak(&secp, &tweak)
        .expect("tweak is valid");
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51);
    spk.push(0x20);
    spk.extend_from_slice(&out_key.serialize());
    Script::from(spk)
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

pub fn sign_bip340(privkey: &[u8; 32], digest: &[u8; 32]) -> Result<([u8; 64], XOnlyPublicKey), String> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(privkey).map_err(|e| format!("bad private key: {e}"))?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest(*digest);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let (xonly, _) = kp.x_only_public_key();
    Ok((*sig.as_ref(), xonly))
}

/// Attach the four-element Simplicity witness stack to input `index`.
/// `env = Some(..)` prunes and locally executes (the honest path); `None`
/// attaches without validation for building deliberately invalid txs.
pub fn attach_simplicity(
    tx: &mut Transaction,
    index: usize,
    program: &CompiledProgram,
    witness: simplicityhl::WitnessValues,
    env: Option<&ElementsEnv<Arc<Transaction>>>,
    control_block: &simplicityhl::elements::taproot::ControlBlock,
) -> Result<usize, String> {
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
    let cost = node.bounds().cost;
    if !cost.is_budget_valid(&stack) {
        return Err(format!(
            "input {index}: program cost {cost:?} exceeds the witness budget \
             ({size} B stack); the witness needs padding"
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

/// Attach the verifier program's witness to input 0 and verify that the
/// resulting stack buys enough Simplicity execution budget.
///
/// Budget = serialized witness-stack size + 50 weight units; cost is a static
/// bound over the whole program DAG. The program reserves a fixed-size inert
/// pad (see BUDGET_PAD in verifier.simf) precisely so this check passes; if it
/// ever fails, the program changed and BUDGET_PAD_LEN needs re-sizing rather
/// than the transaction being patched.
///
/// Returns (witness stack size in bytes, pad length, cost in milli-WU).
pub fn attach_verifier(
    tx: &mut Transaction,
    program: &CompiledProgram,
    slots: &VerifierSlots,
    env: Option<&ElementsEnv<Arc<Transaction>>>,
    control_block: &simplicityhl::elements::taproot::ControlBlock,
) -> Result<(usize, usize, u32), String> {
    let witness = programs::verifier_witness(&slots.outputs, &slots.inputs)?;
    let node = satisfy_program(program, witness, env)?;
    let (program_bytes, witness_bytes) = node.to_vec_with_witness();
    let cmr = node.cmr();
    let stack = vec![
        witness_bytes,
        program_bytes,
        cmr.as_ref().to_vec(),
        control_block.serialize(),
    ];
    let cost = node.bounds().cost;
    let size: usize = stack.iter().map(Vec::len).sum();
    if !cost.is_budget_valid(&stack) {
        return Err(format!(
            "verifier cost {cost:?} exceeds the budget bought by a {size} B \
             witness stack; raise BUDGET_PAD_LEN (currently {})",
            programs::BUDGET_PAD_LEN
        ));
    }
    tx.input[0].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: stack,
        pegin_witness: vec![],
    };
    Ok((size, programs::BUDGET_PAD_LEN, cost_milliweight(cost)))
}

fn cost_milliweight(cost: simplicityhl::simplicity::Cost) -> u32 {
    // Cost's inner value is private; its Debug form is `Cost(<milliweight>)`.
    format!("{cost:?}")
        .trim_start_matches("Cost(")
        .trim_end_matches(')')
        .parse()
        .unwrap_or(0)
}

/// The verifier's per-slot witness: recipient proofs for outputs 1..7 and owner
/// proofs for inputs 1..7.
#[derive(Default)]
pub struct VerifierSlots {
    pub outputs: [SlotWitness; programs::N_OUT_SLOTS],
    pub inputs: [programs::InputSlotWitness; programs::N_IN_SLOTS],
}

/// Build the verifier witness slots for a transfer: every A output needs its
/// recipient's membership proof, and every A input needs its owner's.
pub fn verifier_slots(ctx: &Ctx, built: &BuiltTransfer) -> Result<VerifierSlots, String> {
    let mut slots = VerifierSlots::default();
    for (out_idx, owner) in &built.a_outputs {
        if *out_idx == 0 || *out_idx > programs::N_OUT_SLOTS {
            return Err(format!(
                "A output at index {out_idx}; the covenant scans 1..={}",
                programs::N_OUT_SLOTS
            ));
        }
        let proof = ctx
            .wl_tree
            .prove(&owner.serialize())
            .ok_or_else(|| format!("recipient key {owner} is not in the whitelist"))?;
        slots.outputs[*out_idx - 1] = Some((*owner, proof));
    }
    for (in_idx, owner, outpoint) in &built.a_inputs {
        if *in_idx == 0 || *in_idx > programs::N_IN_SLOTS {
            return Err(format!(
                "A input at index {in_idx}; the covenant scans 1..={} \
                 (at most {} regulated inputs per transfer)",
                programs::N_IN_SLOTS,
                programs::N_IN_SLOTS - 1
            ));
        }
        let proof = ctx.wl_tree.prove(&owner.serialize()).ok_or_else(|| {
            format!("owner key {owner} is not in the whitelist: these coins are frozen")
        })?;
        let k = outpoint_policy_key(outpoint);
        let interval = ctx.bl_tree.prove_absent(&k).ok_or_else(|| {
            format!("outpoint {outpoint} is blacklisted: these coins are frozen")
        })?;
        slots.inputs[*in_idx - 1] = Some((*owner, proof, interval));
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
    /// Verifier input's witness stack size in bytes (padding included).
    pub verifier_witness: usize,
    /// How many of those bytes are inert budget padding.
    pub verifier_pad: usize,
    /// Verifier program's static cost in milli-weight-units.
    pub verifier_cost: u32,
    pub user_witnesses: Vec<usize>,
}

impl WitnessReport {
    /// Budget the verifier input buys, in weight units (stack size + 50).
    pub fn verifier_budget(&self) -> usize {
        self.verifier_witness + 50
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
    let built = build_transfer(ctx, req)?;
    let mut tx = built.tx.clone();

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
    let (_, p_cb, _) = cv_spend_info(ctx.p_cmr(), ctx.g_cmr());
    let slots = if validate {
        verifier_slots(ctx, &built)?
    } else {
        // Invalid-tx path: fill what we can, leave the rest None.
        let mut slots = VerifierSlots::default();
        for (out_idx, owner) in &built.a_outputs {
            if (1..=programs::N_OUT_SLOTS).contains(out_idx) {
                if let Some(proof) = ctx.wl_tree.prove(&owner.serialize()) {
                    slots.outputs[*out_idx - 1] = Some((*owner, proof));
                }
            }
        }
        for (in_idx, owner, outpoint) in &built.a_inputs {
            if (1..=programs::N_IN_SLOTS).contains(in_idx) {
                let k = outpoint_policy_key(outpoint);
                if let (Some(proof), Some(interval)) = (
                    ctx.wl_tree.prove(&owner.serialize()),
                    ctx.bl_tree.prove_absent(&k),
                ) {
                    slots.inputs[*in_idx - 1] = Some((*owner, proof, interval));
                }
            }
        }
        slots
    };
    let p_env = covenant_env(
        &ctx.net,
        &built.tx,
        &built.prevouts,
        0,
        ctx.p_cmr(),
        p_cb.clone(),
    );
    let (verifier_witness, verifier_pad, verifier_cost) = attach_verifier(
        &mut tx,
        &ctx.verifier,
        &slots,
        validate.then_some(&p_env),
        &p_cb,
    )?;

    // Fee input.
    sign_fee_input(&ctx.net, &mut tx, &built.prevouts, built.fee_input, fee_privkey)?;

    Ok((
        tx,
        WitnessReport {
            verifier_witness,
            verifier_pad,
            verifier_cost,
            user_witnesses,
        },
    ))
}

/// Issuer operation: policy update (recreate C_V under `new_ctx`) or halt
/// (send the verifier output to `halt_spk`).
pub struct IssuerReq {
    pub verifier_outpoint: OutPoint,
    /// The context whose C_V(pi') receives V; None = halt.
    pub halt_spk: Option<Script>,
    pub fee_utxo: (OutPoint, AssetId, u64),
    pub fee_key: XOnlyPublicKey,
    pub fee_amount: u64,
    pub fee_change_spk: Script,
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

    // Issuer leaf spend at input 0.
    let (_, _, g_cb) = cv_spend_info(old_ctx.p_cmr(), old_ctx.g_cmr());
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
