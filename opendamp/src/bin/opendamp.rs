//! OpenDAMP CLI: derive covenant addresses, print the template registry, build
//! and finalize transfers offline, and perform issuer operations.
//!
//! Everything except broadcasting works with no node: a policy snapshot plus
//! explicit UTXO data is enough (milestone M3).
//!
//!   opendamp derive   --snapshot S [--owner X]...
//!   opendamp registry --snapshot S
//!   opendamp vectors  --snapshot S [--out FILE]
//!   opendamp transfer-build    --snapshot S --request R
//!   opendamp transfer-finalize --snapshot S --request R
//!   opendamp issuer-update --snapshot S --next-snapshot S' --request R \
//!                          --issuer-privkey HEX
//!   opendamp halt          --snapshot S --to-spk HEX --request R \
//!                          --issuer-privkey HEX

use std::collections::HashMap;
use std::str::FromStr;

use opendamp::dmt;
use opendamp::elements::hashes::Hash as _;
use opendamp::elements::pset::serialize::Serialize as _;
use opendamp::elements::secp256k1_zkp::XOnlyPublicKey;
use opendamp::elements::{AssetId, OutPoint, Script, Txid};
use opendamp::hexutil::{hex, unhex, unhex32};
use opendamp::net::Net;
use opendamp::programs::{self, AssetParams};
use opendamp::tapscript::{
    cu_spend_info, cv_spend_info, simplicity_leaf_hash, tap_branch, tap_data_hash,
};
use opendamp::txbuild::{
    build_transfer, complete_issuer_op, complete_transfer, covenant_env, sig_all_digest, Ctx,
    IssuerReq, TransferReq,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// --------------------------------------------------------------- argument glue

struct Args {
    cmd: String,
    flags: HashMap<String, Vec<String>>,
}

fn usage() -> String {
    "usage: opendamp <derive|registry|vectors|transfer-build|transfer-finalize|\
     issuer-update|halt> --snapshot FILE [...]"
        .to_string()
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().ok_or_else(usage)?;
    let mut flags: HashMap<String, Vec<String>> = HashMap::new();
    while let Some(a) = it.next() {
        let name = a
            .strip_prefix("--")
            .ok_or_else(|| format!("expected a --flag, got {a}"))?
            .to_string();
        let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
        flags.entry(name).or_default().push(value);
    }
    Ok(Args { cmd, flags })
}

impl Args {
    fn one(&self, name: &str) -> Result<&str, String> {
        self.opt(name).ok_or_else(|| format!("missing --{name}"))
    }
    fn opt(&self, name: &str) -> Option<&str> {
        self.flags
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }
    fn many(&self, name: &str) -> Vec<&str> {
        self.flags
            .get(name)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

// ------------------------------------------------------------------- snapshot

/// The subset of the design doc's `snapshot/v1` this tool consumes, plus the
/// chain selector it needs to derive addresses and sighashes.
#[derive(serde::Deserialize)]
struct Snapshot {
    asset: String,
    verifier_asset: String,
    q: u64,
    #[serde(default = "default_tree")]
    tree: String,
    issuer_update_key: String,
    #[serde(default)]
    seq: u64,
    predicates: Predicates,
    #[serde(default = "default_network")]
    network: String,
    #[serde(default)]
    genesis: Option<String>,
}

fn default_tree() -> String {
    "dmt-v1".to_string()
}

fn default_network() -> String {
    "testnet".to_string()
}

#[derive(serde::Deserialize)]
struct Predicates {
    whitelist: Whitelist,
    #[serde(default)]
    blacklist: Option<Blacklist>,
    /// Carried in the snapshot and committed in pi, but no program reads it; see
    /// STATUS.md.
    #[serde(default)]
    limit: Option<u64>,
}

#[derive(serde::Deserialize)]
struct Whitelist {
    entries: Vec<String>,
}

/// Blacklisted outpoints. `entries` are outpoints in the form the operator sees
/// them (display-order txid plus vout); `keys` accepts pre-hashed policy keys for
/// a registrar that would rather not republish raw outpoints.
#[derive(serde::Deserialize, Default)]
struct Blacklist {
    #[serde(default)]
    entries: Vec<OutPointRef>,
    #[serde(default)]
    keys: Vec<String>,
}

impl Blacklist {
    fn policy_keys(&self) -> Result<Vec<[u8; 32]>, String> {
        let mut out = Vec::new();
        for e in &self.entries {
            let op = outpoint(&e.txid, e.vout)?;
            out.push(opendamp::txbuild::outpoint_policy_key(&op));
        }
        for k in &self.keys {
            out.push(unhex32(k)?);
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}

fn xonly(s: &str) -> Result<XOnlyPublicKey, String> {
    XOnlyPublicKey::from_str(s.trim()).map_err(|e| format!("bad x-only key {s}: {e}"))
}

fn asset(s: &str) -> Result<AssetId, String> {
    AssetId::from_str(s.trim()).map_err(|e| format!("bad asset id {s}: {e}"))
}

fn load_snapshot(path: &str) -> Result<(Snapshot, Ctx), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let snap: Snapshot = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    if snap.tree != "dmt-v1" {
        return Err(format!(
            "unsupported tree {:?}; this build implements dmt-v1 only",
            snap.tree
        ));
    }
    let net = Net::from_name(&snap.network, snap.genesis.as_deref())?;
    let params = AssetParams {
        asset_a: asset(&snap.asset)?,
        asset_v: asset(&snap.verifier_asset)?,
        q: snap.q,
    };
    let issuer = xonly(&snap.issuer_update_key)?;
    let wl: Vec<XOnlyPublicKey> = snap
        .predicates
        .whitelist
        .entries
        .iter()
        .map(|s| xonly(s))
        .collect::<Result<_, _>>()?;
    let bl = match &snap.predicates.blacklist {
        Some(b) => b.policy_keys()?,
        None => Vec::new(),
    };
    if snap.predicates.limit.is_some() {
        eprintln!(
            "warning: this snapshot sets a transfer limit, which no program in this \
             build reads. It is committed in pi but NOT enforced. See STATUS.md."
        );
    }
    let ctx = Ctx::new(net, params, issuer, &wl, &bl)?;
    Ok((snap, ctx))
}

/// pi for this snapshot. Both tree roots are committed, because both are read by
/// P(pi) and therefore enforced by consensus.
fn pi_of(snap: &Snapshot, ctx: &Ctx) -> [u8; 32] {
    let rules = opendamp::policy::rules_root(
        Some(ctx.bl_tree.root()),
        Some(ctx.wl_tree.root()),
        snap.predicates.limit,
        None,
    );
    opendamp::policy::pi(
        programs::asset_internal_bytes(&ctx.params.asset_a),
        snap.seq,
        rules,
    )
}

// ------------------------------------------------------------- transfer request

#[derive(serde::Deserialize)]
struct RequestFile {
    sender: String,
    #[serde(default)]
    sender_privkey: Option<String>,
    #[serde(default)]
    sender_utxos: Vec<UtxoRef>,
    #[serde(default)]
    recipient: Option<String>,
    #[serde(default)]
    amount: u64,
    verifier_outpoint: OutPointRef,
    fee: FeeRef,
}

#[derive(serde::Deserialize)]
struct UtxoRef {
    txid: String,
    vout: u32,
    value: u64,
}

#[derive(serde::Deserialize)]
struct OutPointRef {
    txid: String,
    vout: u32,
}

#[derive(serde::Deserialize)]
struct FeeRef {
    txid: String,
    vout: u32,
    asset: String,
    value: u64,
    key: String,
    #[serde(default)]
    privkey: Option<String>,
    amount: u64,
    change_spk: String,
}

fn outpoint(txid: &str, vout: u32) -> Result<OutPoint, String> {
    Ok(OutPoint::new(
        Txid::from_str(txid.trim()).map_err(|e| format!("bad txid {txid}: {e}"))?,
        vout,
    ))
}

fn load_request(path: &str) -> Result<RequestFile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

fn to_transfer_req(r: &RequestFile) -> Result<TransferReq, String> {
    let recipient = r
        .recipient
        .as_deref()
        .ok_or("request needs a recipient for a transfer")?;
    let mut utxos = Vec::new();
    for u in &r.sender_utxos {
        utxos.push((outpoint(&u.txid, u.vout)?, u.value));
    }
    Ok(TransferReq {
        sender: xonly(&r.sender)?,
        sender_utxos: utxos,
        recipient: xonly(recipient)?,
        amount: r.amount,
        verifier_outpoint: outpoint(&r.verifier_outpoint.txid, r.verifier_outpoint.vout)?,
        fee_utxo: (
            outpoint(&r.fee.txid, r.fee.vout)?,
            asset(&r.fee.asset)?,
            r.fee.value,
        ),
        fee_key: xonly(&r.fee.key)?,
        fee_amount: r.fee.amount,
        fee_change_spk: Script::from(unhex(&r.fee.change_spk)?),
        recipient_spk_override: None,
    })
}

// ------------------------------------------------------------------- commands

fn run() -> Result<(), String> {
    let args = parse_args()?;
    match args.cmd.as_str() {
        "derive" => cmd_derive(&args),
        "registry" => cmd_registry(&args),
        "vectors" => cmd_vectors(&args),
        "transfer-build" => cmd_transfer_build(&args),
        "transfer-finalize" => cmd_transfer_finalize(&args),
        "issuer-update" => cmd_issuer(&args, false),
        "halt" => cmd_issuer(&args, true),
        other => Err(format!("unknown command {other}\n{}", usage())),
    }
}

fn owner_list<'a>(args: &'a Args, snap: &'a Snapshot) -> Vec<&'a str> {
    let owners = args.many("owner");
    if owners.is_empty() {
        snap.predicates
            .whitelist
            .entries
            .iter()
            .map(String::as_str)
            .collect()
    } else {
        owners
    }
}

fn cmd_derive(args: &Args) -> Result<(), String> {
    let (snap, ctx) = load_snapshot(args.one("snapshot")?)?;
    println!("network        {}", snap.network);
    println!("asset A        {}", ctx.params.asset_a);
    println!("verifier V     {}", ctx.params.asset_v);
    println!("q              {}", ctx.params.q);
    println!("policy seq     {}", snap.seq);
    println!("whitelist root {}", hex(&ctx.wl_tree.root()));
    println!("blacklist root {}", hex(&ctx.bl_tree.root()));
    println!("pi             {}", hex(&pi_of(&snap, &ctx)));
    println!("U   CMR        {}", ctx.u_cmr());
    println!("P   CMR        {}", ctx.p_cmr());
    println!("G   CMR        {}", ctx.g_cmr());
    let cv = ctx.cv_info();
    println!("C_V(pi) spk    {}", hex(cv.script_pubkey.as_bytes()));
    println!("C_V(pi)        {}", cv.address(ctx.net.address_params));
    for o in owner_list(args, &snap) {
        let cu = ctx.cu_info(&xonly(o)?);
        println!(
            "C_U({o}) {} (spk {})",
            cu.address(ctx.net.address_params),
            hex(cu.script_pubkey.as_bytes())
        );
    }
    Ok(())
}

fn cmd_registry(args: &Args) -> Result<(), String> {
    let (snap, ctx) = load_snapshot(args.one("snapshot")?)?;
    // Wallets and the registrar verify CMRs against this pinning, never against
    // a locally compiled artifact (design doc section 8).
    let doc = serde_json::json!({
        "v": 1,
        "tree": "dmt-v1",
        "asset": ctx.params.asset_a.to_string(),
        "verifier_asset": ctx.params.asset_v.to_string(),
        "verifier_amount": ctx.params.q,
        "policy": {
            "seq": snap.seq,
            "pi": hex(&pi_of(&snap, &ctx)),
            "whitelist_root": hex(&ctx.wl_tree.root()),
            "blacklist_root": hex(&ctx.bl_tree.root()),
            "blacklisted_outpoints": ctx.bl_tree.keys.len(),
        },
        "programs": {
            format!("opendamp/user/v1/{}", ctx.params.asset_a): {
                "cmr": ctx.u_cmr().to_string(),
                "tapleaf": hex(&simplicity_leaf_hash(ctx.u_cmr()).to_byte_array()),
                "source": "programs/user.simf",
            },
            format!("opendamp/verifier/v1/{}/seq{}", ctx.params.asset_a, snap.seq): {
                "cmr": ctx.p_cmr().to_string(),
                "tapleaf": hex(&simplicity_leaf_hash(ctx.p_cmr()).to_byte_array()),
                "source": "programs/verifier.simf",
                "n_max_outputs": opendamp::txbuild::N_MAX_OUTPUTS,
                "budget_pad_words": programs::BUDGET_PAD_WORDS,
            },
            format!("opendamp/issuer/v1/{}", ctx.issuer_key): {
                "cmr": ctx.g_cmr().to_string(),
                "tapleaf": hex(&simplicity_leaf_hash(ctx.g_cmr()).to_byte_array()),
                "source": "programs/issuer.simf",
            },
        },
        "verifier_spk": hex(ctx.cv_info().script_pubkey.as_bytes()),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// Golden derivation vectors, so an independent implementation (the Go policy
/// server) can check its taproot construction byte for byte.
fn cmd_vectors(args: &Args) -> Result<(), String> {
    let (snap, ctx) = load_snapshot(args.one("snapshot")?)?;
    // Address encoding does not depend on the chain's genesis, so both chains'
    // addresses are emitted whatever the snapshot selects.
    let testnet_params = Net::testnet().address_params;
    let regtest_params: &'static opendamp::elements::AddressParams =
        &opendamp::net::ELEMENTS_REGTEST_ADDRESS_PARAMS;
    let u_leaf = simplicity_leaf_hash(ctx.u_cmr()).to_byte_array();
    let p_leaf = simplicity_leaf_hash(ctx.p_cmr()).to_byte_array();
    let g_leaf = simplicity_leaf_hash(ctx.g_cmr()).to_byte_array();

    let mut owners = Vec::new();
    for o in owner_list(args, &snap) {
        let key = xonly(o)?;
        let data = tap_data_hash(&key.serialize()).to_byte_array();
        let root = tap_branch(u_leaf, data);
        let (cu, cb) = cu_spend_info(ctx.u_cmr(), &key);
        owners.push(serde_json::json!({
            "owner_xonly": o,
            "tapdata_hash": hex(&data),
            "user_tapleaf_hash": hex(&u_leaf),
            "merkle_root": hex(&root.to_byte_array()),
            "output_key": hex(&cu.output_key.serialize()),
            "output_key_parity_odd": format!("{:?}", cu.output_parity) == "Odd",
            "script_pubkey": hex(cu.script_pubkey.as_bytes()),
            "control_block": hex(&cb.serialize()),
            "address_testnet": cu.address(testnet_params).to_string(),
            "address_regtest": cu.address(regtest_params).to_string(),
            "dmt_whitelist_index": ctx.wl_tree.slot_of(&key.serialize()),
        }));
    }

    let (cv, p_cb, g_cb) = cv_spend_info(ctx.p_cmr(), ctx.g_cmr());
    let doc = serde_json::json!({
        "v": 1,
        "note": "OpenDAMP taproot derivation golden vectors. TapLeaf/elements, \
                 TapBranch/elements and TapTweak/elements are BIP341-style tagged hashes \
                 (SHA256(SHA256(tag)||SHA256(tag)||msg)) with the /elements suffix; TapData \
                 is the bare string \"TapData\", tagged the same way. A Simplicity leaf \
                 hashes as H_TapLeaf(0xbe || compact_size(32) || CMR). TapBranch sorts its \
                 two children lexicographically; TapData sorts nothing. All hex is in \
                 internal byte order except asset ids and CMRs, which print reversed, as \
                 txids do.",
        "nums_internal_key": opendamp::net::NUMS_HEX,
        "simplicity_leaf_version": 0xbe,
        "asset": ctx.params.asset_a.to_string(),
        "asset_internal_bytes": hex(&programs::asset_internal_bytes(&ctx.params.asset_a)),
        "verifier_asset": ctx.params.asset_v.to_string(),
        "verifier_asset_internal_bytes": hex(&programs::asset_internal_bytes(&ctx.params.asset_v)),
        "verifier_amount": ctx.params.q,
        "issuer_key": ctx.issuer_key.to_string(),
        "policy": {
            "seq": snap.seq,
            "whitelist_entries": snap.predicates.whitelist.entries,
            "whitelist_root": hex(&ctx.wl_tree.root()),
            "blacklist_root": hex(&ctx.bl_tree.root()),
            "blacklisted_outpoint_keys": ctx.bl_tree.keys.iter()
                .map(|k| hex(k)).collect::<Vec<_>>(),
            "pi": hex(&pi_of(&snap, &ctx)),
        },
        "programs": {
            "u_cmr": ctx.u_cmr().to_string(),
            "u_tapleaf_hash": hex(&u_leaf),
            "p_cmr": ctx.p_cmr().to_string(),
            "p_tapleaf_hash": hex(&p_leaf),
            "g_cmr": ctx.g_cmr().to_string(),
            "g_tapleaf_hash": hex(&g_leaf),
            "budget_pad_words": programs::BUDGET_PAD_WORDS,
            "n_max_outputs": opendamp::txbuild::N_MAX_OUTPUTS,
            "n_max_inputs": opendamp::txbuild::N_MAX_INPUTS,
        },
        "user_covenants": owners,
        "verifier_covenant": {
            "merkle_root": hex(&cv.merkle_root.to_byte_array()),
            "output_key": hex(&cv.output_key.serialize()),
            "output_key_parity_odd": format!("{:?}", cv.output_parity) == "Odd",
            "script_pubkey": hex(cv.script_pubkey.as_bytes()),
            "control_block_primary": hex(&p_cb.serialize()),
            "control_block_issuer": hex(&g_cb.serialize()),
            "address_testnet": cv.address(testnet_params).to_string(),
            "address_regtest": cv.address(regtest_params).to_string(),
        },
        "dmt_v1": {
            "depth": dmt::DEPTH,
            "guard_lo": hex(&dmt::GUARD_LO),
            "guard_hi": hex(&dmt::GUARD_HI),
            "leaf_of_guard_lo": hex(&dmt::leaf_hash(&dmt::GUARD_LO)),
            "leaf_of_guard_hi": hex(&dmt::leaf_hash(&dmt::GUARD_HI)),
            "empty_root": hex(&dmt::Tree::new(vec![])?.root()),
            "interval_leaf_of_guards": hex(&dmt::interval_leaf_hash(&dmt::GUARD_LO, &dmt::GUARD_HI)),
            "interval_pad_leaf": hex(&dmt::interval_leaf_hash(&dmt::GUARD_HI, &dmt::GUARD_HI)),
            "empty_blacklist_root": hex(&dmt::IntervalTree::new(vec![])?.root()),
        },
    });
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    match args.opt("out") {
        Some(path) => {
            std::fs::write(path, format!("{text}\n"))
                .map_err(|e| format!("writing {path}: {e}"))?;
            eprintln!("wrote {path}");
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn cmd_transfer_build(args: &Args) -> Result<(), String> {
    let (_, ctx) = load_snapshot(args.one("snapshot")?)?;
    let req_file = load_request(args.one("request")?)?;
    let req = to_transfer_req(&req_file)?;
    let built = build_transfer(&ctx, &req)?;

    // The digest each user input's owner must sign (BIP340 over sig_all_hash).
    let (_, u_cb) = cu_spend_info(ctx.u_cmr(), &req.sender);
    let mut sighashes = Vec::new();
    for idx in &built.user_inputs {
        let env = covenant_env(
            &ctx.net,
            &built.tx,
            &built.prevouts,
            *idx,
            ctx.u_cmr(),
            u_cb.clone(),
        );
        sighashes.push(serde_json::json!({
            "input": idx,
            "sig_all_hash": hex(&sig_all_digest(&env)),
        }));
    }
    // Membership proofs are resolved here too, so a missing snapshot entry is a
    // build-time error rather than a mystery at broadcast.
    let slots = opendamp::txbuild::verifier_slots(&ctx, &built)?;
    let describe = |slots: &[opendamp::programs::SlotWitness], kind: &str| {
        slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                s.as_ref().map(|(key, proof)| {
                    serde_json::json!({
                        kind: i + 1,
                        "key": hex(&key.serialize()),
                        "dmt_index": proof.index,
                    })
                })
            })
            .collect::<Vec<_>>()
    };
    let output_proofs = describe(&slots.outputs, "output");
    let input_proofs: Vec<serde_json::Value> = slots
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            s.as_ref().map(|(key, owner_proof, interval)| {
                serde_json::json!({
                    "input": i + 1,
                    "owner": hex(&key.serialize()),
                    "dmt_index": owner_proof.index,
                    "blacklist_interval": {
                        "lo": hex(&interval.lo),
                        "hi": hex(&interval.hi),
                        "dmt_index": interval.proof.index,
                    },
                })
            })
        })
        .collect();

    let doc = serde_json::json!({
        "unsigned_tx": hex(&built.tx.serialize()),
        "a_outputs": built.a_outputs.iter()
            .map(|(i, k)| serde_json::json!({"output": i, "owner": hex(&k.serialize())}))
            .collect::<Vec<_>>(),
        "user_inputs": sighashes,
        "whitelist_proofs": {
            "recipients": output_proofs,
            "owners": input_proofs,
        },
        "fee_input": built.fee_input,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn cmd_transfer_finalize(args: &Args) -> Result<(), String> {
    let (_, ctx) = load_snapshot(args.one("snapshot")?)?;
    let req_file = load_request(args.one("request")?)?;
    let req = to_transfer_req(&req_file)?;

    let sender_sk = req_file.sender_privkey.as_deref().ok_or(
        "the CLI finalizes with request.sender_privkey; externally produced \
         signatures go through the library API (txbuild::attach_simplicity)",
    )?;
    let fee_sk = req_file
        .fee
        .privkey
        .as_deref()
        .ok_or("request.fee.privkey is required to sign the fee input")?;

    let (tx, report) =
        complete_transfer(&ctx, &req, &unhex32(sender_sk)?, &unhex32(fee_sk)?, true)?;
    eprintln!(
        "verifier input: witness {} B ({} B pad), cost {} milli-WU = {} WU, \
         budget {} WU, headroom {} WU",
        report.verifier_witness,
        report.verifier_pad,
        report.verifier_cost,
        report.verifier_weight(),
        report.verifier_budget(),
        report.verifier_budget() as i64 - report.verifier_weight() as i64,
    );
    eprintln!("user inputs: {:?} B", report.user_witnesses);
    println!("{}", hex(&tx.serialize()));
    Ok(())
}

fn cmd_issuer(args: &Args, halt: bool) -> Result<(), String> {
    let (_, ctx) = load_snapshot(args.one("snapshot")?)?;
    let req_file = load_request(args.one("request")?)?;
    let issuer_sk = unhex32(args.one("issuer-privkey")?)?;
    let fee_sk = unhex32(
        req_file
            .fee
            .privkey
            .as_deref()
            .ok_or("request.fee.privkey is required")?,
    )?;

    let next = if halt {
        None
    } else {
        Some(load_snapshot(args.one("next-snapshot")?)?.1)
    };
    let req = IssuerReq {
        verifier_outpoint: outpoint(
            &req_file.verifier_outpoint.txid,
            req_file.verifier_outpoint.vout,
        )?,
        halt_spk: if halt {
            Some(Script::from(unhex(args.one("to-spk")?)?))
        } else {
            None
        },
        fee_utxo: (
            outpoint(&req_file.fee.txid, req_file.fee.vout)?,
            asset(&req_file.fee.asset)?,
            req_file.fee.value,
        ),
        fee_key: xonly(&req_file.fee.key)?,
        fee_amount: req_file.fee.amount,
        fee_change_spk: Script::from(unhex(&req_file.fee.change_spk)?),
    };
    let tx = complete_issuer_op(&ctx, next.as_ref(), &req, &issuer_sk, &fee_sk)?;
    match &next {
        Some(n) => eprintln!(
            "verifier moves to {}",
            n.cv_info().address(n.net.address_params)
        ),
        None => eprintln!("verifier asset leaves the covenant (halt)"),
    }
    println!("{}", hex(&tx.serialize()));
    Ok(())
}
