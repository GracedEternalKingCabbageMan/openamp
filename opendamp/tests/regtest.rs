//! Functional proof against a real Sequentia node on elementsregtest.
//!
//! Ignored by default (it spawns a node). Run with:
//!
//!     cargo test --test regtest -- --ignored --nocapture
//!
//! Binary discovery: $OPENDAMP_NODE_BIN (path to sequentiad/elementsd), else
//! /home/aejkohl/Sequentia/src/sequentiad, else src/elementsd. The matching
//! *-cli binary must sit next to it.
//!
//! Proves, printing every txid:
//!   1. issue A and V, fund C_U(alice) and C_V(pi0 = whitelist {alice,bob})
//!   2. alice -> bob transfer with no third party: builds, broadcasts, confirms
//!   3. confinement refusal: A to a plain address is rejected by the node
//!   4. recipient whitelist: carol has no proof; a reused proof is rejected;
//!      and the policy version is bound into the verifier address
//!   5. issuer update to pi1 (adds carol), then alice -> carol succeeds
//!   7. THE FREEZE: an update removing alice stops alice SPENDING - her stale
//!      proof cannot be pruned and its unpruned form is refused, claiming bob's
//!      whitelisted identity for her input is refused, bob is unaffected, and a
//!      further update restores her
//!   8. BLACKLIST: an update listing one of alice's outpoints stops that UTXO
//!      alone, and lifting the listing frees it again
//!   6. halt: V to a plain address; afterwards no transfer can satisfy input 0
//!      (last, because it ends every transfer)

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use opendamp::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use opendamp::elements::pset::serialize::Serialize;
use opendamp::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
use opendamp::hexutil::hex;
use opendamp::net::Net;
use opendamp::programs::{self, AssetParams};
use opendamp::txbuild::{
    attach_simplicity, attach_verifier, build_transfer, complete_issuer_op, complete_transfer, covenant_env,
    p2tr_keypath_spk, sig_all_digest, sign_bip340, sign_fee_input, Ctx, IssuerReq, TransferReq,
};
use opendamp::tapscript::cv_spend_info;

// ---------------------------------------------------------------- node driver

struct Node {
    child: Child,
    cli: PathBuf,
    datadir: PathBuf,
    rpcport: u16,
}

impl Node {
    fn locate_binaries() -> Option<(PathBuf, PathBuf)> {
        let candidates: Vec<PathBuf> = match std::env::var("OPENDAMP_NODE_BIN") {
            Ok(p) => vec![PathBuf::from(p)],
            Err(_) => vec![
                PathBuf::from("/home/aejkohl/Sequentia/src/sequentiad"),
                PathBuf::from("/home/aejkohl/Sequentia/src/elementsd"),
            ],
        };
        for daemon in candidates {
            if !daemon.is_file() {
                continue;
            }
            let dir = daemon.parent().unwrap_or(Path::new("."));
            for cli_name in ["sequentia-cli", "elements-cli"] {
                let cli = dir.join(cli_name);
                if cli.is_file() {
                    return Some((daemon, cli));
                }
            }
        }
        None
    }

    fn start() -> Option<Node> {
        let (daemon, cli) = Self::locate_binaries()?;
        let rpcport = 21000 + (std::process::id() % 2000) as u16;
        let p2pport = rpcport + 2000;
        let datadir = std::env::temp_dir().join(format!("opendamp-regtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).expect("datadir");

        let child = Command::new(&daemon)
            .args([
                "-chain=elementsregtest",
                &format!("-datadir={}", datadir.display()),
                "-server=1",
                "-listen=0",
                "-rpcuser=od",
                "-rpcpassword=od",
                &format!("-rpcport={rpcport}"),
                &format!("-port={p2pport}"),
                "-evbparams=simplicity:-1:::",
                "-anyonecanspendaremine=1",
                "-initialfreecoins=2100000000000000",
                "-validatepegin=0",
                "-con_default_blinded_addresses=0",
                "-txindex=1",
                "-fallbackfee=0.0001",
                "-debug=0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        let node = Node {
            child,
            cli,
            datadir,
            rpcport,
        };
        // Wait for RPC.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if node.try_cli(&["getblockchaininfo"]).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                panic!("node RPC did not come up");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Some(node)
    }

    fn try_cli(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.cli)
            .args([
                "-chain=elementsregtest".to_string(),
                format!("-datadir={}", self.datadir.display()),
                "-rpcuser=od".to_string(),
                "-rpcpassword=od".to_string(),
                format!("-rpcport={}", self.rpcport),
            ])
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn cli(&self, args: &[&str]) -> String {
        self.try_cli(args)
            .unwrap_or_else(|e| panic!("cli {args:?} failed: {e}"))
    }

    fn cli_json(&self, args: &[&str]) -> serde_json::Value {
        let s = self.cli(args);
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("cli {args:?} bad json: {e}: {s}"))
    }

    fn generate(&self, n: u32, addr: &str) {
        self.cli(&["generatetoaddress", &n.to_string(), addr]);
    }

    /// Locate the output paying `spk` in `txid`; returns (outpoint, atoms).
    fn find_vout(&self, txid: &str, spk: &Script) -> (OutPoint, u64) {
        let tx = self.cli_json(&["getrawtransaction", txid, "1"]);
        let spk_hex = hex(spk.as_bytes());
        for v in tx["vout"].as_array().expect("vout") {
            if v["scriptPubKey"]["hex"].as_str() == Some(spk_hex.as_str()) {
                let n = v["n"].as_u64().unwrap() as u32;
                let value = v["value"].as_f64().expect("explicit value");
                let atoms = (value * 1e8).round() as u64;
                return (
                    OutPoint::new(Txid::from_str(txid).unwrap(), n),
                    atoms,
                );
            }
        }
        panic!("no output paying {spk_hex} in {txid}");
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.try_cli(&["stop"]);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                _ if Instant::now() > deadline => {
                    let _ = self.child.kill();
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

// ---------------------------------------------------------------- key helpers

fn key(byte: u8) -> ([u8; 32], XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let sk_bytes = [byte; 32];
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    (sk_bytes, kp.x_only_public_key().0)
}

fn asset_from_display(s: &str) -> AssetId {
    AssetId::from_str(s).expect("asset id")
}

fn tx_hex(tx: &opendamp::elements::Transaction) -> String {
    hex(&tx.serialize())
}

fn clone_req(r: &TransferReq) -> TransferReq {
    TransferReq {
        sender: r.sender,
        sender_utxos: r.sender_utxos.clone(),
        recipient: r.recipient,
        amount: r.amount,
        verifier_outpoint: r.verifier_outpoint,
        fee_utxo: r.fee_utxo.clone(),
        fee_key: r.fee_key,
        fee_amount: r.fee_amount,
        fee_change_spk: r.fee_change_spk.clone(),
        recipient_spk_override: r.recipient_spk_override.clone(),
    }
}

fn reject_reason(node: &Node, tx: &opendamp::elements::Transaction) -> String {
    let accept = node.cli_json(&["testmempoolaccept", &format!("[\"{}\"]", tx_hex(tx))]);
    assert_eq!(
        accept[0]["allowed"].as_bool(),
        Some(false),
        "node unexpectedly accepted an invalid transaction: {accept}"
    );
    accept[0]["reject-reason"].as_str().unwrap_or("").to_string()
}

/// Build `bad`, sign its user inputs honestly (U passes: it enforces custody,
/// not policy), and splice in a FAIL-free pruned P(pi) taken from a spend of
/// `good` - the same transaction shape that the covenant does accept. P(pi)'s
/// witness carries no signature and nothing else tx-dependent, so what
/// consensus then runs is a well-formed verifier program against `bad`.
#[allow(clippy::too_many_arguments)]
fn splice_verifier(
    _node: &Node,
    net: &Net,
    ctx: &Ctx,
    good: &TransferReq,
    good_sender_sk: &[u8; 32],
    bad: &TransferReq,
    sender_sk: &[u8; 32],
    fee_sk: &[u8; 32],
) -> opendamp::elements::Transaction {
    let (good_tx, _) = complete_transfer(ctx, good, good_sender_sk, fee_sk, true)
        .expect("the good-shape transfer must validate");

    let built = build_transfer(ctx, bad).expect("bad skeleton builds");
    let mut tx = built.tx.clone();
    let (_, u_cb) = opendamp::tapscript::cu_spend_info(ctx.u_cmr(), &bad.sender);
    for idx in &built.user_inputs {
        let env = covenant_env(net, &built.tx, &built.prevouts, *idx, ctx.u_cmr(), u_cb.clone());
        let digest = sig_all_digest(&env);
        let (sig, _) = sign_bip340(sender_sk, &digest).unwrap();
        let w = programs::user_witness(&bad.sender, &sig).unwrap();
        attach_simplicity(&mut tx, *idx, &ctx.user, w, Some(&env), &u_cb)
            .expect("U is satisfied by the bad transaction too");
    }
    tx.input[0].witness = good_tx.input[0].witness.clone();
    sign_fee_input(net, &mut tx, &built.prevouts, built.fee_input, fee_sk).unwrap();
    tx
}

/// Attach a verifier witness that the covenant does NOT accept, without
/// pruning.
///
/// This is the whole remaining option open to a spender whose policy proof is
/// bad, and the reason it is worth testing: `satisfy_with_env(.., Some(env))`
/// prunes, pruning replays the program, and a failing check makes pruning
/// itself fail (asserted in `bad_witness_cannot_be_pruned`). So a bad proof
/// cannot be turned into a pruned program at all, and the only submittable form
/// still carries its FAIL nodes - which consensus refuses outright. Both doors
/// are therefore shut, and this exercises the second one against the node.
fn attach_unpruned_verifier(
    net: &Net,
    ctx: &Ctx,
    req: &TransferReq,
    slots: &opendamp::txbuild::VerifierSlots,
    sender_sk: &[u8; 32],
    fee_sk: &[u8; 32],
) -> opendamp::elements::Transaction {
    let built = build_transfer(ctx, req).expect("skeleton builds");
    let mut tx = built.tx.clone();
    let (_, u_cb) = opendamp::tapscript::cu_spend_info(ctx.u_cmr(), &req.sender);
    for idx in &built.user_inputs {
        let env = covenant_env(net, &built.tx, &built.prevouts, *idx, ctx.u_cmr(), u_cb.clone());
        let digest = sig_all_digest(&env);
        let (sig, _) = sign_bip340(sender_sk, &digest).unwrap();
        let w = programs::user_witness(&req.sender, &sig).unwrap();
        // U enforces custody, not policy, so the owner's own input still passes.
        attach_simplicity(&mut tx, *idx, &ctx.user, w, Some(&env), &u_cb)
            .expect("U is satisfied regardless of policy");
    }
    let (_, p_cb, _) = cv_spend_info(ctx.p_cmr(), ctx.g_cmr());
    attach_verifier(&mut tx, &ctx.verifier, slots, None, &p_cb)
        .expect("assembles unpruned");
    sign_fee_input(net, &mut tx, &built.prevouts, built.fee_input, fee_sk).unwrap();
    tx
}

/// Slots carrying a STALE membership proof: the realistic attempt by a holder
/// who was removed from the whitelist and still has the proof that worked under
/// the previous policy version.
fn stale_slots(
    frozen_ctx: &Ctx,
    stale_ctx: &Ctx,
    built: &opendamp::txbuild::BuiltTransfer,
) -> opendamp::txbuild::VerifierSlots {
    let mut slots = opendamp::txbuild::VerifierSlots::default();
    for (out_idx, owner) in &built.a_outputs {
        let proof = stale_ctx
            .wl_tree
            .prove(&owner.serialize())
            .or_else(|| frozen_ctx.wl_tree.prove(&owner.serialize()))
            .expect("recipient is provable under one of the two policies");
        slots.outputs[*out_idx - 1] = Some((*owner, proof));
    }
    for (in_idx, owner, outpoint) in &built.a_inputs {
        let proof = stale_ctx
            .wl_tree
            .prove(&owner.serialize())
            .expect("the stale policy did include this owner");
        let k = opendamp::txbuild::outpoint_policy_key(outpoint);
        let interval = stale_ctx
            .bl_tree
            .prove_absent(&k)
            .or_else(|| frozen_ctx.bl_tree.prove_absent(&k))
            .expect("some policy version leaves this outpoint unlisted");
        slots.inputs[*in_idx - 1] = Some((*owner, proof, interval));
    }
    slots
}

// -------------------------------------------------------------------- the test

/// Chain state that every step advances: the live verifier output, each holder's
/// regulated UTXO, and the fee stash.
struct Utxo {
    outpoint: OutPoint,
    value: u64,
}

#[test]
#[ignore = "spawns a Sequentia node; run with --ignored"]
fn regtest_end_to_end() {
    let Some(node) = Node::start() else {
        panic!(
            "no node binary found; set OPENDAMP_NODE_BIN or build \
             /home/aejkohl/Sequentia/src/sequentiad"
        );
    };

    // --- chain and wallet setup
    node.cli(&["createwallet", "w"]);
    let mine_addr = node.cli(&["getnewaddress"]);
    node.generate(101, &mine_addr);
    node.cli(&["rescanblockchain"]);

    // An unenforced 0xbe leaf is anyone-can-spend, so this is checked BEFORE a
    // single covenant output is funded, not merely somewhere in the test.
    let dep = node.cli_json(&["getdeploymentinfo"]);
    assert_eq!(
        dep["deployments"]["simplicity"]["active"].as_bool(),
        Some(true),
        "simplicity must be active before funding any covenant address"
    );

    let genesis = node.cli(&["getblockhash", "0"]);
    let net = Net::regtest(BlockHash::from_str(&genesis).unwrap());

    // Open fee market: every wallet call must name its fee asset explicitly.
    let labels = node.cli_json(&["dumpassetlabels"]);
    let policy_hex = labels["bitcoin"].as_str().expect("policy asset").to_string();
    let policy_asset = asset_from_display(&policy_hex);
    let fee_arg = format!("fee_asset={policy_hex}");
    let fee_label_arg = format!("fee_asset_label={policy_hex}");

    // --- 1. issue A and V
    let issue_a = node.cli_json(&[
        "-named", "issueasset", "assetamount=1000", "tokenamount=0", "blind=false", &fee_arg,
    ]);
    let asset_a = asset_from_display(issue_a["asset"].as_str().unwrap());
    let q: u64 = 100_000;
    let issue_v = node.cli_json(&[
        "-named", "issueasset", "assetamount=0.00100000", "tokenamount=0", "blind=false", &fee_arg,
    ]);
    let asset_v = asset_from_display(issue_v["asset"].as_str().unwrap());
    node.generate(1, &mine_addr);
    println!("asset A {asset_a}");
    println!("asset V {asset_v}");

    let (alice_sk, alice) = key(1);
    let (bob_sk, bob) = key(2);
    let (_carol_sk, carol) = key(4);
    let (issuer_sk, issuer) = key(9);
    let (fee_sk, fee_key) = key(3);

    let params = AssetParams { asset_a, asset_v, q };
    let ctx = |wl: &[XOnlyPublicKey], bl: &[[u8; 32]]| {
        Ctx::new(net, params, issuer, wl, bl).expect("policy compiles")
    };

    // pi0: whitelist {alice, bob}, empty blacklist.
    let ctx0 = ctx(&[alice, bob], &[]);
    let cu_alice = ctx0.cu_info(&alice);
    let cu_bob = ctx0.cu_info(&bob);
    let cu_carol = ctx0.cu_info(&carol);
    let cv0 = ctx0.cv_info();
    let fee_spk = p2tr_keypath_spk(&fee_key);
    let fee_addr = opendamp::elements::Address::from_script(&fee_spk, None, net.address_params)
        .unwrap()
        .to_string();
    println!("U CMR {}", ctx0.u_cmr());
    println!("P CMR (pi0) {}", ctx0.p_cmr());
    println!("G CMR {}", ctx0.g_cmr());
    println!("C_U(alice) {}", cu_alice.address(net.address_params));
    println!("C_V(pi0)   {}", cv0.address(net.address_params));

    // --- fund
    let a_hex = issue_a["asset"].as_str().unwrap();
    let v_hex = issue_v["asset"].as_str().unwrap();
    let cu_alice_addr = cu_alice.address(net.address_params).to_string();
    let cv0_addr = cv0.address(net.address_params).to_string();
    let fund_a = node.cli(&[
        "-named", "sendtoaddress", &format!("address={cu_alice_addr}"), "amount=5.0",
        &format!("assetlabel={a_hex}"), &fee_label_arg,
    ]);
    let fund_v = node.cli(&[
        "-named", "sendtoaddress", &format!("address={cv0_addr}"), "amount=0.00100000",
        &format!("assetlabel={v_hex}"), &fee_label_arg,
    ]);
    let fund_fee = node.cli(&[
        "-named", "sendtoaddress", &format!("address={fee_addr}"), "amount=1.0", &fee_label_arg,
    ]);
    node.generate(1, &mine_addr);
    println!("PROOF 1: funded A->C_U(alice) {fund_a}, V->C_V(pi0) {fund_v}, fee {fund_fee}");

    let (op, atoms) = node.find_vout(&fund_a, &cu_alice.script_pubkey);
    let mut alice_a = Utxo { outpoint: op, value: atoms };
    let (op, v_atoms) = node.find_vout(&fund_v, &cv0.script_pubkey);
    assert_eq!(v_atoms, q, "verifier funding must be exactly q");
    let mut verifier_op = op;
    let (op, atoms) = node.find_vout(&fund_fee, &fee_spk);
    let mut fee = Utxo { outpoint: op, value: atoms };
    let fee_amount: u64 = 50_000;

    // A transfer request against the current chain state.
    let make_req = |sender: XOnlyPublicKey,
                    utxo: &Utxo,
                    recipient: XOnlyPublicKey,
                    amount: u64,
                    verifier_op: OutPoint,
                    fee: &Utxo| TransferReq {
        sender,
        sender_utxos: vec![(utxo.outpoint, utxo.value)],
        recipient,
        amount,
        verifier_outpoint: verifier_op,
        fee_utxo: (fee.outpoint, policy_asset, fee.value),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
        recipient_spk_override: None,
    };

    // --- 2. alice -> bob, no third party signature
    let req = make_req(alice, &alice_a, bob, 200_000_000, verifier_op, &fee);
    let (tx, report) = complete_transfer(&ctx0, &req, &alice_sk, &fee_sk, true)
        .expect("transfer satisfies U and P");
    println!(
        "BUDGET: verifier witness {} B ({} B pad), cost {} milli-WU = {} WU, \
         budget {} WU, headroom {} WU ({}%); user witnesses {:?} B; tx {} B",
        report.verifier_witness, report.verifier_pad, report.verifier_cost,
        report.verifier_weight(), report.verifier_budget(),
        report.verifier_budget() as i64 - report.verifier_weight() as i64,
        (report.verifier_budget() - report.verifier_weight()) * 100 / report.verifier_budget(),
        report.user_witnesses, tx_hex(&tx).len() / 2,
    );
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    assert!(
        node.cli_json(&["getrawtransaction", &txid, "1"])["blockhash"].as_str().is_some(),
        "transfer must confirm"
    );
    println!("PROOF 2: alice->bob transfer, no third party: {txid}");

    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &cu_alice.script_pubkey);
    alice_a = Utxo { outpoint: o, value: v };
    let (o, v) = node.find_vout(&txid, &cu_bob.script_pubkey);
    let bob_a = Utxo { outpoint: o, value: v };
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    // --- 3. confinement: A to a plain address
    let good = make_req(alice, &alice_a, bob, 100_000_000, verifier_op, &fee);
    let bad = TransferReq {
        recipient_spk_override: Some(p2tr_keypath_spk(&bob)),
        ..clone_req(&good)
    };
    let local = complete_transfer(&ctx0, &bad, &alice_sk, &fee_sk, true);
    println!(
        "PROOF 3a: builder/BitMachine refuses an unconfined A output: {}",
        local.err().map(|e| e.to_string()).unwrap_or_default()
    );
    let bad_tx = splice_verifier(&node, &net, &ctx0, &good, &alice_sk, &bad, &alice_sk, &fee_sk);
    let reason = reject_reason(&node, &bad_tx);
    println!("PROOF 3b: node rejects the unconfined A output: {reason}");
    assert!(reason.contains("Assertion failed"), "must fail the confinement assertion: {reason}");

    // --- 4. RECIPIENT whitelist
    let to_carol = TransferReq { recipient: carol, ..clone_req(&good) };
    let err = complete_transfer(&ctx0, &to_carol, &alice_sk, &fee_sk, true)
        .err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("not in the whitelist"), "builder must refuse carol: {err}");
    println!("PROOF 4a: builder refuses carol as recipient (no proof exists under pi0): {err}");

    let bad_tx = splice_verifier(&node, &net, &ctx0, &good, &alice_sk, &to_carol, &alice_sk, &fee_sk);
    let reason = reject_reason(&node, &bad_tx);
    println!("PROOF 4b: node rejects bob's proof reused to pay carol: {reason}");
    assert!(reason.contains("Assertion failed"), "must fail recipient binding: {reason}");

    // --- 5. issuer update pi0 -> pi1 (adds carol), then alice -> carol
    let ctx1 = ctx(&[alice, bob, carol], &[]);
    assert_ne!(ctx0.cv_info().script_pubkey, ctx1.cv_info().script_pubkey);
    let upd = IssuerReq {
        verifier_outpoint: verifier_op,
        halt_spk: None,
        fee_utxo: (fee.outpoint, policy_asset, fee.value),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let tx = complete_issuer_op(&ctx0, Some(&ctx1), &upd, &issuer_sk, &fee_sk).expect("update");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 5a: issuer update pi0->pi1 (adds carol): {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    // 4c. The policy version is bound into the verifier ADDRESS. Take the fully
    // valid pi1 transfer and swap only input 0's Simplicity program (and its
    // CMR) for P(pi0)'s. Nothing else changes - same control block, same
    // signatures - so the sole defect is that the leaf no longer hashes into
    // C_V(pi1)'s output key. The taproot commitment is checked before the
    // program runs, so this is unambiguous.
    assert_ne!(
        ctx0.cv_info().script_pubkey,
        ctx1.cv_info().script_pubkey,
        "a policy update must move the verifier to a new address"
    );
    let probe = make_req(alice, &alice_a, carol, 100_000_000, verifier_op, &fee);
    let (tx, _) = complete_transfer(&ctx1, &probe, &alice_sk, &fee_sk, true)
        .expect("alice->carol under pi1");

    let built = build_transfer(&ctx1, &probe).expect("skeleton");
    let slots = opendamp::txbuild::verifier_slots(&ctx1, &built).expect("all keys in pi1");
    let mut swapped = tx.clone();
    let (_, p1_cb, _) = cv_spend_info(ctx1.p_cmr(), ctx1.g_cmr());
    // P(pi0)'s program under P(pi1)'s control block: unpruned, because P(pi0)
    // cannot be satisfied by a payment to carol at all.
    attach_verifier(&mut swapped, &ctx0.verifier, &slots, None, &p1_cb)
        .expect("assembles");
    let reason = reject_reason(&node, &swapped);
    println!("PROOF 4c: node rejects P(pi0) spending C_V(pi1): {reason}");
    assert!(
        reason.contains("mismatch"),
        "the policy version must be bound into the verifier address: {reason}"
    );

    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 5b: alice->carol under pi1: {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &cu_alice.script_pubkey);
    alice_a = Utxo { outpoint: o, value: v };
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };
    let _ = node.find_vout(&txid, &cu_carol.script_pubkey);

    // ================= 7. THE FREEZE: remove the SPENDER from the whitelist
    let ctx2 = ctx(&[bob, carol], &[]); // alice removed
    let upd = IssuerReq {
        verifier_outpoint: verifier_op,
        halt_spk: None,
        fee_utxo: (fee.outpoint, policy_asset, fee.value),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let tx = complete_issuer_op(&ctx1, Some(&ctx2), &upd, &issuer_sk, &fee_sk).expect("freeze");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 7a: issuer update pi1->pi2 REMOVING alice (the freeze): {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    // Alice tries to spend her own coins. She is the owner, she signs correctly,
    // and the recipient is whitelisted - only she is not.
    let frozen = make_req(alice, &alice_a, carol, alice_a.value, verifier_op, &fee);
    let err = complete_transfer(&ctx2, &frozen, &alice_sk, &fee_sk, true)
        .err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        err.contains("frozen") || err.contains("not in the whitelist"),
        "the builder must refuse a frozen owner: {err}"
    );
    println!("PROOF 7b: alice cannot spend - no owner proof exists under pi2: {err}");

    // Her stale proof from pi1 is the realistic attempt. It cannot be pruned...
    let built = build_transfer(&ctx2, &frozen).expect("skeleton");
    let stale = stale_slots(&ctx2, &ctx1, &built);
    let (_, p_cb, _) = cv_spend_info(ctx2.p_cmr(), ctx2.g_cmr());
    let p_env = covenant_env(&net, &built.tx, &built.prevouts, 0, ctx2.p_cmr(), p_cb.clone());
    let mut probe_tx = built.tx.clone();
    let pruned = attach_verifier(&mut probe_tx, &ctx2.verifier, &stale, Some(&p_env), &p_cb);
    assert!(pruned.is_err(), "a stale proof must not satisfy the new whitelist root");
    println!(
        "PROOF 7c: alice's stale pi1 proof fails the pi2 whitelist fold: {}",
        pruned.err().unwrap()
    );

    // ...so the only submittable form keeps its FAIL nodes, and the node
    // refuses that outright. Both doors shut.
    let unpruned = attach_unpruned_verifier(&net, &ctx2, &frozen, &stale, &alice_sk, &fee_sk);
    let reason = reject_reason(&node, &unpruned);
    println!("PROOF 7d: node rejects the only submittable form of it: {reason}");
    assert!(reason.contains("FAIL node"), "expected a FAIL-node refusal: {reason}");

    // And claiming to be a whitelisted owner does not work either: the owner key
    // is bound to the input's script. Bob's spend of his own coin is valid under
    // pi2 and has the identical shape, so its verifier witness splices cleanly.
    let bobs_good = make_req(bob, &bob_a, carol, bob_a.value, verifier_op, &fee);
    let alices_bad = make_req(alice, &alice_a, carol, alice_a.value, verifier_op, &fee);
    let bad_tx = splice_verifier(&node, &net, &ctx2, &bobs_good, &bob_sk, &alices_bad, &alice_sk, &fee_sk);
    let reason = reject_reason(&node, &bad_tx);
    println!("PROOF 7e: node rejects bob's whitelisted identity used for alice's input: {reason}");
    assert!(reason.contains("Assertion failed"), "must fail the owner binding: {reason}");

    // Bob, who is still whitelisted, is unaffected by alice's freeze.
    let (tx, _) = complete_transfer(&ctx2, &bobs_good, &bob_sk, &fee_sk, true)
        .expect("bob is not frozen");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 7f: bob still spends under pi2 - the freeze is per holder: {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    // Lift the freeze.
    let ctx3 = ctx(&[alice, bob, carol], &[]);
    let upd = IssuerReq {
        verifier_outpoint: verifier_op,
        halt_spk: None,
        fee_utxo: (fee.outpoint, policy_asset, fee.value),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let tx = complete_issuer_op(&ctx2, Some(&ctx3), &upd, &issuer_sk, &fee_sk).expect("unfreeze");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 7g: issuer update pi2->pi3 restoring alice: {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    let thawed = make_req(alice, &alice_a, carol, 50_000_000, verifier_op, &fee);
    let (tx, _) = complete_transfer(&ctx3, &thawed, &alice_sk, &fee_sk, true)
        .expect("alice spends again once re-whitelisted");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 7h: alice spends again under pi3 - the freeze is reversible: {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &cu_alice.script_pubkey);
    alice_a = Utxo { outpoint: o, value: v };
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    // ================= 8. BLACKLIST BY OUTPOINT: freeze one UTXO, not a holder
    let frozen_key = opendamp::txbuild::outpoint_policy_key(&alice_a.outpoint);
    let ctx4 = ctx(&[alice, bob, carol], &[frozen_key]);
    println!(
        "blacklisting outpoint {} (policy key {})",
        alice_a.outpoint,
        hex(&frozen_key)
    );
    let upd = IssuerReq {
        verifier_outpoint: verifier_op,
        halt_spk: None,
        fee_utxo: (fee.outpoint, policy_asset, fee.value),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let tx = complete_issuer_op(&ctx3, Some(&ctx4), &upd, &issuer_sk, &fee_sk).expect("blacklist");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 8a: issuer update pi3->pi4 blacklisting alice's outpoint: {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    let listed = make_req(alice, &alice_a, carol, 10_000_000, verifier_op, &fee);
    let err = complete_transfer(&ctx4, &listed, &alice_sk, &fee_sk, true)
        .err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        err.contains("blacklisted"),
        "the builder must refuse a listed outpoint: {err}"
    );
    println!("PROOF 8b: alice cannot spend the listed outpoint - no interval covers it: {err}");

    // The pre-blacklist interval proof is stale in exactly the same way.
    let built = build_transfer(&ctx4, &listed).expect("skeleton");
    let stale = stale_slots(&ctx4, &ctx3, &built);
    let (_, p_cb, _) = cv_spend_info(ctx4.p_cmr(), ctx4.g_cmr());
    let p_env = covenant_env(&net, &built.tx, &built.prevouts, 0, ctx4.p_cmr(), p_cb.clone());
    let mut probe_tx = built.tx.clone();
    let pruned = attach_verifier(&mut probe_tx, &ctx4.verifier, &stale, Some(&p_env), &p_cb);
    assert!(pruned.is_err(), "a stale interval proof must not satisfy the new blacklist root");
    println!(
        "PROOF 8c: the pre-freeze interval proof fails the pi4 blacklist root: {}",
        pruned.err().unwrap()
    );
    let unpruned = attach_unpruned_verifier(&net, &ctx4, &listed, &stale, &alice_sk, &fee_sk);
    let reason = reject_reason(&node, &unpruned);
    println!("PROOF 8d: node rejects the only submittable form of it: {reason}");
    assert!(reason.contains("FAIL node"), "expected a FAIL-node refusal: {reason}");

    // Lift the outpoint freeze; the very same UTXO moves again.
    let ctx5 = ctx(&[alice, bob, carol], &[]);
    let upd = IssuerReq {
        verifier_outpoint: verifier_op,
        halt_spk: None,
        fee_utxo: (fee.outpoint, policy_asset, fee.value),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let tx = complete_issuer_op(&ctx4, Some(&ctx5), &upd, &issuer_sk, &fee_sk).expect("unlist");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 8e: issuer update pi4->pi5 lifting the outpoint freeze: {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    let unlisted = make_req(alice, &alice_a, carol, 10_000_000, verifier_op, &fee);
    let (tx, _) = complete_transfer(&ctx5, &unlisted, &alice_sk, &fee_sk, true)
        .expect("the unlisted outpoint spends");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 8f: the same outpoint spends once unlisted: {txid}");
    verifier_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &cu_alice.script_pubkey);
    alice_a = Utxo { outpoint: o, value: v };
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    // ================= 6. HALT (last: it ends all transfers)
    let halt = IssuerReq {
        verifier_outpoint: verifier_op,
        halt_spk: Some(p2tr_keypath_spk(&bob)),
        fee_utxo: (fee.outpoint, policy_asset, fee.value),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let tx = complete_issuer_op(&ctx5, None, &halt, &issuer_sk, &fee_sk).expect("halt");
    let txid = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 6a: halt - V leaves the covenant: {txid}");
    let halted_op = OutPoint::new(Txid::from_str(&txid).unwrap(), 0);
    let (o, v) = node.find_vout(&txid, &fee_spk);
    fee = Utxo { outpoint: o, value: v };

    let post = make_req(alice, &alice_a, carol, 10_000_000, halted_op, &fee);
    let (tx, _) = complete_transfer(&ctx5, &post, &alice_sk, &fee_sk, false)
        .expect("assembles unvalidated");
    let reason = reject_reason(&node, &tx);
    println!("PROOF 6b: node rejects any transfer after the halt: {reason}");

    println!("ALL REGTEST PROOFS COMPLETE");
    let _ = (alice_a.value, bob_a.value, cu_carol.script_pubkey);
}

/// Pruning replays the program, so a witness the covenant rejects cannot be
/// pruned at all. That is what closes the second door in proofs 7 and 8: with no
/// pruned form available, the only submittable program still carries its FAIL
/// nodes, which consensus refuses. Asserted here so the argument is tested and
/// not merely asserted in prose.
#[test]
fn bad_witness_cannot_be_pruned() {
    let (_, alice) = key(1);
    let (_, bob) = key(2);
    let (_, issuer) = key(9);
    let (_, fee_key) = key(3);
    let net = Net::regtest(BlockHash::from_str(&format!("{:064x}", 7u8)).unwrap());
    let params = AssetParams {
        asset_a: AssetId::from_slice(&[0xaa; 32]).unwrap(),
        asset_v: AssetId::from_slice(&[0xbb; 32]).unwrap(),
        q: 1000,
    };
    let ctx = Ctx::new(net, params, issuer, &[alice, bob], &[]).unwrap();
    let outpoint = |b: u8, v: u32| {
        OutPoint::new(Txid::from_str(&format!("{:064x}", b as u128)).unwrap(), v)
    };
    let req = TransferReq {
        sender: alice,
        sender_utxos: vec![(outpoint(0x11, 1), 50_000)],
        recipient: bob,
        amount: 20_000,
        verifier_outpoint: outpoint(0x22, 0),
        fee_utxo: (outpoint(0x33, 0), AssetId::from_slice(&[0xcc; 32]).unwrap(), 10_000),
        fee_key,
        fee_amount: 400,
        fee_change_spk: Script::from(vec![0x51]),
        recipient_spk_override: None,
    };
    let built = build_transfer(&ctx, &req).unwrap();
    let mut slots = opendamp::txbuild::verifier_slots(&ctx, &built).unwrap();
    // Alice's key with BOB's membership proof: the script check still passes, so
    // only the whitelist fold can reject it.
    let bobs_proof = ctx.wl_tree.prove(&bob.serialize()).unwrap();
    if let Some((k, _, iv)) = slots.inputs[0].clone() {
        slots.inputs[0] = Some((k, bobs_proof, iv));
    }
    let (_, p_cb, _) = cv_spend_info(ctx.p_cmr(), ctx.g_cmr());
    let env = covenant_env(&net, &built.tx, &built.prevouts, 0, ctx.p_cmr(), p_cb.clone());
    let mut tx = built.tx.clone();
    let pruned = attach_verifier(&mut tx, &ctx.verifier, &slots, Some(&env), &p_cb);
    assert!(
        pruned.is_err(),
        "a witness with a mismatched membership proof must not prune"
    );
}
