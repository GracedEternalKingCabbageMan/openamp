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
//! Proves, in order, printing every txid:
//!   1. issue A and V, fund C_U(alice) and C_V(pi0 = whitelist {alice,bob})
//!   2. alice -> bob transfer with no third party: builds, broadcasts, confirms
//!   3. confinement refusal: A to a plain address is rejected by the node
//!   4. whitelist refusal: carol fails locally; a forged proof is rejected by the node
//!   5. issuer update to pi1 (adds carol), then alice -> carol succeeds
//!   6. halt: V to a plain address; afterwards no transfer can satisfy input 0

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use opendamp::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use opendamp::elements::pset::serialize::Serialize;
use opendamp::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
use opendamp::hexutil::hex;
use opendamp::net::Net;
use opendamp::programs::{self, AssetParams, SlotWitness};
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
    bad: &TransferReq,
    sender_sk: &[u8; 32],
    fee_sk: &[u8; 32],
) -> opendamp::elements::Transaction {
    let (good_tx, _) = complete_transfer(ctx, good, sender_sk, fee_sk, true)
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

// -------------------------------------------------------------------- the test

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
    // Pick up the genesis initialfreecoins (the wallet was created after the
    // genesis block was connected, and block subsidy may be zero).
    node.cli(&["rescanblockchain"]);
    let bal = node.cli(&["getbalance"]);
    println!("wallet balance after rescan: {bal}");

    let dep = node.cli_json(&["getdeploymentinfo"]);
    assert_eq!(
        dep["deployments"]["simplicity"]["active"].as_bool(),
        Some(true),
        "simplicity must be active on this chain"
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
        "-named",
        "issueasset",
        "assetamount=1000",
        "tokenamount=0",
        "blind=false",
        &fee_arg,
    ]);
    let asset_a = asset_from_display(issue_a["asset"].as_str().unwrap());
    // q = 100,000 atoms of V; the whole V issuance is exactly q.
    let q: u64 = 100_000;
    let issue_v = node.cli_json(&[
        "-named",
        "issueasset",
        "assetamount=0.00100000",
        "tokenamount=0",
        "blind=false",
        &fee_arg,
    ]);
    let asset_v = asset_from_display(issue_v["asset"].as_str().unwrap());
    node.generate(1, &mine_addr);
    println!("asset A {asset_a}");
    println!("asset V {asset_v}");

    // --- keys and policy pi0 = whitelist {alice, bob}
    let (alice_sk, alice) = key(1);
    let (_bob_sk, bob) = key(2);
    let (_carol_sk, carol) = key(4);
    let (issuer_sk, issuer) = key(9);
    let (fee_sk, fee_key) = key(3);

    let params = AssetParams {
        asset_a,
        asset_v,
        q,
    };
    let ctx0 = Ctx::new(net, params, issuer, &[alice, bob]).expect("ctx0");

    let cu_alice = ctx0.cu_info(&alice);
    let cv0 = ctx0.cv_info();
    let cu_alice_addr = cu_alice.address(net.address_params).to_string();
    let cv0_addr = cv0.address(net.address_params).to_string();
    let fee_spk = p2tr_keypath_spk(&fee_key);
    let fee_addr = opendamp::elements::Address::from_script(&fee_spk, None, net.address_params)
        .unwrap()
        .to_string();
    println!("C_U(alice) {cu_alice_addr}");
    println!("C_V(pi0)   {cv0_addr}");

    // --- fund C_U(alice), C_V(pi0), and the fee stash
    let a_hex = issue_a["asset"].as_str().unwrap();
    let v_hex = issue_v["asset"].as_str().unwrap();
    let fund_a = node.cli(&[
        "-named",
        "sendtoaddress",
        &format!("address={cu_alice_addr}"),
        "amount=5.0",
        &format!("assetlabel={a_hex}"),
        &fee_label_arg,
    ]);
    let fund_v = node.cli(&[
        "-named",
        "sendtoaddress",
        &format!("address={cv0_addr}"),
        "amount=0.00100000",
        &format!("assetlabel={v_hex}"),
        &fee_label_arg,
    ]);
    let fund_fee = node.cli(&[
        "-named",
        "sendtoaddress",
        &format!("address={fee_addr}"),
        "amount=1.0",
        &fee_label_arg,
    ]);
    node.generate(1, &mine_addr);
    println!("funded: A->C_U(alice) {fund_a}");
    println!("        V->C_V(pi0)   {fund_v}");
    println!("        fee stash     {fund_fee}");

    let (alice_op, alice_atoms) = node.find_vout(&fund_a, &cu_alice.script_pubkey);
    let (verifier_op, v_atoms) = node.find_vout(&fund_v, &cv0.script_pubkey);
    assert_eq!(v_atoms, q, "verifier funding must be exactly q");
    let (fee_op, fee_atoms) = node.find_vout(&fund_fee, &fee_spk);

    let fee_amount: u64 = 50_000;

    // --- 2. transfer alice -> bob, no third party
    let req = TransferReq {
        sender: alice,
        sender_utxos: vec![(alice_op, alice_atoms)],
        recipient: bob,
        amount: 200_000_000, // 2.0 of A
        verifier_outpoint: verifier_op,
        fee_utxo: (fee_op, policy_asset, fee_atoms),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
        recipient_spk_override: None,
    };
    let (tx, report) = complete_transfer(&ctx0, &req, &alice_sk, &fee_sk, true)
        .expect("transfer builds and satisfies covenants locally");
    println!(
        "transfer budget: verifier witness {} B ({} B pad), cost {} milli-WU = {} WU, \
         budget {} WU, headroom {} WU; user witnesses {:?} B",
        report.verifier_witness,
        report.verifier_pad,
        report.verifier_cost,
        report.verifier_weight(),
        report.verifier_budget(),
        report.verifier_budget() as i64 - report.verifier_weight() as i64,
        report.user_witnesses,
    );
    let txid2 = node.cli(&["sendrawtransaction", &tx_hex(&tx)]);
    node.generate(1, &mine_addr);
    let conf = node.cli_json(&["getrawtransaction", &txid2, "1"]);
    assert!(conf["blockhash"].as_str().is_some(), "transfer confirmed");
    println!("PROOF 2: alice->bob transfer confirmed: {txid2}");

    // Chain state moved: new verifier outpoint and alice's change.
    let verifier_op2 = OutPoint::new(Txid::from_str(&txid2).unwrap(), 0);
    let (alice_change_op, alice_change_atoms) = node.find_vout(&txid2, &cu_alice.script_pubkey);
    let (fee_op2, fee_atoms2) = node.find_vout(&txid2, &fee_spk);

    // --- 3. confinement refusal: A to a plain address
    //
    // A transaction the covenant rejects cannot be pruned (pruning needs a
    // successful run) and an UNpruned Simplicity program is refused for
    // containing FAIL nodes, which would prove nothing about the rule. So the
    // verifier's witness is taken from a well-formed spend of the same shape
    // and spliced in: P(pi) has no signature and no tx-dependent witness data,
    // so a spliced witness is exactly "a valid, FAIL-free P(pi) run against
    // this transaction". The user input is signed for the bad transaction and
    // passes on its own (U checks custody, not confinement), so the only check
    // that can fail is the verifier's output scan.
    let plain_spk = p2tr_keypath_spk(&bob);
    let ctx1 = Ctx::new(net, params, issuer, &[alice, bob, carol]).expect("ctx1");
    let good_shape = TransferReq {
        sender: alice,
        sender_utxos: vec![(alice_change_op, alice_change_atoms)],
        recipient: bob,
        amount: 100_000_000,
        verifier_outpoint: verifier_op2,
        fee_utxo: (fee_op2, policy_asset, fee_atoms2),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
        recipient_spk_override: None,
    };
    let bad = TransferReq {
        recipient_spk_override: Some(plain_spk.clone()),
        ..clone_req(&good_shape)
    };
    // Locally the verifier refuses outright.
    let local = complete_transfer(&ctx0, &bad, &alice_sk, &fee_sk, true);
    assert!(local.is_err(), "confinement violation must fail locally");
    println!(
        "PROOF 3a: builder/BitMachine refuses an unconfined A output: {}",
        local.err().map(|e| e.to_string()).unwrap_or_default()
    );

    let bad_tx = splice_verifier(&node, &net, &ctx0, &good_shape, &bad, &alice_sk, &fee_sk);
    let reason = reject_reason(&node, &bad_tx);
    println!("PROOF 3b: node rejects the unconfined A output: {reason}");
    assert!(
        reason.contains("Assertion failed") || reason.contains("Jet failed"),
        "the node must fail the confinement assertion, not something incidental: {reason}"
    );

    // --- 4. whitelist refusal for carol
    let to_carol = TransferReq {
        recipient: carol,
        ..clone_req(&good_shape)
    };
    let local = complete_transfer(&ctx0, &to_carol, &alice_sk, &fee_sk, true);
    let local_err = local.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        local_err.contains("not in the whitelist"),
        "builder must refuse carol: {local_err}"
    );
    println!("PROOF 4a: builder refuses carol (no proof exists under pi0): {local_err}");

    // 4b. The attack that matters: reuse bob's genuine membership proof to pay
    // carol. The proof is bound to the output script (the covenant recomputes
    // C_U(Y) from the SAME witness key it proves membership for), so this is a
    // consensus failure, not a builder policy.
    let bad_tx = splice_verifier(&node, &net, &ctx0, &good_shape, &to_carol, &alice_sk, &fee_sk);
    let reason = reject_reason(&node, &bad_tx);
    println!("PROOF 4b: node rejects bob's proof reused to pay carol: {reason}");
    assert!(
        reason.contains("Assertion failed") || reason.contains("Jet failed"),
        "must fail the recipient/proof binding: {reason}"
    );

    // 4c. And the policy version is bound into the address: P(pi1) cannot spend
    // C_V(pi0), because pi1's whitelist root changes P's CMR and therefore the
    // taproot output key.
    assert_ne!(
        ctx0.cv_info().script_pubkey,
        ctx1.cv_info().script_pubkey,
        "a policy update must move the verifier to a new address"
    );
    let built = build_transfer(&ctx0, &to_carol).expect("skeleton builds");
    let mut wrong_policy = built.tx.clone();
    let (_, u_cb) = opendamp::tapscript::cu_spend_info(ctx0.u_cmr(), &alice);
    for idx in &built.user_inputs {
        let env = covenant_env(&net, &built.tx, &built.prevouts, *idx, ctx0.u_cmr(), u_cb.clone());
        let digest = sig_all_digest(&env);
        let (sig, _) = sign_bip340(&alice_sk, &digest).unwrap();
        let w = programs::user_witness(&alice, &sig).unwrap();
        attach_simplicity(&mut wrong_policy, *idx, &ctx0.user, w, Some(&env), &u_cb).unwrap();
    }
    // Carol IS a member of pi1's tree, so P(pi1) runs successfully...
    let mut slots: [SlotWitness; 7] = Default::default();
    for (out_idx, owner) in &built.a_outputs {
        let proof = ctx1.wl_tree.prove(&owner.serialize()).expect("member of pi1");
        slots[*out_idx - 1] = Some((*owner, proof));
    }
    let (_, p1_cb, _) = cv_spend_info(ctx1.p_cmr(), ctx1.g_cmr());
    let p1_env = covenant_env(&net, &built.tx, &built.prevouts, 0, ctx1.p_cmr(), p1_cb.clone());
    attach_verifier(&mut wrong_policy, &ctx1.verifier, &slots, Some(&p1_env), &p1_cb)
        .expect("P(pi1) is satisfied by a carol payment");
    sign_fee_input(&net, &mut wrong_policy, &built.prevouts, built.fee_input, &fee_sk).unwrap();
    // ...but the output it is spending commits to pi0.
    let reason = reject_reason(&node, &wrong_policy);
    println!("PROOF 4c: node rejects P(pi1) spending C_V(pi0): {reason}");
    assert!(
        reason.contains("Witness program hash mismatch"),
        "the policy version must be bound into the verifier address: {reason}"
    );

    // --- 5. issuer update to pi1 (whitelists carol), then alice -> carol
    let upd = IssuerReq {
        verifier_outpoint: verifier_op2,
        halt_spk: None,
        fee_utxo: (fee_op2, policy_asset, fee_atoms2),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let upd_tx =
        complete_issuer_op(&ctx0, Some(&ctx1), &upd, &issuer_sk, &fee_sk).expect("issuer update");
    let txid5 = node.cli(&["sendrawtransaction", &tx_hex(&upd_tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 5a: issuer policy update pi0->pi1 confirmed: {txid5}");

    let verifier_op3 = OutPoint::new(Txid::from_str(&txid5).unwrap(), 0);
    let (fee_op3, fee_atoms3) = node.find_vout(&txid5, &fee_spk);
    let to_carol_now = TransferReq {
        sender: alice,
        sender_utxos: vec![(alice_change_op, alice_change_atoms)],
        recipient: carol,
        amount: 100_000_000,
        verifier_outpoint: verifier_op3,
        fee_utxo: (fee_op3, policy_asset, fee_atoms3),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
        recipient_spk_override: None,
    };
    let (tx5, _) = complete_transfer(&ctx1, &to_carol_now, &alice_sk, &fee_sk, true)
        .expect("alice->carol under pi1");
    let txid5b = node.cli(&["sendrawtransaction", &tx_hex(&tx5)]);
    node.generate(1, &mine_addr);
    println!("PROOF 5b: alice->carol transfer under pi1 confirmed: {txid5b}");

    let verifier_op4 = OutPoint::new(Txid::from_str(&txid5b).unwrap(), 0);
    let (fee_op4, fee_atoms4) = node.find_vout(&txid5b, &fee_spk);
    let (alice_change_op2, alice_change_atoms2) = node.find_vout(&txid5b, &cu_alice.script_pubkey);

    // --- 6. halt: V leaves the covenant; transfers stop
    let halt = IssuerReq {
        verifier_outpoint: verifier_op4,
        halt_spk: Some(plain_spk.clone()),
        fee_utxo: (fee_op4, policy_asset, fee_atoms4),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
    };
    let halt_tx = complete_issuer_op(&ctx1, None, &halt, &issuer_sk, &fee_sk).expect("halt");
    let txid6 = node.cli(&["sendrawtransaction", &tx_hex(&halt_tx)]);
    node.generate(1, &mine_addr);
    println!("PROOF 6a: halt confirmed (V now at a plain address): {txid6}");

    // A transfer pointing at the halted outpoint cannot satisfy input 0: the
    // UTXO is no longer C_V, so the Simplicity witness fails outright.
    let halted_op = OutPoint::new(Txid::from_str(&txid6).unwrap(), 0);
    let (fee_op5, fee_atoms5) = node.find_vout(&txid6, &fee_spk);
    let post_halt = TransferReq {
        sender: alice,
        sender_utxos: vec![(alice_change_op2, alice_change_atoms2)],
        recipient: bob,
        amount: 50_000_000,
        verifier_outpoint: halted_op,
        fee_utxo: (fee_op5, policy_asset, fee_atoms5),
        fee_key,
        fee_amount,
        fee_change_spk: fee_spk.clone(),
        recipient_spk_override: None,
    };
    let (tx6, _) = complete_transfer(&ctx1, &post_halt, &alice_sk, &fee_sk, false)
        .expect("assembles unvalidated");
    let accept = node.cli_json(&[
        "testmempoolaccept",
        &format!("[\"{}\"]", tx_hex(&tx6)),
    ]);
    assert_eq!(accept[0]["allowed"].as_bool(), Some(false));
    let reason = accept[0]["reject-reason"].as_str().unwrap_or("").to_string();
    println!("PROOF 6b: post-halt transfer rejected by node: {reason}");

    println!("ALL REGTEST PROOFS COMPLETE");
}
