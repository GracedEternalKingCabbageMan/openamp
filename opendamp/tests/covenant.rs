//! Offline proof of the covenant logic: compile U, P(pi), G, build a full
//! transfer transaction, and execute every covenant on the BitMachine against
//! the exact environment consensus would use. No node required.

use std::str::FromStr;

use opendamp::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use opendamp::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
use opendamp::net::Net;
use opendamp::programs::AssetParams;
use opendamp::txbuild::{
    build_transfer, complete_issuer_op, complete_transfer, Ctx, IssuerReq, TransferReq,
};

fn key(byte: u8) -> ([u8; 32], XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let sk_bytes = [byte; 32];
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    (sk_bytes, kp.x_only_public_key().0)
}

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).unwrap()
}

fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_str(&format!("{:064x}", byte as u128)).unwrap(), vout)
}

fn net() -> Net {
    // Synthetic chain: the genesis only has to be consistent between signing
    // and execution, which it is because both use this Net.
    Net::regtest(BlockHash::from_str(&format!("{:064x}", 7u8)).unwrap())
}

fn test_ctx(wl: &[XOnlyPublicKey]) -> Ctx {
    let (_, issuer) = key(9);
    let params = AssetParams {
        asset_a: asset(0xaa),
        asset_v: asset(0xbb),
        q: 1000,
    };
    Ctx::new(net(), params, issuer, wl, &[]).expect("programs compile")
}

fn transfer_req(_ctx: &Ctx, sender: XOnlyPublicKey, recipient: XOnlyPublicKey) -> TransferReq {
    let (_, fee_key) = key(3);
    TransferReq {
        sender,
        sender_utxos: vec![(outpoint(0x11, 1), 50_000)],
        recipient,
        amount: 20_000,
        verifier_outpoint: outpoint(0x22, 0),
        fee_utxo: (outpoint(0x33, 0), asset(0xcc), 10_000),
        fee_key,
        fee_amount: 400,
        fee_change_spk: Script::from(vec![0x51]),
        locktime: 0,
        recipient_spk_override: None,
    }
}

#[test]
fn programs_compile_and_have_stable_shape() {
    let (_, alice) = key(1);
    let (_, bob) = key(2);
    let ctx = test_ctx(&[alice, bob]);
    // CMRs derive; addresses derive on both networks.
    let cu = ctx.cu_info(&alice);
    let cv = ctx.cv_info();
    assert_eq!(cu.script_pubkey.len(), 34);
    assert_eq!(cv.script_pubkey.len(), 34);
    println!("U   CMR {}", ctx.u_cmr());
    println!("G   CMR {}", ctx.g_cmr());
    // Every shape is a distinct program with a distinct CMR, and none of them
    // collides with U or G. They all live in the one C_V address.
    let mut cmrs = vec![ctx.u_cmr(), ctx.g_cmr()];
    for shape in opendamp::programs::SHAPES {
        let cmr = ctx.p_cmr(shape).expect("shape is in the menu");
        println!("P   CMR {:>5} {}", shape.name(), cmr);
        assert!(!cmrs.contains(&cmr), "{shape} duplicates another program's CMR");
        cmrs.push(cmr);
        // ...and each has its own control block against the same output key.
        let cb = ctx.verifier_spend().control_for(shape).expect("control block");
        assert!(cb.verify_taproot_commitment(
            &opendamp::elements::secp256k1_zkp::Secp256k1::verification_only(),
            &opendamp::elements::schnorr::TweakedPublicKey::new(cv.output_key),
            &opendamp::elements::Script::from(cmr.as_ref().to_vec()),
        ), "{shape}'s control block must open against C_V");
    }
}

#[test]
fn transfer_satisfies_all_covenants_on_the_bitmachine() {
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let (fee_sk, _) = key(3);
    let ctx = test_ctx(&[alice, bob]);
    let req = transfer_req(&ctx, alice, bob);
    let (tx, report) = complete_transfer(&ctx, &req, &alice_sk, &fee_sk, true)
        .expect("transfer satisfies U and P");
    assert_eq!(tx.input.len(), 3);
    println!(
        "verifier input: leaf {}, witness {} B, cost {} milli-WU = {} WU, \
         budget {} WU, headroom {} WU",
        report.shape.name(),
        report.verifier_witness,
        report.verifier_cost,
        report.verifier_weight(),
        report.verifier_budget(),
        report.verifier_budget() as i64 - report.verifier_weight() as i64,
    );
    println!("user inputs: witness sizes {:?} B", report.user_witnesses);
    // There is no padding any more: the functional witness alone has to buy the
    // budget, which is only true because a witness byte buys four weight units
    // on this chain. If that stops holding, this is where it shows.
    assert!(report.verifier_budget() <= 4_000_050);
    assert!(
        report.verifier_weight() <= report.verifier_budget(),
        "cost {} WU exceeds the {} WU a {} B witness buys",
        report.verifier_weight(),
        report.verifier_budget(),
        report.verifier_witness,
    );
    // The canonical transfer must take the canonical leaf.
    assert_eq!(report.shape, opendamp::programs::CANONICAL);
    // And the whole thing must be a fraction of what the padded single-shape
    // program cost: that program's witness was 26,830 B.
    assert!(
        report.verifier_witness < 6_000,
        "verifier witness is {} B; the point of dropping the pad was to be far \
         under the 26,830 B the padded program carried",
        report.verifier_witness,
    );
}

#[test]
fn confinement_violation_fails_locally() {
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let (fee_sk, _) = key(3);
    let ctx = test_ctx(&[alice, bob]);
    let mut req = transfer_req(&ctx, alice, bob);
    // Pay bob's A to a plain P2TR instead of C_U(bob).
    req.recipient_spk_override = Some(opendamp::txbuild::p2tr_keypath_spk(&bob));
    let err = complete_transfer(&ctx, &req, &alice_sk, &fee_sk, true)
        .expect_err("verifier must refuse an unconfined A output");
    println!("refusal: {err}");
}

#[test]
fn non_member_recipient_fails_locally() {
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let (_, carol) = key(4);
    let (fee_sk, _) = key(3);
    let ctx = test_ctx(&[alice, bob]);
    let req = transfer_req(&ctx, alice, carol);
    let err = complete_transfer(&ctx, &req, &alice_sk, &fee_sk, true)
        .expect_err("carol is not whitelisted");
    println!("refusal: {err}");
}

#[test]
fn wrong_owner_key_cannot_claim_the_covenant() {
    // Mallory supplies her own key+signature for alice's C_U input: the SPK
    // recomputation must fail before the signature is even relevant.
    let (mallory_sk, _mallory) = key(5);
    let (_, alice) = key(1);
    let (_, bob) = key(2);
    let (fee_sk, _) = key(3);
    let ctx = test_ctx(&[alice, bob]);
    let mut req = transfer_req(&ctx, alice, bob);
    // Claim the sender is mallory: prevouts still commit to C_U(alice) so the
    // state binding must fail... but build_transfer derives prevouts from
    // req.sender. Instead: correct sender, wrong signing key.
    req.sender = alice;
    let err = complete_transfer(&ctx, &req, &mallory_sk, &fee_sk, true)
        .expect_err("wrong key must not satisfy C_U(alice)");
    println!("refusal: {err}");
}

#[test]
fn issuer_update_and_halt_satisfy_g() {
    let (issuer_sk, issuer) = key(9);
    let (_, alice) = key(1);
    let (_, bob) = key(2);
    let (_, carol) = key(4);
    let (fee_sk, fee_key) = key(3);
    let params = AssetParams {
        asset_a: asset(0xaa),
        asset_v: asset(0xbb),
        q: 1000,
    };
    let ctx0 = Ctx::new(net(), params, issuer, &[alice, bob], &[]).unwrap();
    let ctx1 = Ctx::new(net(), params, issuer, &[alice, bob, carol], &[]).unwrap();
    assert_ne!(
        ctx0.cv_info().script_pubkey,
        ctx1.cv_info().script_pubkey,
        "policy update moves the verifier to a new address"
    );

    let req = IssuerReq {
        verifier_outpoint: outpoint(0x22, 0),
        halt_spk: None,
        fee_utxo: (outpoint(0x44, 0), asset(0xcc), 5_000),
        fee_key,
        fee_amount: 300,
        fee_change_spk: Script::from(vec![0x51]),
    };
    let tx = complete_issuer_op(&ctx0, Some(&ctx1), &req, &issuer_sk, &fee_sk)
        .expect("issuer update satisfies G");
    assert_eq!(tx.output[0].script_pubkey, ctx1.cv_info().script_pubkey);

    // Halt: V to a plain script.
    let halt = IssuerReq {
        halt_spk: Some(Script::from(vec![0x51])),
        ..req
    };
    let tx = complete_issuer_op(&ctx0, None, &halt, &issuer_sk, &fee_sk)
        .expect("halt satisfies G");
    assert_eq!(tx.output[0].script_pubkey, Script::from(vec![0x51]));

    // Wrong key refused.
    let (mallory_sk, _) = key(5);
    assert!(complete_issuer_op(&ctx0, Some(&ctx1), &halt, &mallory_sk, &fee_sk).is_err());
}

#[test]
fn build_rejects_fee_in_asset_a() {
    let (_, alice) = key(1);
    let (_, bob) = key(2);
    let ctx = test_ctx(&[alice, bob]);
    let mut req = transfer_req(&ctx, alice, bob);
    req.fee_utxo = (outpoint(0x33, 0), ctx.params.asset_a, 10_000);
    assert!(build_transfer(&ctx, &req).is_err());
}
