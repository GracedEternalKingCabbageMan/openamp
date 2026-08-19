//! Builder-side refusals: the two places the transfer builder used to wave
//! through a transaction the covenant would then reject for reasons its error
//! message never mentioned.

use std::str::FromStr;

use opendamp::elements::secp256k1_zkp::{Keypair, Secp256k1, XOnlyPublicKey};
use opendamp::elements::{confidential, AssetId, BlockHash, OutPoint, Script, Txid};
use opendamp::net::Net;
use opendamp::programs::{AssetParams, Shape, CANONICAL};
use opendamp::txbuild::{build_transfer, payments_to_others, Ctx, TransferReq};

fn key(byte: u8) -> ([u8; 32], XOnlyPublicKey) {
    let mut sk = [byte; 32];
    sk[31] = byte.wrapping_add(1);
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, &sk).expect("valid key");
    (sk, kp.x_only_public_key().0)
}

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).unwrap()
}

fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint::new(
        Txid::from_str(&format!("{:064x}", byte as u128)).unwrap(),
        vout,
    )
}

fn test_ctx(wl: &[XOnlyPublicKey]) -> Ctx {
    let (_, issuer) = key(9);
    let params = AssetParams {
        asset_a: asset(0xaa),
        asset_v: asset(0xbb),
        q: 1000,
    };
    let net = Net::regtest(BlockHash::from_str(&format!("{:064x}", 7u8)).unwrap());
    Ctx::new(net, params, issuer, wl, &[]).expect("programs compile")
}

fn transfer_req(sender: XOnlyPublicKey, recipient: XOnlyPublicKey) -> TransferReq {
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

/// The builder must refuse a transaction wider than every leaf in the menu,
/// naming the reason.
///
/// It used to define `N_MAX_INPUTS` and never check it, unlike `N_MAX_OUTPUTS`
/// which was checked. The result was that a transfer spending too many
/// regulated inputs built cleanly, passed slot assembly, and then died in the
/// BitMachine with `covenant execution failed` -- a message that says nothing
/// about the bound it broke.
#[test]
fn build_refuses_a_transaction_no_leaf_can_spend() {
    let (_, alice) = key(1);
    let (_, bob) = key(2);
    let ctx = test_ctx(&[alice, bob]);
    let mut req = transfer_req(alice, bob);

    // The widest leaf takes five inputs: the verifier, three regulated and a
    // fee. Four regulated inputs is one too many.
    req.sender_utxos = (1..=4).map(|i| (outpoint(0x11, i), 50_000)).collect();
    req.amount = 10_000;
    let err = build_transfer(&ctx, &req)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        err.contains("exceeds every verifier shape"),
        "the builder must name the bound rather than failing in the BitMachine: {err}"
    );

    // Three regulated inputs still fits, on the widest leaf.
    req.sender_utxos = (1..=3).map(|i| (outpoint(0x11, i), 50_000)).collect();
    let built = build_transfer(&ctx, &req).expect("three regulated inputs fit");
    assert_eq!(built.shape, Shape::new(4, 6));

    // And one fits on the canonical leaf, which is the point of the menu.
    req.sender_utxos = vec![(outpoint(0x11, 1), 50_000)];
    let built = build_transfer(&ctx, &req).expect("the ordinary case");
    assert_eq!(built.shape, CANONICAL);
}

/// A payment to another owner with a blinded value must be refused by name.
///
/// `payments_to_others` used to read it as `.explicit().unwrap_or(0)`, so a
/// blinded payment scored zero: the limit preflight passed a transfer the
/// covenant refuses outright, and reported an under-limit total for a
/// transaction whose real total it could not see.
#[test]
fn a_blinded_payment_is_refused_rather_than_counted_as_zero() {
    let (_, alice) = key(1);
    let (_, bob) = key(2);
    let ctx = test_ctx(&[alice, bob]);
    let req = transfer_req(alice, bob);
    let mut built = build_transfer(&ctx, &req).expect("builds");

    // A real Pedersen commitment, so the test exercises the same shape a blinded
    // transaction actually carries rather than an arbitrary 33 bytes.
    let commitment = |v: u64, tag: u8| {
        let secp = Secp256k1::new();
        confidential::Value::new_confidential_from_assetid(
            &secp,
            v,
            asset(0xaa),
            opendamp::elements::confidential::ValueBlindingFactor::from_slice(&[tag; 32]).unwrap(),
            opendamp::elements::confidential::AssetBlindingFactor::from_slice(&[tag ^ 0xff; 32])
                .unwrap(),
        )
    };

    // Blind the payment's value, leaving its asset id explicit.
    let paid_idx = built
        .a_outputs
        .iter()
        .find(|(_, owner)| *owner == bob)
        .map(|(i, _)| *i)
        .expect("the payment output");
    built.tx.output[paid_idx].value = commitment(20_000, 0x11);

    let err = payments_to_others(alice, &built).err().unwrap_or_default();
    assert!(
        err.contains("blinded value"),
        "a blinded payment must be named, not scored as zero: {err}"
    );

    // Change, by contrast, may stay blinded: it is not a payment to anyone else
    // and the covenant never reads its value.
    let change_idx = built
        .a_outputs
        .iter()
        .find(|(_, owner)| *owner == alice)
        .map(|(i, _)| *i)
        .expect("the change output");
    built.tx.output[paid_idx].value = confidential::Value::Explicit(20_000);
    built.tx.output[change_idx].value = commitment(30_000, 0x22);
    assert_eq!(
        payments_to_others(alice, &built).unwrap(),
        20_000,
        "blinded change must be permitted and must not count"
    );
}

/// A halt that parks the verifier asset at a spendable address is the one way
/// to break the invariant confinement rests on, so the request type names it.
#[test]
fn a_halt_that_parks_the_verifier_asset_is_flagged() {
    use opendamp::txbuild::{burn_spk, IssuerReq};
    let (_, fee_key) = key(3);
    let burn = IssuerReq::halt_to_burn(
        outpoint(0x22, 0),
        (outpoint(0x33, 0), asset(0xcc), 10_000),
        fee_key,
        400,
        Script::from(vec![0x51]),
    );
    assert!(!burn.halt_leaves_live_verifier_asset());
    assert_eq!(burn.halt_spk.as_ref().unwrap(), &burn_spk());

    let parked = IssuerReq {
        halt_spk: Some(Script::from(vec![0x51, 0x20].into_iter().chain([0u8; 32]).collect::<Vec<u8>>())),
        ..burn
    };
    assert!(
        parked.halt_leaves_live_verifier_asset(),
        "parking q of V at a spendable address leaves a standing bypass of the \
         whole policy, and the caller has to be able to see that"
    );

    // A policy update is not a halt and leaves the verifier where it belongs.
    let update = IssuerReq {
        halt_spk: None,
        ..parked
    };
    assert!(!update.halt_leaves_live_verifier_asset());
}
