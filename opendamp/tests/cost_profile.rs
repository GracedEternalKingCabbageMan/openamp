//! Static-cost profile of the verifier leaf menu: what each shape costs, what
//! its own witness buys, and where the money goes inside one.
//!
//! This used to be an argument about padding. It is now an argument about
//! headroom: there is no pad, so every shape has to pay for itself out of the
//! proofs it genuinely carries, and the margin is what stands between the menu
//! and an unspendable covenant. The assertions are bands, not equalities, so a
//! change that moves a cost by an order of magnitude fails here rather than at
//! a node.

use opendamp::dmt;
use opendamp::elements::AssetId;
use opendamp::programs::{
    self, compile_user, render_verifier, AssetParams, Shape, CANONICAL, DEPTH, SHAPES,
};
use opendamp::simplicityhl::{Arguments, CompiledProgram, WitnessValues};

fn params() -> AssetParams {
    AssetParams {
        asset_a: AssetId::from_slice(&[0xaa; 32]).unwrap(),
        asset_v: AssetId::from_slice(&[0xbb; 32]).unwrap(),
        q: 1000,
    }
}

fn issuer_key() -> opendamp::elements::secp256k1_zkp::XOnlyPublicKey {
    opendamp::net::nums_key()
}

fn args_for() -> Arguments {
    let u_cmr = compile_user(&params()).unwrap().commit().cmr();
    let mut cmr = [0u8; 32];
    cmr.copy_from_slice(u_cmr.as_ref());
    serde_json::from_str(&format!(
        r#"{{"ASSET_A":{{"value":"0x{a}","type":"u256"}},
             "ASSET_V":{{"value":"0x{v}","type":"u256"}},
             "AMOUNT_Q":{{"value":"1000","type":"u64"}},
             "U_CMR":{{"value":"0x{c}","type":"u256"}},
             "WL_ROOT":{{"value":"0x{r}","type":"u256"}},
             "BL_ROOT":{{"value":"0x{b}","type":"u256"}},
             "LIMIT":{{"value":"18446744073709551615","type":"u64"}},
             "PI":{{"value":"0x{p}","type":"u256"}}}}"#,
        a = "aa".repeat(32),
        v = "bb".repeat(32),
        c = opendamp::hexutil::hex(&cmr),
        r = "11".repeat(32),
        b = "22".repeat(32),
        p = "33".repeat(32),
    ))
    .unwrap()
}

/// Static cost of `src`, in milli-weight-units, with every slot empty.
fn cost_of(src: &str, shape: Shape) -> u64 {
    measure(src, shape, 0, 0).0
}

/// Cost (milli-WU) and the full witness STACK size in bytes -- witness blob,
/// program, CMR and control block, which is what the node measures the budget
/// against -- with `n_in_filled` input slots and `n_out_filled` output slots
/// carrying real proofs.
///
/// Measured unpruned, which is the conservative direction for cost: a real
/// spend prunes its untaken branches away and costs slightly less.
fn measure(src: &str, shape: Shape, n_in_filled: usize, n_out_filled: usize) -> (u64, usize) {
    let prog = CompiledProgram::new(src, args_for(), false).expect("template compiles");
    let out_ty = format!("Option<(Pubkey, u32, u32, [(u256, bool); {DEPTH}])>");
    let in_ty = format!("Option<(u256, u256, [(u256, bool); {DEPTH}])>");
    let sender_ty = format!("(Pubkey, u32, u32, [(u256, bool); {DEPTH}])");
    let path: Vec<String> = (0..DEPTH)
        .map(|_| format!("(0x{}, false)", "00".repeat(32)))
        .collect();
    let sender = format!("(0x{}, 0, 0, [{}])", "cc".repeat(32), path.join(", "));
    let mut w = serde_json::Map::new();
    w.insert(
        "SENDER".into(),
        serde_json::json!({"value": sender, "type": sender_ty}),
    );
    let filled_out = format!("Some((0x{}, 0, 0, [{}]))", "dd".repeat(32), path.join(", "));
    let filled_in = format!(
        "Some((0x{}, 0x{}, [{}]))",
        "00".repeat(32),
        "ff".repeat(32),
        path.join(", ")
    );
    for i in 1..=shape.n_out {
        let v = if i <= n_out_filled { filled_out.clone() } else { "None".into() };
        w.insert(format!("W{i}"), serde_json::json!({"value": v, "type": out_ty}));
    }
    for i in 1..=shape.n_in {
        let v = if i <= n_in_filled { filled_in.clone() } else { "None".into() };
        w.insert(format!("I{i}"), serde_json::json!({"value": v, "type": in_ty}));
    }
    let wv: WitnessValues =
        serde_json::from_str(&serde_json::to_string(&serde_json::Value::Object(w)).unwrap())
            .unwrap();
    let sat = prog.satisfy(wv).unwrap();
    let node = sat.redeem();
    let c = format!("{:?}", node.bounds().cost);
    let cost: u64 = c
        .trim_start_matches("Cost(")
        .trim_end_matches(')')
        .parse()
        .unwrap();
    let (program_bytes, witness_bytes) = node.to_vec_with_witness();
    // + 32 for the CMR element, + 65 for a depth-1 control block (the canonical
    // leaf's; deeper leaves carry more, and buy more budget with it).
    (cost, witness_bytes.len() + program_bytes.len() + 32 + 65)
}

/// Budget, in milli-WU, that a witness stack of `bytes` buys on this chain.
fn budget(bytes: usize) -> u64 {
    (bytes as u64 * opendamp::txbuild::BUDGET_PER_WITNESS_BYTE + 50).min(4_000_050) * 1000
}

#[test]
fn every_shape_pays_for_itself_without_padding() {
    // The smallest witness a legitimate spend can present: the sender proof
    // (always), one filled input slot (a regulated input must exist) and one
    // filled output slot (its A has to go somewhere). Anything richer carries
    // more proof bytes and therefore buys MORE budget against an unchanged
    // static cost, so this is the worst case for every shape.
    eprintln!("\nshape   cost(mWU)  min stack  budget(mWU)   margin");
    for shape in SHAPES {
        let (cost, stack) = measure(&render_verifier(shape), shape, 1, 1);
        let b = budget(stack);
        eprintln!(
            "{:>5}  {cost:>10}  {stack:>9}  {b:>11}  {:>7.2}x",
            shape.name(),
            b as f64 / cost as f64
        );
        assert!(
            cost < b,
            "{shape} costs {cost} milli-WU but its minimum legitimate witness \
             stack ({stack} B) buys only {b}. Without a pad, that makes the leaf \
             unspendable: narrow the shape, or the chain is not granting four \
             weight units per witness byte."
        );
        assert!(
            cost < 4_000_050_000,
            "{shape} exceeds the interpreter's absolute budget cap"
        );
    }
}

#[test]
fn the_canonical_leaf_is_the_cheapest_useful_one() {
    let canonical = cost_of(&render_verifier(CANONICAL), CANONICAL);
    for shape in SHAPES {
        if shape == CANONICAL {
            continue;
        }
        let c = cost_of(&render_verifier(shape), shape);
        if shape.n_in + shape.n_out > CANONICAL.n_in + CANONICAL.n_out {
            assert!(
                c > canonical,
                "{shape} has more slots than the canonical leaf but costs less"
            );
        }
    }
    // And the whole point of the menu: the widest leaf costs substantially more
    // than the one an ordinary transfer takes, which is exactly what a single
    // program would have charged everybody.
    let widest = SHAPES
        .iter()
        .copied()
        .max_by_key(|s| s.n_in + s.n_out)
        .unwrap();
    let w = cost_of(&render_verifier(widest), widest);
    eprintln!(
        "canonical {} costs {canonical} mWU; widest {} costs {w} mWU ({:.2}x)",
        CANONICAL.name(),
        widest.name(),
        w as f64 / canonical as f64
    );
    assert!(w > canonical);
}

#[test]
fn where_the_cost_goes() {
    let src = render_verifier(CANONICAL);
    let base = cost_of(&src, CANONICAL);

    // Hoisting the sender out of the input loop is why an input slot is cheap
    // now: it carries a blacklist proof and a script comparison, not a second
    // membership fold and a taproot reconstruction.
    let no_wl = src.replace(
        &format!(
            "    let root: u256 = array_fold::<wl_step, {DEPTH}>(proof, wl_leaf(key, send_after, recv_after));\n    assert!(jet::eq_256(root, param::WL_ROOT));"
        ),
        "",
    );
    let a = cost_of(&no_wl, CANONICAL);
    eprintln!("whitelist folds, whole program: {} mWU", base - a);

    let no_bl = src.replace(
        "                    require_bl_nonmember(i, bl_lo, bl_hi, bl_proof);\n",
        "",
    );
    let e = cost_of(&no_bl, CANONICAL);
    eprintln!(
        "blacklist non-membership, all {} input slots: {} mWU",
        CANONICAL.n_in,
        base - e
    );

    // pi is committed, not computed: it must be nearly free, or committing it
    // would have been the wrong way to bind a policy version.
    let no_pi = src.replace(
        "    assert!(jet::eq_256(param::PI, param::PI));\n",
        "",
    );
    let pi_cost = base - cost_of(&no_pi, CANONICAL);
    eprintln!("committing pi: {pi_cost} mWU");
    assert!(
        pi_cost < 50_000,
        "committing pi costs {pi_cost} milli-WU, which is too much for an inert \
         commitment; it should be a single comparison"
    );
    // ...and it must actually be committed. If the compiler folded it away the
    // CMR would not move, and C_V would stop distinguishing policy versions.
    assert!(pi_cost > 0, "pi is not reaching the program DAG at all");
}

#[test]
fn pi_changes_the_address() {
    // The claim the design document makes -- that C_V(pi) commits to one policy
    // VERSION -- is only true if pi reaches the CMR. Two contexts with identical
    // rules and different sequence numbers must be different addresses.
    let p = params();
    let (_, alice) = {
        let sk = [7u8; 32];
        let secp = opendamp::elements::secp256k1_zkp::Secp256k1::new();
        let kp = opendamp::elements::secp256k1_zkp::Keypair::from_seckey_slice(&secp, &sk).unwrap();
        (sk, kp.x_only_public_key().0)
    };
    let entries = vec![dmt::Entry::unrestricted(alice.serialize())];
    let net = opendamp::net::Net::testnet();
    let mk = |seq: u64| {
        opendamp::txbuild::Ctx::with_policy(
            net,
            p,
            issuer_key(),
            entries.clone(),
            &[],
            programs::NO_LIMIT,
            seq,
        )
        .unwrap()
    };
    let a = mk(0);
    let b = mk(1);
    assert_ne!(a.pi, b.pi, "pi must depend on the sequence number");
    assert_ne!(
        a.cv_info().script_pubkey,
        b.cv_info().script_pubkey,
        "two policy versions with identical rules must be different addresses"
    );
    // The rules really are identical, so it is pi alone doing the work.
    assert_eq!(a.wl_tree.root(), b.wl_tree.root());
    assert_eq!(a.bl_tree.root(), b.bl_tree.root());
}
