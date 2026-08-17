//! Static-cost profile of P(pi): how much each check actually costs, so
//! STATUS.md's "what remains" numbers are measured rather than guessed.
use opendamp::elements::AssetId;
use opendamp::programs::{compile_user, AssetParams, BUDGET_PAD_WORDS, VERIFIER_SOURCE};
use opendamp::simplicityhl::{Arguments, CompiledProgram, WitnessValues};

fn cost_of(src: &str) -> u64 {
    let p = AssetParams {
        asset_a: AssetId::from_slice(&[0xaa; 32]).unwrap(),
        asset_v: AssetId::from_slice(&[0xbb; 32]).unwrap(),
        q: 1000,
    };
    let u_cmr = compile_user(&p).unwrap().commit().cmr();
    let mut cmr = [0u8; 32];
    cmr.copy_from_slice(u_cmr.as_ref());
    let args: Arguments = serde_json::from_str(&format!(
        r#"{{"ASSET_A":{{"value":"0x{a}","type":"u256"}},
             "ASSET_V":{{"value":"0x{v}","type":"u256"}},
             "AMOUNT_Q":{{"value":"1000","type":"u64"}},
             "U_CMR":{{"value":"0x{c}","type":"u256"}},
             "WL_ROOT":{{"value":"0x{r}","type":"u256"}}}}"#,
        a = "aa".repeat(32), v = "bb".repeat(32),
        c = opendamp::hexutil::hex(&cmr), r = "11".repeat(32)
    )).unwrap();
    let prog = CompiledProgram::new(src, args, false).unwrap();
    let mut w = serde_json::Map::new();
    for i in 1..=7 {
        w.insert(format!("W{i}"), serde_json::json!({
            "value": "None", "type": "Option<(Pubkey, [(u256, bool); 16])>"}));
    }
    let zero = format!("0x{}", "00".repeat(32));
    w.insert("BUDGET_PAD".to_string(), serde_json::json!({
        "value": format!("[{}]", vec![zero; BUDGET_PAD_WORDS].join(", ")),
        "type": format!("[u256; {BUDGET_PAD_WORDS}]")}));
    let wv: WitnessValues =
        serde_json::from_str(&serde_json::to_string(&serde_json::Value::Object(w)).unwrap()).unwrap();
    let sat = prog.satisfy(wv).unwrap();
    let c = format!("{:?}", sat.redeem().bounds().cost);
    c.trim_start_matches("Cost(").trim_end_matches(')').parse().unwrap()
}

/// These numbers are quoted in STATUS.md section 3 and section 6. The
/// assertions are loose bands, not exact equalities: they exist so that a
/// change which moves a cost by an order of magnitude fails here instead of
/// silently invalidating the documented budget arithmetic.
#[test]
fn profile() {
    let full = VERIFIER_SOURCE.to_string();
    let base = cost_of(&full);
    eprintln!("full P (unpruned static cost): {base} milli-WU");

    let no_wl = full.replace(
        "    let root: u256 = array_fold::<wl_step, 16>(proof, wl_leaf(key));\n    assert!(jet::eq_256(root, param::WL_ROOT));",
        "");
    let a = cost_of(&no_wl);
    eprintln!("whitelist folds, all 7 slots: {} milli-WU ({} per slot = {} WU)",
        base - a, (base - a) / 7, (base - a) / 7000);

    let no_spk = full.replace(
        "                    assert!(jet::eq_256(cu_spk_hash(y), unwrap(jet::output_script_hash(i))));\n",
        "");
    let b = cost_of(&no_spk);
    eprintln!("C_U(Y) recomputation, all 7 slots: {} milli-WU ({} per slot = {} WU)",
        base - b, (base - b) / 7, (base - b) / 7000);

    let mut six = full.clone();
    six = six.replace("    check_output(7, witness::W7);\n", "");
    let c = cost_of(&six);
    eprintln!("one whole output slot (scan+spk+whitelist): {} milli-WU = {} WU",
        base - c, (base - c) / 1000);
    eprintln!("  a slot's witness proof is 16*33+33 = 561 B, which BUYS 561 WU");

    // The whitelist fold dominates, and one output slot costs about 1,000 WU
    // against the 561 WU its own proof bytes buy back.
    let per_slot_wl = (base - a) / 7;
    let per_slot_total = base - c;
    assert!(
        (600_000..1_000_000).contains(&per_slot_wl),
        "whitelist fold is {per_slot_wl} milli-WU per slot; STATUS.md says ~772k"
    );
    assert!(
        (800_000..1_400_000).contains(&per_slot_total),
        "an output slot is {per_slot_total} milli-WU; STATUS.md says ~1.01M"
    );
    assert!(base < 4_000_050_000, "cost must stay under the consensus cap");
}
