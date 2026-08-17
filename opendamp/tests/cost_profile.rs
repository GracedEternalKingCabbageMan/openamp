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
             "WL_ROOT":{{"value":"0x{r}","type":"u256"}},
             "BL_ROOT":{{"value":"0x{b}","type":"u256"}}}}"#,
        a = "aa".repeat(32), v = "bb".repeat(32),
        c = opendamp::hexutil::hex(&cmr), r = "11".repeat(32), b = "22".repeat(32)
    )).unwrap();
    let prog = CompiledProgram::new(src, args, false).unwrap();
    let mut w = serde_json::Map::new();
    for i in 1..=opendamp::programs::N_OUT_SLOTS {
        w.insert(format!("W{i}"), serde_json::json!({
            "value": "None", "type": "Option<(Pubkey, [(u256, bool); 16])>"}));
    }
    for i in 1..=opendamp::programs::N_IN_SLOTS {
        w.insert(format!("I{i}"), serde_json::json!({
            "value": "None",
            "type": "Option<(Pubkey, [(u256, bool); 16], u256, u256, [(u256, bool); 16])>"}));
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

    let slots = (opendamp::programs::N_OUT_SLOTS + opendamp::programs::N_IN_SLOTS) as u64;
    let no_wl = full.replace(
        "    let root: u256 = array_fold::<wl_step, 16>(proof, wl_leaf(key));\n    assert!(jet::eq_256(root, param::WL_ROOT));",
        "");
    let a = cost_of(&no_wl);
    eprintln!("whitelist folds, all {slots} slots: {} milli-WU ({} per slot = {} WU)",
        base - a, (base - a) / slots, (base - a) / (slots * 1000));

    let mut one_less_out = full.clone();
    one_less_out = one_less_out.replace("    check_output(5, witness::W5);\n", "");
    let c = cost_of(&one_less_out);
    eprintln!("one whole OUTPUT slot (asset+spk+whitelist): {} milli-WU = {} WU",
        base - c, (base - c) / 1000);

    let mut one_less_in = full.clone();
    one_less_in = one_less_in.replace(
        "    bool_or(check_input(2, witness::I2),\n                             check_input(3, witness::I3)));",
        "            check_input(2, witness::I2));");
    let d = cost_of(&one_less_in);
    eprintln!("one whole INPUT slot (asset+spk+whitelist+blacklist): {} milli-WU = {} WU",
        base - d, (base - d) / 1000);

    let no_bl = full.replace(
        "                    require_bl_nonmember(i, bl_lo, bl_hi, bl_proof);\n", "");
    let e = cost_of(&no_bl);
    let in_slots = opendamp::programs::N_IN_SLOTS as u64;
    eprintln!("blacklist non-membership, all {in_slots} input slots: {} milli-WU ({} per slot = {} WU)",
        base - e, (base - e) / in_slots, (base - e) / (in_slots * 1000));

    let no_lt = full.replace("    assert!(lt_256(lo, k));\n    assert!(lt_256(k, hi));\n", "");
    let f = cost_of(&no_lt);
    eprintln!("  of which the two 256-bit comparisons: {} milli-WU ({} per slot = {} WU)",
        base - f, (base - f) / in_slots, (base - f) / (in_slots * 1000));
    eprintln!("  a used input slot's witness is 33 + 16*33 + 64 + 16*33 = 1153 B, buying 1153 WU");

    // The whitelist fold dominates, and one output slot costs about 1,000 WU
    // against the 561 WU its own proof bytes buy back.
    let per_slot_wl = (base - a) / slots;
    let per_slot_total = base - c;
    assert!(
        (600_000..1_000_000).contains(&per_slot_wl),
        "whitelist fold is {per_slot_wl} milli-WU per slot; STATUS.md says ~772k"
    );
    let per_input_slot = base - d;
    assert!(
        (1_500_000..2_500_000).contains(&per_input_slot),
        "an input slot is {per_input_slot} milli-WU; STATUS.md quotes ~1.96M"
    );
    let per_bl_slot = (base - e) / in_slots;
    assert!(
        (600_000..1_400_000).contains(&per_bl_slot),
        "blacklist non-membership is {per_bl_slot} milli-WU per slot; STATUS.md quotes ~947k"
    );
    assert!(
        (800_000..1_400_000).contains(&per_slot_total),
        "an output slot is {per_slot_total} milli-WU; STATUS.md says ~1.01M"
    );
    assert!(base < 4_000_050_000, "cost must stay under the consensus cap");
}
