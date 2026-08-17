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
             "BL_ROOT":{{"value":"0x{b}","type":"u256"}},
             "LIMIT":{{"value":"18446744073709551615","type":"u64"}}}}"#,
        a = "aa".repeat(32), v = "bb".repeat(32),
        c = opendamp::hexutil::hex(&cmr), r = "11".repeat(32), b = "22".repeat(32)
    )).unwrap();
    let prog = CompiledProgram::new(src, args, false).unwrap();
    let mut w = serde_json::Map::new();
    for i in 1..=opendamp::programs::N_OUT_SLOTS {
        w.insert(format!("W{i}"), serde_json::json!({
            "value": "None", "type": "Option<(Pubkey, u32, u32, [(u256, bool); 16])>"}));
    }
    for i in 1..=opendamp::programs::N_IN_SLOTS {
        w.insert(format!("I{i}"), serde_json::json!({
            "value": "None",
            "type": "Option<(Pubkey, u32, u32, [(u256, bool); 16], u256, u256, [(u256, bool); 16])>"}));
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
        "    let root: u256 = array_fold::<wl_step, 16>(proof, wl_leaf(key, send_after, recv_after));\n    assert!(jet::eq_256(root, param::WL_ROOT));",
        "");
    let a = cost_of(&no_wl);
    eprintln!("whitelist folds, all {slots} slots: {} milli-WU ({} per slot = {} WU)",
        base - a, (base - a) / slots, (base - a) / (slots * 1000));

    let mut one_less_out = full.clone();
    one_less_out = one_less_out.replace(
        "    let paid: u64 = add_payment(paid, check_output(5, sender, witness::W5));\n", "");
    let c = cost_of(&one_less_out);
    eprintln!("one whole OUTPUT slot (asset+spk+whitelist): {} milli-WU = {} WU",
        base - c, (base - c) / 1000);

    let one_less_in = full
        .replace("    let o3: Option<Pubkey> = check_input(3, witness::I3);\n", "")
        .replace("    let o3: Option<Pubkey> = None;\n", "")
        .replace(
            "    let sender: Pubkey = unwrap(first_owner(o1, first_owner(o2, o3)));",
            "    let sender: Pubkey = unwrap(first_owner(o1, o2));",
        )
        .replace("    require_same_owner(o3, sender);\n", "");
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

    // The transfer limit, whole: the single-sender agreement, change detection,
    // the running sum with its overflow check, and the bound itself.
    let no_limit = full
        .replace("    assert!(jet::le_64(paid, param::LIMIT));\n", "")
        .replace(
            "    require_same_owner(o1, sender);\n    require_same_owner(o2, sender);\n    require_same_owner(o3, sender);\n",
            "",
        )
        .replace(
            "                        limited_amount(v, y, sender)\n",
            "                        0\n",
        );
    let g = cost_of(&no_limit);
    eprintln!("transfer limit (single sender + change detection + sum + bound): {} milli-WU = {} WU",
        base - g, (base - g) / 1000);

    // Height windows: the lock jets plus the two extra words in every leaf.
    let no_win = full
        .replace(
            "fn require_height_bound(bound: u32) {\n    jet::check_lock_height(bound);\n}",
            "fn require_height_bound(bound: u32) {\n}",
        )
        .replace(
            "    let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, send_after);\n    let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, recv_after);\n",
            "",
        );
    let h = cost_of(&no_win);
    eprintln!("height windows (lock jets + the two words in each leaf): {} milli-WU = {} WU",
        base - h, (base - h) / 1000);
    eprintln!("  a used input slot's witness is 33+8 + 16*33 + 64 + 16*33 = 1161 B, buying 1161 WU");

    // The whitelist fold dominates, and one output slot costs about 1,000 WU
    // against the 561 WU its own proof bytes buy back.
    let per_slot_wl = (base - a) / slots;
    let per_slot_total = base - c;
    assert!(
        (650_000..1_000_000).contains(&per_slot_wl),
        "whitelist fold is {per_slot_wl} milli-WU per slot; STATUS.md quotes ~796k"
    );
    let per_input_slot = base - d;
    assert!(
        (1_800_000..3_200_000).contains(&per_input_slot),
        "an input slot is {per_input_slot} milli-WU; STATUS.md quotes ~2.4M"
    );
    let per_bl_slot = (base - e) / in_slots;
    assert!(
        (600_000..1_400_000).contains(&per_bl_slot),
        "blacklist non-membership is {per_bl_slot} milli-WU per slot; STATUS.md quotes ~947k"
    );
    assert!(
        (1_100_000..1_900_000).contains(&per_slot_total),
        "an output slot is {per_slot_total} milli-WU; STATUS.md quotes ~1.44M"
    );
    assert!(base < 4_000_050_000, "cost must stay under the consensus cap");
    // These two are the MARGINAL cost of the checks, not of the restructuring
    // that landing them required (reading output amounts rather than only assets,
    // and wider witness tuples). STATUS.md quotes both figures and says which is
    // which.
    let limit_cost = base - g;
    assert!(
        (20_000..300_000).contains(&limit_cost),
        "the transfer limit is {limit_cost} milli-WU; STATUS.md quotes ~74k"
    );
    let window_cost = base - h;
    assert!(
        (80_000..500_000).contains(&window_cost),
        "the height windows are {window_cost} milli-WU; STATUS.md quotes ~184k"
    );
}
