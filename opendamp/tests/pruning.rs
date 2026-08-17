//! Why the verifier's BUDGET_PAD is read rather than merely declared.
//!
//! Consensus rejects a redeem program that still contains FAIL nodes ("Program
//! has FAIL node"), so a Simplicity spend must be pruned. Pruning removes the
//! witness leaves that execution never reads. Those two facts together are the
//! whole reason `programs/verifier.simf` absorbs every pad word with
//! `eq_256(x, x)` instead of just binding it to an unused variable.
//!
//! This test pins the behaviour, because if a future compiler kept unread
//! witness data the pad could be simplified, and if it pruned more aggressively
//! the pad could silently vanish and take the execution budget with it.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use opendamp::elements::{
    confidential, AssetId, BlockHash, LockTime, Script, Sequence, Transaction, TxIn, TxOut,
};
use opendamp::simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use opendamp::simplicityhl::simplicity::Cmr;
use opendamp::simplicityhl::{Arguments, CompiledProgram, WitnessValues};

/// A minimal environment: the programs under test introspect only `num_outputs`.
fn env() -> ElementsEnv<Arc<Transaction>> {
    let txout = TxOut {
        asset: confidential::Asset::Explicit(AssetId::from_slice(&[1u8; 32]).unwrap()),
        value: confidential::Value::Explicit(1000),
        nonce: confidential::Nonce::Null,
        script_pubkey: Script::new(),
        witness: Default::default(),
    };
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: Default::default(),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }],
        output: vec![txout.clone()],
    };
    let cmr = Cmr::unit();
    ElementsEnv::new(
        Arc::new(tx),
        vec![ElementsUtxo {
            script_pubkey: Script::new(),
            asset: txout.asset,
            value: txout.value,
        }],
        0,
        cmr,
        opendamp::tapscript::cu_spend_info(cmr, &opendamp::net::nums_key()).1,
        None,
        BlockHash::from_str(&format!("{:064x}", 7u8)).unwrap(),
    )
}

/// 32 words = 1024 bytes of pad, and an always-taken assertion so that the
/// program has a FAIL node to prune away, exactly like the real covenants.
fn pad_program(absorb_all: bool) -> String {
    let body = if absorb_all {
        // Fold over every word: each is read, so none can be pruned.
        "    assert!(array_fold::<absorb, 32>(pad, true));"
    } else {
        // Read one word only, by destructuring down to it.
        "    let (h, _): ([u256; 16], [u256; 16]) = <[u256; 32]>::into(pad);
    let (h, _): ([u256; 8], [u256; 8]) = <[u256; 16]>::into(h);
    let (h, _): ([u256; 4], [u256; 4]) = <[u256; 8]>::into(h);
    let (h, _): ([u256; 2], [u256; 2]) = <[u256; 4]>::into(h);
    let (h, _): (u256, u256) = <[u256; 2]>::into(h);
    assert!(jet::eq_256(h, h));"
    };
    format!(
        "fn absorb(x: u256, acc: bool) -> bool {{
    jet::eq_256(x, x)
}}

fn main() {{
    let pad: [u256; 32] = witness::BUDGET_PAD;
{body}
    // An assertion that holds, so the compiled program contains a FAIL node
    // for the branch that is never taken - which is what forces pruning.
    match jet::eq_32(jet::num_outputs(), 99) {{
        true => panic!(),
        false => {{}},
    }};
}}
"
    )
}

fn pruned_witness_len(src: &str) -> usize {
    let prog = CompiledProgram::new(src, Arguments::from(HashMap::new()), false)
        .expect("pad program compiles");
    let words: Vec<String> = (0..32).map(|i| format!("0x{i:064x}")).collect();
    let wv: WitnessValues = serde_json::from_str(&format!(
        r#"{{"BUDGET_PAD": {{"value": "[{}]", "type": "[u256; 32]"}}}}"#,
        words.join(", ")
    ))
    .expect("witness parses");
    let e = env();
    let sat = prog
        .satisfy_with_env(wv, Some(&e))
        .expect("program is satisfied and prunes");
    sat.redeem().to_vec_with_witness().1.len()
}

#[test]
fn pruning_keeps_only_the_pad_words_that_are_read() {
    let partially_read = pruned_witness_len(&pad_program(false));
    let fully_absorbed = pruned_witness_len(&pad_program(true));

    // Reading one word of 32 leaves ~1 word in the pruned witness: the other 31
    // are dropped, and with them the budget they would have bought.
    assert!(
        partially_read < 200,
        "expected pruning to discard the unread pad words, kept {partially_read} B"
    );
    // Absorbing every word keeps all 1024 bytes.
    assert!(
        fully_absorbed >= 1024,
        "absorbing every word must keep the whole pad, kept only {fully_absorbed} B"
    );
    eprintln!(
        "pruned witness: {partially_read} B when one word is read, \
         {fully_absorbed} B when all 32 are absorbed"
    );
}
