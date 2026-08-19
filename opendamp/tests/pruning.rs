//! Pruning drops the witness that execution never reads.
//!
//! Consensus rejects a redeem program that still contains FAIL nodes ("Program
//! has FAIL node"), so a Simplicity spend must be pruned, and pruning removes
//! the witness leaves no execution path touched. This test pins that behaviour
//! because two things in OpenDAMP now depend on it.
//!
//! It is why a CHANGE output is free. An A output paying the sender's own C_U
//! takes the branch that reads no recipient key, no membership proof and no
//! window, so none of that reaches the wire even though the slot's type still
//! has room for it. Change costs a script comparison and nothing else.
//!
//! And it is why a bad proof cannot be smuggled in. A witness the covenant
//! rejects cannot be pruned at all -- pruning replays the program against the
//! transaction -- so the only submittable form of a bad-proof spend still
//! carries its FAIL nodes and is refused outright. Both doors, and the regtest
//! suite walks through them.
//!
//! (Until the chain granted four weight units of budget per witness byte, this
//! test guarded the opposite property: the verifier carried 22 kB of inert
//! padding that had to be READ, or pruning would drop it and take the execution
//! budget with it. The padding is gone; the mechanism it relied on is not.)

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

/// 32 words of witness data, and an always-taken assertion so that the program
/// has a FAIL node to prune away, exactly like the real covenants.
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
fn pruning_keeps_only_the_witness_that_is_read() {
    let partially_read = pruned_witness_len(&pad_program(false));
    let fully_absorbed = pruned_witness_len(&pad_program(true));

    // Reading one word of 32 leaves ~1 word in the pruned witness: the other 31
    // are dropped. This is the change slot, in miniature.
    assert!(
        partially_read < 200,
        "expected pruning to discard the unread words, kept {partially_read} B"
    );
    // Reading every word keeps all 1024 bytes: nothing is dropped that the
    // program actually touched, so a payment's proof always reaches the wire.
    assert!(
        fully_absorbed >= 1024,
        "reading every word must keep them all, kept only {fully_absorbed} B"
    );
    eprintln!(
        "pruned witness: {partially_read} B when one word is read, \
         {fully_absorbed} B when all 32 are read"
    );
}
