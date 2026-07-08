#!/usr/bin/env python3
"""Golden-vector generator for openampd's Go implementation of Elements
taproot primitives. Runs against the Sequentia node repo's functional test
framework (the same code the M0 proof used, itself validated by consensus):

    PYTHONPATH=$SEQ_REPO/test/functional python3 tools/gen_vectors.py > openampd/internal/elements/testdata/vectors.json
"""

import json
import sys

from test_framework.key import compute_xonly_pubkey, sign_schnorr, verify_schnorr
from test_framework.messages import (
    CTxOutWitness,
    COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, CTxOutAsset, CTxOutValue,
    uint256_from_str,
)
from test_framework.script import (
    CScript, OP_CHECKSIG, OP_CHECKSIGVERIFY, SIGHASH_DEFAULT, SIGHASH_ALL,
    TaprootSignatureHash, TaggedHash, taproot_construct,
)

NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

def h2b(h):
    return bytes.fromhex(h)

def det(i, n=32):
    return bytes([i] * n)

def main():
    out = {}

    # 1. Elements tagged hashes
    out["tagged"] = []
    for tag in ("TapLeaf/elements", "TapBranch/elements", "TapTweak/elements", "TapSighash/elements"):
        for msg in (b"", b"\x00" * 32, bytes(range(64))):
            out["tagged"].append({"tag": tag, "msg": msg.hex(), "hash": TaggedHash(tag, msg).hex()})

    # 2. Enclave taproot construction (transfer + clawback leaves)
    user_x = compute_xonly_pubkey(det(1))[0]
    policy_x = compute_xonly_pubkey(det(2))[0]
    issuer_x = compute_xonly_pubkey(det(3))[0]
    transfer = CScript([user_x, OP_CHECKSIGVERIFY, policy_x, OP_CHECKSIG])
    claw = CScript([issuer_x, OP_CHECKSIGVERIFY, policy_x, OP_CHECKSIG])
    tap = taproot_construct(NUMS, [("transfer", transfer), ("claw", claw)])
    out["enclave"] = {
        "user_x": user_x.hex(), "policy_x": policy_x.hex(), "issuer_x": issuer_x.hex(),
        "nums": NUMS.hex(),
        "transfer_script": bytes(transfer).hex(),
        "claw_script": bytes(claw).hex(),
        "spk": bytes(tap.scriptPubKey).hex(),
        "negflag": tap.negflag,
        "transfer_control": (bytes([tap.leaves["transfer"].version + tap.negflag]) + tap.internal_pubkey + tap.leaves["transfer"].merklebranch).hex(),
        "claw_control": (bytes([tap.leaves["claw"].version + tap.negflag]) + tap.internal_pubkey + tap.leaves["claw"].merklebranch).hex(),
    }
    # single-leaf variant
    tap1 = taproot_construct(NUMS, [("transfer", transfer)])
    out["enclave_single"] = {
        "spk": bytes(tap1.scriptPubKey).hex(),
        "negflag": tap1.negflag,
        "control": (bytes([tap1.leaves["transfer"].version + tap1.negflag]) + tap1.internal_pubkey + tap1.leaves["transfer"].merklebranch).hex(),
    }

    # 3. Sighash vectors: 2-input explicit tx (enclave + fee input), 4 outputs
    asset = det(0xAA)
    asset_out = b"\x01" + asset
    btc = det(0xBB)
    btc_out = b"\x01" + btc
    genesis = uint256_from_str(det(0x77))

    tx = CTransaction()
    tx.nVersion = 2
    tx.vin.append(CTxIn(COutPoint(uint256_from_str(det(0x11)), 0)))
    tx.vin.append(CTxIn(COutPoint(uint256_from_str(det(0x22)), 3)))
    wallet_spk = h2b("0014") + det(0x33, 20)
    tx.vout.append(CTxOut(CTxOutValue(60 * 10**8), tap.scriptPubKey, CTxOutAsset(asset_out)))
    tx.vout.append(CTxOut(CTxOutValue(40 * 10**8), tap1.scriptPubKey, CTxOutAsset(asset_out)))
    tx.vout.append(CTxOut(CTxOutValue(99995000), wallet_spk, CTxOutAsset(btc_out)))
    tx.vout.append(CTxOut(CTxOutValue(5000), b"", CTxOutAsset(btc_out)))
    # Pad witnesses to consensus shape (one per input AND one per output)
    # before any sighash: C++ CTransaction always carries them.
    for _ in tx.vin:
        tx.wit.vtxinwit.append(CTxInWitness())
    for _ in tx.vout:
        tx.wit.vtxoutwit.append(CTxOutWitness())
    spent = [
        CTxOut(CTxOutValue(100 * 10**8), tap.scriptPubKey, CTxOutAsset(asset_out)),
        CTxOut(CTxOutValue(10**8), wallet_spk, CTxOutAsset(btc_out)),
    ]
    out["sighash"] = []
    for idx, leafname, hashty in ((0, "transfer", SIGHASH_DEFAULT), (0, "claw", SIGHASH_DEFAULT), (0, "transfer", SIGHASH_ALL)):
        msg = TaprootSignatureHash(tx, spent, hashty, genesis, idx, scriptpath=True,
                                   script=tap.leaves[leafname].script)
        out["sighash"].append({
            "tx": tx.serialize().hex(),
            "spent": [o.serialize().hex() for o in spent],
            "genesis": det(0x77)[::-1].hex(),  # display order
            "input": idx, "leaf": bytes(tap.leaves[leafname].script).hex(),
            "hashtype": hashty, "sighash": msg.hex(),
        })

    # 3b. issuance-input variant
    tx2 = CTransaction()
    tx2.nVersion = 2
    tx2.vin.append(CTxIn(COutPoint(uint256_from_str(det(0x44)), 1)))
    tx2.vin[0].assetIssuance.assetEntropy = uint256_from_str(det(0x55))
    tx2.vin[0].assetIssuance.nAmount = CTxOutValue(100 * 10**8)
    tx2.vin[0].assetIssuance.nInflationKeys = CTxOutValue(10**8)
    tx2.vin[0].assetIssuance.denomination = 8
    tx2.vout.append(CTxOut(CTxOutValue(100 * 10**8), tap.scriptPubKey, CTxOutAsset(asset_out)))
    tx2.vout.append(CTxOut(CTxOutValue(5000), b"", CTxOutAsset(btc_out)))
    tx2.wit.vtxinwit.append(CTxInWitness())
    for _ in tx2.vout:
        tx2.wit.vtxoutwit.append(CTxOutWitness())
    spent2 = [CTxOut(CTxOutValue(10**8), wallet_spk, CTxOutAsset(btc_out))]
    msg2 = TaprootSignatureHash(tx2, spent2, SIGHASH_DEFAULT, genesis, 0, scriptpath=True,
                                script=tap.leaves["transfer"].script)
    out["sighash_issuance"] = {
        "tx": tx2.serialize().hex(),
        "spent": [o.serialize().hex() for o in spent2],
        "genesis": det(0x77)[::-1].hex(),
        "input": 0, "leaf": bytes(tap.leaves["transfer"].script).hex(),
        "hashtype": SIGHASH_DEFAULT, "sighash": msg2.hex(),
    }

    # 4. schnorr sanity (sign with known key over known msg; Go verifies)
    sig = sign_schnorr(det(1), det(0x66))
    assert verify_schnorr(user_x, sig, det(0x66))
    out["schnorr"] = {"sec": det(1).hex(), "pub": user_x.hex(), "msg": det(0x66).hex(), "sig": sig.hex()}

    # 5. issuance id derivation (cross-check for Go fastmerkle)
    import feature_openamp_m0 as m0
    prevout = COutPoint(uint256_from_str(det(0x88)), 7)
    entropy, asset_i, token_i = m0.derive_issuance_ids(prevout, det(0x99))
    out["issuance_ids"] = {
        "prevout_hash_internal": det(0x88).hex(), "vout": 7,
        "contract_digest": det(0x99).hex(),
        "entropy": entropy.hex(), "asset": asset_i.hex(), "token": token_i.hex(),
    }

    json.dump(out, sys.stdout, indent=1)

if __name__ == "__main__":
    main()
