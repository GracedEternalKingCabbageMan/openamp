# OpenAMP

Open-source issuer-governed assets for the Sequentia network: an open, self-hostable equivalent of Blockstream's AMP2. Issuers manage regulated assets (securities, funds, bonds) whose every transfer is co-signed by an issuer-controlled policy server, with KYC whitelisting, categories, velocity limits, vesting, freezing, distributions, clawback under disclosed terms, and auditor reports. No chain-side changes are required: assets live in 2-of-2 taproot enclaves whose policy key is a FROST threshold, and confidentiality is opt-in per asset just as for any other Sequentia asset (the policy server holds the blinding keys, so the issuer always sees who owns what while outside observers see nothing).

Design document: [`doc/sequentia/openamp-design.md`](https://github.com/GracedEternalKingCabbageMan/SequentiaByClaude/blob/claude/sequentia-bitcoin-sidechain-w6xady/doc/sequentia/openamp-design.md) in the node repository.

## How it works, in short

- A restricted asset lives only in **enclave outputs**: taproot outputs with a NUMS internal key (no key-path spend) and leaves `<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG` (transfer) and `<K_issuer> CHECKSIGVERIFY <K_policy> CHECKSIG` (clawback, default on, disclosed at issuance). `K_policy` is a FROST threshold key, so freeing the asset requires a quorum, not one machine.
- The **asset ID commits to the policy key**: the issuance contract JSON (which names the policy public key) is hashed into the asset's issuance entropy, so anyone can verify the asset-to-policy binding offline. No registry state, no consensus lookup.
- **Confidentiality is opt-in per asset**, as easy as for any other Sequentia asset: amounts and asset tags are blinded to outsiders while the policy server holds the blinding keys, so the issuer always sees who owns what.
- **Fees**: a restricted asset never appears in a fee output, so it can never be swept into a block producer's coinbase. Users still pay costs in the restricted asset via **fee conversion** (the issuer or a registered broker atomically takes a fee-equivalent slice and attaches the real fee in an ordinary asset), and self-paid ordinary-asset fees work with no issuer involvement at all.

## Status

M0–M4 done and live on the Sequentia public testnet: `openampd` runs behind `https://sequentiatestnet.com/openamp/`, a demo asset (BONDX) was issued and transferred, and the SWK web wallet and Ambra ship restricted-asset support. Proofs: [`feature_openamp_m0.py`](https://github.com/GracedEternalKingCabbageMan/SequentiaByClaude/blob/claude/sequentia-bitcoin-sidechain-w6xady/test/functional/feature_openamp_m0.py) and `feature_openamp_daemon.py` in the node repository. Frozen format specifications are under [`spec/`](spec/).

## Roadmap

| Milestone | Scope |
|---|---|
| M0 | enclave proof on regtest — done |
| M1 | `openampd` v0: registration, policy engine, PSET co-sign, chain follower — done |
| M3 | issuer operations: assignments, distributions, vesting, velocity, holder caps, reports, transparency log, clawback ceremony — done |
| M4 | ecosystem: wallet integration, registry, public-testnet demo asset — done |
| M5 | FROST threshold policy key, opt-in confidential assets end to end, registered trading on SeqDEX — in progress |
