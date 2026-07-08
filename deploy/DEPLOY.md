# Deploying openampd to the Sequentia testnet box

Turnkey deploy of the OpenAMP policy server alongside the public testnet node.
`openampd` talks to the node over RPC only; it never touches consensus or the
node binary. Nothing here modifies the running chain.

Prerequisites on the box:
- The public testnet node running with `-con_any_asset_fees=1` and an RPC
  endpoint (the committee runtime already provides this).
- A funded wallet loaded on that node (the founder treasury, `treasury-clean`)
  to fund issuance and pay the ordinary-asset fees openampd attaches.
- Go (matches the laptop toolchain; install under `~/dev-tools/go` if absent).

## 1. Clone/pull and build (on the box)

```
cd /root/sequentia
git clone https://github.com/GracedEternalKingCabbageMan/openamp.git   # first time
cd openamp && git pull
export PATH=$PATH:~/dev-tools/go/bin
go build -o openampd/openampd ./openampd/cmd/openampd
```

## 2. Secrets env file (box-only, never in git)

Write `/root/sequentia/openampd.env` (chmod 600):

```
OPENAMPD_RPC=http://127.0.0.1:<node-rpc-port>
OPENAMPD_RPCAUTH=<rpcuser>:<rpcpassword>       # or cookie:/root/.../.cookie
OPENAMPD_WALLET=treasury-clean
OPENAMPD_ISSUER_TOKEN=<long-random-token>       # gates the issuer API
OPENAMPD_FEE_ASSET=<display-hex of tSEQ or USDX>   # the asset openampd pays fees in
```

The fee asset must be one the testnet producers accept (on their
`setfeeexchangerates` whitelist). tSEQ (the policy asset) always works.

## 3. Install and start the service

```
cp deploy/openampd.service /etc/systemd/system/openampd.service
systemctl daemon-reload
systemctl enable --now openampd
systemctl status openampd
journalctl -u openampd -f
```

## 4. Expose behind Caddy (optional public API)

openampd listens on 127.0.0.1:8722. To expose the wallet-facing endpoints at
`https://sequentiatestnet.com/openamp/`, add to the Caddyfile:

```
handle_path /openamp/* {
    reverse_proxy 127.0.0.1:8722
}
```

Then `systemctl reload caddy`. Consider leaving the issuer endpoints
(`/v1/issuer/*`) internal-only or firewalled; they are already token-gated.

## 5. Issue the demo restricted asset (BONDX)

Register an issuer account and a holder, then issue. Example against the local
API (token from the env file):

```
# register issuer + first holder (returns AIDs)
curl -s localhost:8722/v1/users -d '{"pubkeys":["<issuer-xonly-hex>"]}'
curl -s localhost:8722/v1/users -d '{"pubkeys":["<holder-xonly-hex>"]}'

# issue 1,000,000 BONDX into the holder's enclave (clawback ON by default)
curl -s localhost:8722/v1/issuer/assets \
  -H "Authorization: Bearer $OPENAMPD_ISSUER_TOKEN" \
  -d '{"name":"OpenAMP Demo Bond","ticker":"BONDX","precision":8,
       "atoms":100000000000000,"holder_aid":"<holder-aid>",
       "issuer_aid":"<issuer-aid>","burn_allowed":true,
       "rules":{"fee_convert_atoms":100}}'
```

The response returns the asset id, the contract JSON, and its hash. Publish
the contract to the registry so wallets can verify the asset-to-policy binding
(§4 of the design doc). Transfers then go through
`POST /v1/transfers` (fee convert/sponsor) or `POST /v1/cosign` (self-paid),
each requiring the holder's signature over the returned sighashes.

## 6. Redeploy

`git pull && go build -o openampd/openampd ./openampd/cmd/openampd && systemctl restart openampd`.
State (registry, keys, transparency log) persists in
`/root/sequentia/openampd-data`.

## Note on keys (testnet demo vs production)

`-demoissuer` holds the issuer and policy keys server-side so the box can issue
and co-sign autonomously. That is appropriate ONLY for the testnet demo. A
production issuer keeps the issuer key offline and runs the policy key behind
an HSM or FROST threshold (design doc §5, M5); openampd's HSM interface is the
seam for that.
