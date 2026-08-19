# OpenAMP

`openampd`: a Go daemon that issues and polices issuer-governed restricted assets on Sequentia,
a self-hostable equivalent of Blockstream's AMP2. It requires **zero consensus changes** — it
talks to an ordinary Sequentia node (`elementsd`) over JSON-RPC, and enforcement lives in
taproot script plus the policy server's signature.

`README.md` is the reference for the REST API, the trust model and the flag table. Read it
before changing behaviour; this file covers only what the README does not.

Node and consensus conventions live in the
[`Sequentia`](https://github.com/GracedEternalKingCabbageMan/Sequentia) repo.

## Build, test, run

Go 1.26+. Dependencies are vendored under `vendor/`, so builds work offline.

```sh
go build ./...
go test ./...
go build -o openampd/openampd ./openampd/cmd/openampd
```

There is no CI. `go build ./... && go test ./...` before every PR is the whole gate.

Deployment: `deploy/DEPLOY.md` plus the systemd units in `deploy/`. The server pulls this repo
from GitHub and builds there — never edit source on the server, never copy binaries onto it.

## Layout

| Path | What |
|---|---|
| `openampd/cmd/openampd/` | the daemon |
| `openampd/cmd/keygen`, `cmd/signer` | demo client helpers |
| `openampd/internal/server/` | HTTP API, policy engine, issuance, transfers, clawback, chain follower |
| `openampd/internal/elements/` | minimal Elements tx codec, taproot, sighash — golden-vectored |
| `openampd/internal/fastmerkle/` | issuance entropy and asset/token id derivation |
| `spec/` | frozen formats (contract v1) |
| `tools/gen_vectors.py` | golden-vector generator |

## Things that are expensive to get wrong

- **The golden vectors are the proof that the hand-rolled Elements primitives are byte-exact.**
  If a change to `openampd/internal/elements` breaks them, regenerate or extend the vectors
  against the node repo's functional-test framework — never weaken or delete the test.

  ```sh
  PYTHONPATH=$SEQ_REPO/test/functional python3 tools/gen_vectors.py \
    > openampd/internal/elements/testdata/vectors.json
  go test ./openampd/internal/elements
  ```

- **Precision 0 is a real value, not "unset".** Integer-only restricted assets exist, so any code
  path handling `precision` has to distinguish an explicit `0` from an absent field. This was
  fixed once; do not reintroduce a zero-check that silently substitutes a default.
- **The asset id commits to the policy key**, via the issuance contract JSON hashed into the
  issuance entropy. Changing the contract shape changes every derived asset id. `spec/contract-v1.md`
  is frozen; pre-freeze assets on the live testnet carry legacy fields and must be verified as-is,
  because the hash commits to the exact bytes.
- **A restricted asset must never appear in a fee output.** The policy server refuses to co-sign
  such a transaction. That rule is what stops a restricted asset being swept into a block
  producer's coinbase; do not relax it for convenience.
- **`PolicySigner` in `openampd/internal/server/signer.go` is a deliberate seam.** The committed
  backend is a single local key per asset (testnet only); the threshold backend swaps in behind
  that interface. Keep new signing code behind the interface.
- **Reorg awareness is not optional.** Sequentia reorganises whenever Bitcoin reorganises, so the
  chain follower re-marks transfer records above a fork point as unconfirmed. Velocity accounting
  and ownership reports depend on it.
- **`-demoissuer` holds issuer keys server-side.** It is a testnet demo flag. A production issuer
  keeps that key offline.

## Working in this repo

- **Repository is public.** RPC credentials, issuer tokens and keys never belong in it. The
  daemon's key file lives in its data directory at mode 0600, outside the repo.
- **Commit author:**
  `GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`
- **Always open a pull request, then merge it yourself immediately.** The PR exists so the change
  and its reasoning are recorded, not because anyone is waiting to review it. There is no review
  process. If you are ever told to leave one specific PR open, that applies to that PR only and
  never becomes the default.
- PRs go against `main`, which is the remote default.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as**
`GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`.
Never a personal address.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
