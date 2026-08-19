package store

// Pledges: a restricted-asset holding committed as loan collateral.
//
// A Pignus loan normally locks collateral in a covenant, and the covenant is
// the whole of the enforcement -- no issuer, no server, nobody to ask. That
// cannot work for a restricted asset, and the reason is not an oversight in
// either design. A restricted asset may only ever sit at an enclave output the
// policy server co-signs for; a covenant vault is not one, so the asset cannot
// legally be moved into it. And if it could, the covenant would let the
// collateral leave to whoever satisfied the loan's terms, which is exactly the
// transfer restriction the issuer exists to enforce. Self-enforcing collateral
// and issuer-enforced transferability are in direct tension: you can have one.
//
// So a pledge is the honest alternative. The collateral never moves. It stays
// in the holder's own enclave, and the SERVER refuses to move it while the
// pledge stands -- releasing it when the debt is repaid, or delivering it to
// the lender when the loan defaults or is liquidated.
//
// What that costs, stated plainly because a user must be able to see it: the
// lender's security is the issuer's promise, not a script. A policy server that
// is dishonest or compromised can release a pledge without repayment, and no
// amount of checking on the lender's side would reveal it beforehand. Pignus
// calls this Tier C and labels it issuer-permissioned everywhere a user can see
// it, because it is a different product from a covenant loan wearing the same
// name.

// PledgeState is where a pledge is in its life.
type PledgeState string

const (
	PledgeOpen     PledgeState = "open"     // collateral locked in place
	PledgeReleased PledgeState = "released" // debt repaid, holder free again
	PledgeSeized   PledgeState = "seized"   // delivered to the lender
)

// Pledge locks a quantity of one restricted asset in a holder's enclave against
// a debt owed to a lender.
type Pledge struct {
	ID       string      `json:"id"`
	AssetID  string      `json:"asset_id"`
	Holder   string      `json:"holder_aid"`
	Lender   string      `json:"lender_aid"`
	Atoms    uint64      `json:"atoms"`
	State    PledgeState `json:"state"`
	Created  int64       `json:"created_height"`
	Maturity int64       `json:"maturity_height"`

	// What the holder owes, recorded so a release can be checked against the
	// loan rather than taken on trust. The debt is settled OUTSIDE this
	// server -- it is an ordinary Sequentia asset moving to the lender -- and
	// `RepaidTxid` records the transaction the issuer accepted as proof.
	DebtAsset string `json:"debt_asset,omitempty"`
	DebtAtoms uint64 `json:"debt_atoms,omitempty"`
	RepaidTx  string `json:"repaid_txid,omitempty"`

	// Why the pledge ended, for the transparency log and for anyone asking
	// afterwards whether a seizure was justified.
	Note string `json:"note,omitempty"`
}

// Open reports whether this pledge still locks collateral.
func (p *Pledge) Open() bool { return p.State == PledgeOpen }

// PledgedAtoms totals the open pledges a holder has against one asset.
//
// This is the number the transfer check subtracts from a holder's balance: a
// transfer may spend anything ABOVE it and nothing below.
func PledgedAtoms(st *State, assetID, holderAID string) uint64 {
	var total uint64
	for _, p := range st.Pledges {
		if p.Open() && p.AssetID == assetID && p.Holder == holderAID {
			total += p.Atoms
		}
	}
	return total
}

// PledgesFor lists a holder's pledges against one asset, open or not.
func PledgesFor(st *State, assetID, holderAID string) []*Pledge {
	var out []*Pledge
	for _, p := range st.Pledges {
		if p.AssetID == assetID && p.Holder == holderAID {
			out = append(out, p)
		}
	}
	return out
}
