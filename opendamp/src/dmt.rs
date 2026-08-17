//! dmt-v1: the sorted-leaf dense Merkle tree the OpenDAMP covenants verify
//! membership against. Byte-exact specification in `SPEC-dmt-v1.md`; a plain
//! Go mirror lives in `gomirror/dmt/`.
//!
//!   depth D = 16 (65,536 slots)
//!   slot 0           = GUARD_LO (32 x 0x00)
//!   slots 1..=n      = the n real keys, sorted ascending bytewise, unique
//!   slots n+1..65535 = GUARD_HI (32 x 0xff)
//!   leaf(key) = SHA256(0x00 || key)
//!   node(l,r) = SHA256(0x01 || l || r)     (no sorting: positional)
//!
//! Membership proof: 16 sibling hashes bottom-up plus the leaf index (whose
//! bit j says the running node is the right child at level j).

use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};

pub const DEPTH: usize = 16;
pub const SLOTS: usize = 1 << DEPTH;
pub const GUARD_LO: [u8; 32] = [0x00; 32];
pub const GUARD_HI: [u8; 32] = [0xff; 32];

fn sha256_all(parts: &[&[u8]]) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    for p in parts {
        eng.input(p);
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

pub fn leaf_hash(key: &[u8; 32]) -> [u8; 32] {
    sha256_all(&[&[0x00], key])
}

/// dmt-v1 INTERVAL leaf: `SHA256(0x02 || lo || hi)`. Used by the blacklist tree,
/// which stores the gaps between listed keys rather than the keys themselves, so
/// that non-membership is one membership proof of the covering interval instead
/// of an adjacency argument over proof indices.
pub fn interval_leaf_hash(lo: &[u8; 32], hi: &[u8; 32]) -> [u8; 32] {
    sha256_all(&[&[0x02], lo, hi])
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_all(&[&[0x01], left, right])
}

/// A membership proof: bottom-up siblings plus the leaf index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub siblings: [[u8; 32]; DEPTH],
    pub index: u16,
}

impl Proof {
    /// The covenant's witness encoding: (sibling, node_is_right) per level.
    pub fn levels(&self) -> Vec<([u8; 32], bool)> {
        (0..DEPTH)
            .map(|j| (self.siblings[j], (self.index >> j) & 1 == 1))
            .collect()
    }
}

pub fn verify(root: &[u8; 32], key: &[u8; 32], proof: &Proof) -> bool {
    let mut node = leaf_hash(key);
    for j in 0..DEPTH {
        let sib = &proof.siblings[j];
        node = if (proof.index >> j) & 1 == 1 {
            node_hash(sib, &node)
        } else {
            node_hash(&node, sib)
        };
    }
    &node == root
}

/// The dense tree over the sorted key set (guards included implicitly).
pub struct Tree {
    /// Sorted unique real keys (guards excluded).
    pub keys: Vec<[u8; 32]>,
    /// levels[0] = leaves (only the occupied prefix, padding handled by
    /// `pad[level]`); levels[DEPTH] = [root].
    levels: Vec<Vec<[u8; 32]>>,
    /// pad[j] = hash of an all-GUARD_HI subtree of height j.
    pad: Vec<[u8; 32]>,
}

impl Tree {
    /// Build from real keys (any order; deduplicated after sorting is an
    /// error, as are guard-valued keys).
    pub fn new(mut keys: Vec<[u8; 32]>) -> Result<Self, String> {
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err("duplicate key in dmt-v1 tree".into());
        }
        if keys.iter().any(|k| *k == GUARD_LO || *k == GUARD_HI) {
            return Err("key collides with a dmt-v1 guard value".into());
        }
        if keys.len() > SLOTS - 2 {
            return Err(format!("dmt-v1 capacity is {} keys", SLOTS - 2));
        }

        // Padding subtree hashes per level.
        let mut pad = Vec::with_capacity(DEPTH + 1);
        pad.push(leaf_hash(&GUARD_HI));
        for j in 0..DEPTH {
            let h = node_hash(&pad[j], &pad[j]);
            pad.push(h);
        }

        // Occupied prefix of each level.
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(DEPTH + 1);
        let mut level0: Vec<[u8; 32]> = Vec::with_capacity(keys.len() + 1);
        level0.push(leaf_hash(&GUARD_LO));
        level0.extend(keys.iter().map(leaf_hash));
        levels.push(level0);
        for j in 0..DEPTH {
            let prev = &levels[j];
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = &prev[i];
                let right = if i + 1 < prev.len() { &prev[i + 1] } else { &pad[j] };
                next.push(node_hash(left, right));
                i += 2;
            }
            levels.push(next);
        }
        Ok(Tree { keys, levels, pad })
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels[DEPTH][0]
    }

    /// Slot index of `key`, if present (guards are provable members too).
    pub fn slot_of(&self, key: &[u8; 32]) -> Option<u16> {
        if *key == GUARD_LO {
            return Some(0);
        }
        if *key == GUARD_HI {
            // First padding slot.
            return u16::try_from(self.keys.len() + 1).ok();
        }
        self.keys
            .binary_search(key)
            .ok()
            .map(|i| (i + 1) as u16)
    }

    fn node_at(&self, level: usize, idx: usize) -> [u8; 32] {
        if idx < self.levels[level].len() {
            self.levels[level][idx]
        } else {
            self.pad[level]
        }
    }

    pub fn prove(&self, key: &[u8; 32]) -> Option<Proof> {
        let slot = self.slot_of(key)? as usize;
        let mut siblings = [[0u8; 32]; DEPTH];
        let mut idx = slot;
        for (j, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.node_at(j, idx ^ 1);
            idx >>= 1;
        }
        Some(Proof {
            siblings,
            index: slot as u16,
        })
    }
}

/// The blacklist tree: a dmt-v1 tree whose leaves are the intervals between
/// consecutive listed keys.
///
/// Listing `k_1 < ... < k_n` produces `n+1` interval leaves
/// `(GUARD_LO, k_1), (k_1, k_2), ..., (k_n, GUARD_HI)`, in that (sorted) slot
/// order. Padding slots hold the degenerate interval `(GUARD_HI, GUARD_HI)`,
/// which can never strictly contain anything and so is inert.
///
/// A key is provably absent exactly when some interval strictly contains it;
/// because a listed key is an interval *endpoint* and the covenant's comparisons
/// are strict, a listed key has no such interval. That is the freeze.
pub struct IntervalTree {
    /// Sorted unique listed keys.
    pub keys: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
    pad: Vec<[u8; 32]>,
}

/// One interval and the proof that it is in the blacklist tree.
#[derive(Clone, Debug)]
pub struct IntervalProof {
    pub lo: [u8; 32],
    pub hi: [u8; 32],
    pub proof: Proof,
}

impl IntervalTree {
    pub fn new(mut keys: Vec<[u8; 32]>) -> Result<Self, String> {
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err("duplicate key in dmt-v1 blacklist".into());
        }
        if keys.iter().any(|k| *k == GUARD_LO || *k == GUARD_HI) {
            return Err("blacklist key collides with a dmt-v1 guard value".into());
        }
        // n keys produce n+1 intervals, so capacity is one lower than the
        // whitelist tree's.
        if keys.len() + 1 > SLOTS {
            return Err(format!("dmt-v1 blacklist capacity is {} keys", SLOTS - 1));
        }

        let pad_leaf = interval_leaf_hash(&GUARD_HI, &GUARD_HI);
        let mut pad = Vec::with_capacity(DEPTH + 1);
        pad.push(pad_leaf);
        for j in 0..DEPTH {
            let h = node_hash(&pad[j], &pad[j]);
            pad.push(h);
        }

        let mut level0 = Vec::with_capacity(keys.len() + 1);
        let mut lo = GUARD_LO;
        for k in &keys {
            level0.push(interval_leaf_hash(&lo, k));
            lo = *k;
        }
        level0.push(interval_leaf_hash(&lo, &GUARD_HI));

        let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(DEPTH + 1);
        levels.push(level0);
        for j in 0..DEPTH {
            let prev = &levels[j];
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = &prev[i];
                let right = if i + 1 < prev.len() { &prev[i + 1] } else { &pad[j] };
                next.push(node_hash(left, right));
                i += 2;
            }
            levels.push(next);
        }
        Ok(IntervalTree { keys, levels, pad })
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels[DEPTH][0]
    }

    fn node_at(&self, level: usize, idx: usize) -> [u8; 32] {
        if idx < self.levels[level].len() {
            self.levels[level][idx]
        } else {
            self.pad[level]
        }
    }

    /// Prove `key` is NOT listed, by exhibiting the interval that strictly
    /// contains it. Returns `None` when the key IS listed - which is the whole
    /// point: a frozen outpoint cannot be given a proof.
    pub fn prove_absent(&self, key: &[u8; 32]) -> Option<IntervalProof> {
        if *key == GUARD_LO || *key == GUARD_HI || self.keys.binary_search(key).is_ok() {
            return None;
        }
        // Slot i is the interval (keys[i-1], keys[i]), with the guards at the
        // ends; the covering interval is the one at the insertion point.
        let slot = self.keys.partition_point(|k| k < key);
        let lo = if slot == 0 { GUARD_LO } else { self.keys[slot - 1] };
        let hi = if slot == self.keys.len() {
            GUARD_HI
        } else {
            self.keys[slot]
        };
        let mut siblings = [[0u8; 32]; DEPTH];
        let mut idx = slot;
        for (j, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.node_at(j, idx ^ 1);
            idx >>= 1;
        }
        Some(IntervalProof {
            lo,
            hi,
            proof: Proof {
                siblings,
                index: slot as u16,
            },
        })
    }
}

/// Verify a blacklist non-membership proof the way the covenant does.
pub fn verify_absent(root: &[u8; 32], key: &[u8; 32], p: &IntervalProof) -> bool {
    if !(&p.lo[..] < &key[..] && &key[..] < &p.hi[..]) {
        return false;
    }
    let mut node = interval_leaf_hash(&p.lo, &p.hi);
    for j in 0..DEPTH {
        let sib = &p.proof.siblings[j];
        node = if (p.proof.index >> j) & 1 == 1 {
            node_hash(sib, &node)
        } else {
            node_hash(&node, sib)
        };
    }
    &node == root
}

/// The blacklist policy key of an outpoint: `SHA256(txid || BE32(vout))` with
/// `txid` in internal (consensus) byte order, matching what the
/// `input_prev_outpoint` jet yields.
pub fn outpoint_key(txid_internal: &[u8; 32], vout: u32) -> [u8; 32] {
    sha256_all(&[txid_internal, &vout.to_be_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = b;
        x[31] = b;
        x
    }

    #[test]
    fn membership_roundtrip() {
        let tree = Tree::new(vec![k(3), k(1), k(2)]).unwrap();
        let root = tree.root();
        for key in [k(1), k(2), k(3), GUARD_LO, GUARD_HI] {
            let proof = tree.prove(&key).expect("member");
            assert!(verify(&root, &key, &proof), "proof verifies");
        }
        // Non-member has no proof; a member's proof does not transfer.
        assert!(tree.prove(&k(9)).is_none());
        let p1 = tree.prove(&k(1)).unwrap();
        assert!(!verify(&root, &k(9), &p1));
    }

    #[test]
    fn root_changes_with_set() {
        let a = Tree::new(vec![k(1)]).unwrap().root();
        let b = Tree::new(vec![k(1), k(2)]).unwrap().root();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_duplicates_and_guards() {
        assert!(Tree::new(vec![k(1), k(1)]).is_err());
        assert!(Tree::new(vec![GUARD_HI]).is_err());
    }

    /// Golden vectors pinning the format. The Go mirror in gomirror/dmt
    /// asserts the same literals, and SPEC-dmt-v1.md section 6 quotes them; a
    /// change here is a consensus-visible format change.
    #[test]
    fn golden_vectors() {
        assert_eq!(
            crate::hexutil::hex(&leaf_hash(&GUARD_LO)),
            "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9"
        );
        assert_eq!(
            crate::hexutil::hex(&leaf_hash(&GUARD_HI)),
            "5e16d316ecd5773e50c3b02737d424192b02f25b4245822079181c557aafda7d"
        );
        assert_eq!(
            crate::hexutil::hex(&Tree::new(vec![]).unwrap().root()),
            "e69f2dc2186b1cca0ed37d851b60121a87832be1ff7f61d58bc4931d26c844cf"
        );

        // The three-key whitelist of examples/snapshot-seq0.json, supplied out
        // of order: the tree sorts by key bytes, so carol (0x46..) lands in
        // slot 2, before bob (0x4d..).
        let alice = key_hex("1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
        let bob = key_hex("4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766");
        let carol = key_hex("462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b");
        let tree = Tree::new(vec![alice, bob, carol]).unwrap();
        assert_eq!(
            crate::hexutil::hex(&tree.root()),
            "dc9d33e167118409fba74538497bf7a984166cd60dc92ee62e4ad5283cf52118"
        );
        assert_eq!(tree.slot_of(&alice), Some(1));
        assert_eq!(tree.slot_of(&carol), Some(2));
        assert_eq!(tree.slot_of(&bob), Some(3));
    }

    /// node() must be positional. Copying taproot's sorted TapBranch here is
    /// the most likely porting bug, so it is asserted against.
    #[test]
    fn node_hash_is_positional() {
        let a = leaf_hash(&k(1));
        let b = leaf_hash(&k(2));
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }

    fn key_hex(s: &str) -> [u8; 32] {
        crate::hexutil::unhex32(s).expect("32-byte hex key")
    }

    // ------------------------------------------------------- blacklist tree

    #[test]
    fn absent_keys_are_provable_and_listed_keys_are_not() {
        let listed = vec![k(10), k(20), k(30)];
        let tree = IntervalTree::new(listed.clone()).unwrap();
        let root = tree.root();

        // Every listed key is UNPROVABLE - that is the freeze.
        for key in &listed {
            assert!(
                tree.prove_absent(key).is_none(),
                "a listed key must have no non-membership proof"
            );
        }
        // Keys below, between and above the listed range are all provable.
        for key in [k(1), k(15), k(25), k(99)] {
            let p = tree.prove_absent(&key).expect("unlisted key is provable");
            assert!(verify_absent(&root, &key, &p), "proof must verify");
            assert!(p.lo < key && key < p.hi, "the interval must strictly contain the key");
        }
    }

    #[test]
    fn an_interval_cannot_be_stretched_over_a_listed_key() {
        let tree = IntervalTree::new(vec![k(20)]).unwrap();
        let root = tree.root();
        // The interval below k(20) is a genuine tree leaf, but claiming it covers
        // k(20) itself fails the strict containment test.
        let p = tree.prove_absent(&k(10)).unwrap();
        let mut forged = p.clone();
        assert!(!verify_absent(&root, &k(20), &forged), "must not cover the endpoint");
        // Nor can its endpoints be edited: that changes the leaf, so the path
        // no longer reaches the root.
        forged.hi = k(99);
        assert!(!verify_absent(&root, &k(50), &forged), "an edited interval must not verify");
    }

    #[test]
    fn empty_blacklist_proves_everything_absent() {
        let tree = IntervalTree::new(vec![]).unwrap();
        let root = tree.root();
        let p = tree.prove_absent(&k(7)).expect("provable");
        assert_eq!(p.lo, GUARD_LO);
        assert_eq!(p.hi, GUARD_HI);
        assert!(verify_absent(&root, &k(7), &p));
    }

    #[test]
    fn padding_interval_is_inert() {
        // Padding slots hold (GUARD_HI, GUARD_HI), which is in the tree and so has
        // a valid path, but cannot strictly contain anything.
        let tree = IntervalTree::new(vec![k(5)]).unwrap();
        let root = tree.root();
        let degenerate = IntervalProof {
            lo: GUARD_HI,
            hi: GUARD_HI,
            proof: Proof { siblings: [[0u8; 32]; DEPTH], index: 2 },
        };
        assert!(!verify_absent(&root, &k(9), &degenerate));
    }

    #[test]
    fn blacklist_leaf_domain_is_separate_from_the_whitelist_leaf_domain() {
        // A whitelist membership proof must not be replayable as a blacklist
        // non-membership proof; the leading domain byte is what prevents it.
        assert_ne!(leaf_hash(&k(1)), interval_leaf_hash(&k(1), &k(1)));
    }

    #[test]
    fn outpoint_key_is_txid_then_big_endian_vout() {
        let txid = [0xabu8; 32];
        let expected = {
            let mut eng = sha256::Hash::engine();
            eng.input(&txid);
            eng.input(&[0x00, 0x00, 0x01, 0x00]); // vout 256, big-endian
            sha256::Hash::from_engine(eng).to_byte_array()
        };
        assert_eq!(outpoint_key(&txid, 256), expected);
    }

    /// Independently recomputed from the spec (a third implementation, in
    /// Python, agreed on both); the Go mirror asserts the same literals.
    const PAD_INTERVAL_LEAF: &str =
        "507647244d0d51f754f23c5f23c4f9e6a84eeabd0524bd20fe2d932f539be8d4";
    const EMPTY_BL_ROOT: &str =
        "009a25ef01f6cade2d114b8315aab47bf5599e3a1386c2f1d414f0e8d6dbf301";

    #[test]
    fn blacklist_golden_vectors() {
        assert_eq!(
            crate::hexutil::hex(&interval_leaf_hash(&GUARD_LO, &GUARD_HI)),
            "1fd8164b6e61192e120f01ca504c786a6e193abe0265104c1303a9b1e09afc39",
            "the sole interval of an empty blacklist"
        );
        assert_eq!(
            crate::hexutil::hex(&interval_leaf_hash(&GUARD_HI, &GUARD_HI)),
            PAD_INTERVAL_LEAF,
            "the inert padding interval"
        );
        assert_eq!(
            crate::hexutil::hex(&IntervalTree::new(vec![]).unwrap().root()),
            EMPTY_BL_ROOT,
            "empty-blacklist root"
        );
    }
}
