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
}
