//! Policy commitment pi (design doc section 3.1).
//!
//!   pi = H_"OpenDAMP/policy/v1"(version_u8 || asset_A || seq_u64 || rules_root)
//!
//! where H_tag is the BIP340-style tagged hash SHA256(SHA256(tag)||SHA256(tag)||msg),
//! asset_A is the asset id in internal (hash) byte order and seq is big-endian.
//!
//! rules_root is a two-level binary Merkle root over the four predicate
//! commitments in fixed order [blacklist, whitelist, limit, windows]; an
//! absent predicate commits to 32 zero bytes:
//!
//!   rules_root = SHA256(SHA256(c_bl || c_wl) || SHA256(c_lim || c_win))
//!
//! For v1 the whitelist commitment is its dmt-v1 root; the blacklist
//! commitment is its dmt-v1 root (enforced by issuer policy discipline, not
//! in-covenant; see STATUS.md); limit commits to BE64(limit) left-padded to
//! 32 bytes; windows is unused (zero).

use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};

pub const EMPTY_COMMITMENT: [u8; 32] = [0u8; 32];

fn sha256_cat(parts: &[&[u8]]) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    for p in parts {
        eng.input(p);
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    sha256_cat(&[&t, &t, msg])
}

pub fn rules_root(
    blacklist: Option<[u8; 32]>,
    whitelist: Option<[u8; 32]>,
    limit: Option<u64>,
    windows: Option<[u8; 32]>,
) -> [u8; 32] {
    let c_bl = blacklist.unwrap_or(EMPTY_COMMITMENT);
    let c_wl = whitelist.unwrap_or(EMPTY_COMMITMENT);
    let c_lim = limit
        .map(|l| {
            let mut c = [0u8; 32];
            c[24..].copy_from_slice(&l.to_be_bytes());
            c
        })
        .unwrap_or(EMPTY_COMMITMENT);
    let c_win = windows.unwrap_or(EMPTY_COMMITMENT);
    let left = sha256_cat(&[&c_bl, &c_wl]);
    let right = sha256_cat(&[&c_lim, &c_win]);
    sha256_cat(&[&left, &right])
}

/// `asset_a_internal` is the asset id in internal (hash) byte order.
pub fn pi(asset_a_internal: [u8; 32], seq: u64, rules_root: [u8; 32]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(1 + 32 + 8 + 32);
    msg.push(0x01u8); // version
    msg.extend_from_slice(&asset_a_internal);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&rules_root);
    tagged_hash("OpenDAMP/policy/v1", &msg)
}
