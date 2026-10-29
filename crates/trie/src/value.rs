//! Leaf values, profile §1: an account leaf holds
//! `RLP[nonce, balance, storageRoot, codeHash]`, a storage leaf the RLP of
//! the minimal big-endian word. Zero words are absent leaves.

use alloy_primitives::{B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::TrieAccount;

/// `keccak(RLP(""))`, the storage root of an account with no storage.
pub const EMPTY_ROOT: B256 = alloy_trie::EMPTY_ROOT_HASH;

/// An account as the trie stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
}

impl Account {
    pub fn encode(&self) -> Vec<u8> {
        let a = TrieAccount::new(self.nonce, self.balance, self.storage_root, self.code_hash);
        let mut out = Vec::with_capacity(a.length());
        a.encode(&mut out);
        out
    }

    /// Decode a leaf value. The whole value must be the account: trailing
    /// bytes are an error, as is any non-minimal integer (alloy-rlp
    /// rejects those).
    pub fn decode(mut bytes: &[u8]) -> Result<Account, alloy_rlp::Error> {
        let a = TrieAccount::decode(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(Account {
            nonce: a.nonce,
            balance: a.balance,
            storage_root: a.storage_root,
            code_hash: a.code_hash,
        })
    }

    pub fn has_storage(&self) -> bool {
        self.storage_root != EMPTY_ROOT
    }
}

/// The RLP of a storage word: minimal big-endian, so zero would encode as
/// the empty string, which the trie never stores. Callers must not emit a
/// leaf for a zero word.
pub fn encode_word(word: &U256) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    word.encode(&mut out);
    out
}

/// Decode a storage leaf value. Rejects a zero word (it would be absent, not
/// a leaf), non-minimal encodings and trailing bytes.
pub fn decode_word(mut bytes: &[u8]) -> Result<U256, alloy_rlp::Error> {
    let w = U256::decode(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(alloy_rlp::Error::UnexpectedLength);
    }
    if w.is_zero() {
        return Err(alloy_rlp::Error::Custom(
            "zero storage word stored as a leaf",
        ));
    }
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_roundtrip_and_empty_account_encoding() {
        let a = Account {
            nonce: 7,
            balance: U256::from(1_000_000u64),
            storage_root: EMPTY_ROOT,
            code_hash: crate::KECCAK_EMPTY,
        };
        let b = a.encode();
        assert_eq!(Account::decode(&b).unwrap(), a);
        assert!(!a.has_storage());
        let mut t = b.clone();
        t.push(0);
        assert!(Account::decode(&t).is_err());
    }

    #[test]
    fn word_roundtrip_and_rejections() {
        let w = U256::from(0x1234u64);
        let b = encode_word(&w);
        assert_eq!(b, vec![0x82, 0x12, 0x34]);
        assert_eq!(decode_word(&b).unwrap(), w);
        assert_eq!(decode_word(&[0x01]).unwrap(), U256::from(1));
        assert!(decode_word(&[0x80]).is_err(), "zero word");
        assert!(decode_word(&[0x81, 0x01]).is_err(), "non-minimal");
        assert!(decode_word(&[0x01, 0x00]).is_err(), "trailing");
        let max = U256::MAX;
        assert_eq!(decode_word(&encode_word(&max)).unwrap(), max);
    }
}
