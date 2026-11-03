//! Manifest, `RunRef` and `ColdRoot` codecs, v1-min §3 and §5. Fixed-width
//! little-endian integers, byte arrays verbatim, fields in order, no
//! alignment. `Option<T>` is a presence byte (0 or 1, anything else
//! rejected) followed by `T` when present.

use crate::{Error, FORMAT_VERSION};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunRef {
    pub root: [u8; 32],
    pub block_lo: u64,
    pub block_hi: u64,
    pub page_count: u64,
    pub entry_count: u64,
    pub epsilon_pages: u16,
    pub model_bytes: u32,
    pub model_root: [u8; 32],
}

impl RunRef {
    pub const LEN: usize = 32 + 8 + 8 + 8 + 8 + 2 + 4 + 32;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.block_lo.to_le_bytes());
        out.extend_from_slice(&self.block_hi.to_le_bytes());
        out.extend_from_slice(&self.page_count.to_le_bytes());
        out.extend_from_slice(&self.entry_count.to_le_bytes());
        out.extend_from_slice(&self.epsilon_pages.to_le_bytes());
        out.extend_from_slice(&self.model_bytes.to_le_bytes());
        out.extend_from_slice(&self.model_root);
    }

    pub fn decode(b: &[u8]) -> Result<RunRef, Error> {
        if b.len() < Self::LEN {
            return Err(Error::Decode("RunRef short"));
        }
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Ok(RunRef {
            root: b[0..32].try_into().unwrap(),
            block_lo: u64_at(32),
            block_hi: u64_at(40),
            page_count: u64_at(48),
            entry_count: u64_at(56),
            epsilon_pages: u16::from_le_bytes(b[64..66].try_into().unwrap()),
            model_bytes: u32::from_le_bytes(b[66..70].try_into().unwrap()),
            model_root: b[70..102].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub format_version: u32,
    pub chain_id: u64,
    pub profile_id: [u8; 32],
    /// The fold block `F`.
    pub block_number: u64,
    pub block_hash: [u8; 32],
    /// `R`, the block whose state the base holds; 0 before the first base.
    pub rebuild_block: u64,
    pub base: Option<RunRef>,
    pub delta: Option<RunRef>,
}

impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + 32 + 8 + 32 + 8 + 2 * (1 + RunRef::LEN));
        out.extend_from_slice(&self.format_version.to_le_bytes());
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.profile_id);
        out.extend_from_slice(&self.block_number.to_le_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.rebuild_block.to_le_bytes());
        for r in [&self.base, &self.delta] {
            match r {
                Some(r) => {
                    out.push(1);
                    r.encode_into(&mut out);
                }
                None => out.push(0),
            }
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Manifest, Error> {
        let mut o = 0usize;
        let take = |o: &mut usize, n: usize| -> Result<&[u8], Error> {
            if *o + n > b.len() {
                return Err(Error::Decode("Manifest short"));
            }
            let s = &b[*o..*o + n];
            *o += n;
            Ok(s)
        };
        let format_version = u32::from_le_bytes(take(&mut o, 4)?.try_into().unwrap());
        if format_version != FORMAT_VERSION {
            return Err(Error::Decode("format_version"));
        }
        let chain_id = u64::from_le_bytes(take(&mut o, 8)?.try_into().unwrap());
        let profile_id: [u8; 32] = take(&mut o, 32)?.try_into().unwrap();
        let block_number = u64::from_le_bytes(take(&mut o, 8)?.try_into().unwrap());
        let block_hash: [u8; 32] = take(&mut o, 32)?.try_into().unwrap();
        let rebuild_block = u64::from_le_bytes(take(&mut o, 8)?.try_into().unwrap());
        let opt = |o: &mut usize| -> Result<Option<RunRef>, Error> {
            match take(o, 1)?[0] {
                0 => Ok(None),
                1 => Ok(Some(RunRef::decode(take(o, RunRef::LEN)?)?)),
                _ => Err(Error::Decode("presence byte")),
            }
        };
        let base = opt(&mut o)?;
        let delta = opt(&mut o)?;
        if o != b.len() {
            return Err(Error::Decode("Manifest trailing bytes"));
        }
        Ok(Manifest { format_version, chain_id, profile_id, block_number, block_hash, rebuild_block, base, delta })
    }

    pub fn root(&self) -> [u8; 32] {
        *blake3::hash(&self.encode()).as_bytes()
    }
}

/// Stage A anchor object `cold/<F>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColdRoot {
    pub chain_id: u64,
    pub profile_id: [u8; 32],
    pub height: u64,
    pub block_hash: [u8; 32],
    pub manifest_root: [u8; 32],
    pub signature: [u8; 64],
}

pub const COLD_ROOT_DOMAIN: &[u8] = b"csl-cold-root-v1";

impl ColdRoot {
    pub const LEN: usize = 8 + 32 + 8 + 32 + 32 + 64;

    fn fields(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN - 64);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.profile_id);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.manifest_root);
        out
    }

    /// `blake3("csl-cold-root-v1" ‖ fields before signature)`.
    pub fn signing_message(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(COLD_ROOT_DOMAIN);
        h.update(&self.fields());
        *h.finalize().as_bytes()
    }

    pub fn sign(mut self, key: &SigningKey) -> ColdRoot {
        self.signature = key.sign(&self.signing_message()).to_bytes();
        self
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        key.verify(&self.signing_message(), &Signature::from_bytes(&self.signature)).is_ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.fields();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(b: &[u8]) -> Result<ColdRoot, Error> {
        if b.len() != Self::LEN {
            return Err(Error::Decode("ColdRoot length"));
        }
        Ok(ColdRoot {
            chain_id: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            profile_id: b[8..40].try_into().unwrap(),
            height: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            block_hash: b[48..80].try_into().unwrap(),
            manifest_root: b[80..112].try_into().unwrap(),
            signature: b[112..176].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(x: u8) -> RunRef {
        RunRef { root: [x; 32], block_lo: 1, block_hi: 2, page_count: 3, entry_count: 4, epsilon_pages: 5, model_bytes: 6, model_root: [x + 1; 32] }
    }

    #[test]
    fn manifest_roundtrip_all_shapes() {
        for (base, delta) in [(None, None), (Some(rr(1)), None), (None, Some(rr(2))), (Some(rr(1)), Some(rr(2)))] {
            let m = Manifest { format_version: 1, chain_id: 7, profile_id: [9; 32], block_number: 10, block_hash: [3; 32], rebuild_block: 0, base, delta };
            let b = m.encode();
            assert_eq!(Manifest::decode(&b).unwrap(), m);
            let mut bad = b.clone();
            bad.push(0);
            assert!(Manifest::decode(&bad).is_err());
        }
        let m = Manifest { format_version: 1, chain_id: 7, profile_id: [9; 32], block_number: 10, block_hash: [3; 32], rebuild_block: 0, base: None, delta: None };
        let mut b = m.encode();
        let last = b.len() - 1;
        b[last] = 2;
        assert!(matches!(Manifest::decode(&b), Err(Error::Decode("presence byte"))));
    }

    #[test]
    fn cold_root_sign_verify_roundtrip() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let c = ColdRoot { chain_id: 1, profile_id: [2; 32], height: 30, block_hash: [4; 32], manifest_root: [5; 32], signature: [0; 64] }.sign(&key);
        assert!(c.verify(&key.verifying_key()));
        let b = c.encode();
        assert_eq!(b.len(), ColdRoot::LEN);
        assert_eq!(ColdRoot::decode(&b).unwrap(), c);
        let mut t = c;
        t.height = 31;
        assert!(!t.verify(&key.verifying_key()));
        assert!(!c.verify(&SigningKey::from_bytes(&[43u8; 32]).verifying_key()));
    }
}
