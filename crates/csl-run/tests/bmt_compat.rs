//! The run root and inline proofs must be exactly what `commonware-storage::bmt`
//! computes and accepts, so a Commonware chain verifies pages with code it
//! already ships.

use commonware_cryptography::blake3::{Blake3, Digest};
use commonware_storage::bmt::{Builder, Proof};
use csl_run::tree::{depth, Tree, DIGEST_LEN_CHECK};

#[test]
fn roots_and_proofs_match_commonware_bmt() {
    let _ = DIGEST_LEN_CHECK;
    for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 33, 100, 257] {
        let digests: Vec<[u8; 32]> = (0..n).map(|i| *blake3::hash(&(i as u64).to_le_bytes()).as_bytes()).collect();
        let ours = Tree::build(&digests);

        let mut b = Builder::<Blake3>::new(n);
        for d in &digests {
            b.add(&Digest(*d));
        }
        let theirs = b.build();
        assert_eq!(ours.root(), theirs.root().0, "root differs at n = {n}");

        for (i, d) in digests.iter().enumerate() {
            // Their proof, our verifier.
            let p = theirs.proof(i as u32).unwrap();
            let their_siblings: Vec<[u8; 32]> = p.siblings.iter().map(|d| d.0).collect();
            assert_eq!(ours.proof(i as u32), their_siblings, "siblings differ n = {n} i = {i}");

            // Our inline proof region, their verifier.
            let inline = ours.inline_proof(i as u32);
            assert_eq!(inline.len(), 32 * depth(n as u64));
            let used = their_siblings.len();
            let proof = Proof::<Digest> { leaf_count: n as u32, siblings: inline[..32 * used].chunks(32).map(|c| Digest(c.try_into().unwrap())).collect() };
            proof
                .verify_element_inclusion::<Blake3>(&Digest(*d), i as u32, &Digest(ours.root()))
                .unwrap_or_else(|e| panic!("commonware rejected our proof n = {n} i = {i}: {e}"));
            assert!(inline[32 * used..].iter().all(|&b| b == 0), "padding not zero");
        }
    }
}
