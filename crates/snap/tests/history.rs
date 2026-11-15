//! The history fault table over a synthetic chain in a producer's block
//! cache: every fault fires, and no read is wrong.

use csl_eth_snap::history::{block_path, faults};
use csl_eth_store::{
    history::{synthetic, MAINNET_GENESIS_TIME},
    producer::write_atomic,
    EPSILON,
};

#[test]
fn the_fault_table_passes_over_a_synthetic_cache() {
    let work = std::env::temp_dir().join(format!("csl-eth-history-faults-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let c = synthetic::chain(11, 5000, 64, MAINNET_GENESIS_TIME + 12 * 8192 * 1900);
    for b in c.values() {
        write_atomic(&block_path(&work, b.number), &b.encode()).unwrap();
    }
    let top = c.values().last().unwrap();
    let r = faults::run(&work, &work.join("faults"), (top.number, top.hash), 64, EPSILON).unwrap();
    for row in &r.rows {
        assert!(row.pass, "{row:?}");
    }
    assert!(r.pass);
}
