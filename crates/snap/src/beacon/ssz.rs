//! Signed beacon blocks, Bellatrix to Fulu, decoded only to hash: the
//! producer computes each body field's root and the payload's, and from
//! them a block's proof of its execution `block_hash`. A block comes as
//! SSZ or as the beacon API's JSON (public nodes serve archived blocks in
//! JSON only); either way it is untrusted, and its proof must hash to the
//! block root the vector holds. Bellatrix blocks are decoded only to
//! verify the root a chunk opens on when Capella's first slots were
//! missed; no Bellatrix slot is ever given a record that proves it.

use alloy_primitives::{Address, FixedBytes, B256, U256 as Uint256};
use csl_eth_store::beacon::{
    branch_of, levels, BeaconHeader, BodyProof, BODY_EXECUTION_PAYLOAD, DENEB_SLOT, ELECTRA_SLOT,
    PAYLOAD_BLOCK_HASH,
};
use serde::{de::DeserializeOwned, Deserialize};
use ssz::Decode;
use ssz_derive::Decode;
use ssz_types::{
    serde_utils::{hex_fixed_vec, hex_var_list, list_of_hex_var_list, quoted_u64_var_list},
    typenum::{
        U1, U1048576, U1073741824, U128, U131072, U16, U2, U2048, U256, U32, U33, U4096, U512, U64,
        U8, U8192,
    },
    BitList, BitVector, FixedVector, VariableList,
};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

type Bytes20 = Address;
type Bytes32 = B256;
type Bytes48 = FixedBytes<48>;
type Bytes96 = FixedBytes<96>;

#[derive(Decode, TreeHash, Deserialize)]
struct Eth1Data {
    deposit_root: Bytes32,
    #[serde(with = "serde_utils::quoted_u64")]
    deposit_count: u64,
    block_hash: Bytes32,
}

#[derive(Decode, TreeHash, Deserialize)]
struct BlockHeader {
    #[serde(with = "serde_utils::quoted_u64")]
    slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    proposer_index: u64,
    parent_root: Bytes32,
    state_root: Bytes32,
    body_root: Bytes32,
}

#[derive(Decode, TreeHash, Deserialize)]
struct SignedBlockHeader {
    message: BlockHeader,
    signature: Bytes96,
}

#[derive(Decode, TreeHash, Deserialize)]
struct ProposerSlashing {
    signed_header_1: SignedBlockHeader,
    signed_header_2: SignedBlockHeader,
}

#[derive(Decode, TreeHash, Deserialize)]
struct Checkpoint {
    #[serde(with = "serde_utils::quoted_u64")]
    epoch: u64,
    root: Bytes32,
}

#[derive(Decode, TreeHash, Deserialize)]
struct AttestationData {
    #[serde(with = "serde_utils::quoted_u64")]
    slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    index: u64,
    beacon_block_root: Bytes32,
    source: Checkpoint,
    target: Checkpoint,
}

macro_rules! attestation_types {
    ($indexed:ident, $slashing:ident, $limit:ty) => {
        #[derive(Decode, TreeHash, Deserialize)]
        struct $indexed {
            #[serde(with = "quoted_u64_var_list")]
            attesting_indices: VariableList<u64, $limit>,
            data: AttestationData,
            signature: Bytes96,
        }

        #[derive(Decode, TreeHash, Deserialize)]
        struct $slashing {
            attestation_1: $indexed,
            attestation_2: $indexed,
        }
    };
}

// MAX_VALIDATORS_PER_COMMITTEE, and times MAX_COMMITTEES_PER_SLOT from
// Electra (EIP-7549).
attestation_types!(IndexedAttestation, AttesterSlashing, U2048);
attestation_types!(IndexedAttestationElectra, AttesterSlashingElectra, U131072);

#[derive(Decode, TreeHash, Deserialize)]
struct Attestation {
    aggregation_bits: BitList<U2048>,
    data: AttestationData,
    signature: Bytes96,
}

#[derive(Decode, TreeHash, Deserialize)]
struct AttestationElectra {
    aggregation_bits: BitList<U131072>,
    data: AttestationData,
    signature: Bytes96,
    committee_bits: BitVector<U64>,
}

#[derive(Decode, TreeHash, Deserialize)]
struct DepositData {
    pubkey: Bytes48,
    withdrawal_credentials: Bytes32,
    #[serde(with = "serde_utils::quoted_u64")]
    amount: u64,
    signature: Bytes96,
}

#[derive(Decode, TreeHash, Deserialize)]
struct Deposit {
    proof: FixedVector<Bytes32, U33>,
    data: DepositData,
}

#[derive(Decode, TreeHash, Deserialize)]
struct VoluntaryExit {
    #[serde(with = "serde_utils::quoted_u64")]
    epoch: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    validator_index: u64,
}

#[derive(Decode, TreeHash, Deserialize)]
struct SignedVoluntaryExit {
    message: VoluntaryExit,
    signature: Bytes96,
}

#[derive(Decode, TreeHash, Deserialize)]
struct SyncAggregate {
    sync_committee_bits: BitVector<U512>,
    sync_committee_signature: Bytes96,
}

#[derive(Decode, TreeHash, Deserialize)]
struct Withdrawal {
    #[serde(with = "serde_utils::quoted_u64")]
    index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    validator_index: u64,
    address: Bytes20,
    #[serde(with = "serde_utils::quoted_u64")]
    amount: u64,
}

type Transactions = VariableList<VariableList<u8, U1073741824>, U1048576>;

/// Bellatrix's 14 fields: Capella's without withdrawals. Decoded only to
/// verify a predecessor root (the last block before a chunk), never routed.
#[derive(Decode, Deserialize)]
struct PayloadBellatrix {
    parent_hash: Bytes32,
    fee_recipient: Bytes20,
    state_root: Bytes32,
    receipts_root: Bytes32,
    #[serde(with = "hex_fixed_vec")]
    logs_bloom: FixedVector<u8, U256>,
    prev_randao: Bytes32,
    #[serde(with = "serde_utils::quoted_u64")]
    block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    timestamp: u64,
    #[serde(with = "hex_var_list")]
    extra_data: VariableList<u8, U32>,
    #[serde(with = "serde_utils::quoted_u256")]
    base_fee_per_gas: Uint256,
    block_hash: Bytes32,
    #[serde(with = "list_of_hex_var_list")]
    transactions: Transactions,
}

/// Capella's 15 fields, then Deneb's two blob-gas fields.
#[derive(Decode, Deserialize)]
struct Payload {
    parent_hash: Bytes32,
    fee_recipient: Bytes20,
    state_root: Bytes32,
    receipts_root: Bytes32,
    #[serde(with = "hex_fixed_vec")]
    logs_bloom: FixedVector<u8, U256>,
    prev_randao: Bytes32,
    #[serde(with = "serde_utils::quoted_u64")]
    block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    timestamp: u64,
    #[serde(with = "hex_var_list")]
    extra_data: VariableList<u8, U32>,
    #[serde(with = "serde_utils::quoted_u256")]
    base_fee_per_gas: Uint256,
    block_hash: Bytes32,
    #[serde(with = "list_of_hex_var_list")]
    transactions: Transactions,
    withdrawals: VariableList<Withdrawal, U16>,
}

#[derive(Decode, Deserialize)]
struct PayloadDeneb {
    parent_hash: Bytes32,
    fee_recipient: Bytes20,
    state_root: Bytes32,
    receipts_root: Bytes32,
    #[serde(with = "hex_fixed_vec")]
    logs_bloom: FixedVector<u8, U256>,
    prev_randao: Bytes32,
    #[serde(with = "serde_utils::quoted_u64")]
    block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    timestamp: u64,
    #[serde(with = "hex_var_list")]
    extra_data: VariableList<u8, U32>,
    #[serde(with = "serde_utils::quoted_u256")]
    base_fee_per_gas: Uint256,
    block_hash: Bytes32,
    #[serde(with = "list_of_hex_var_list")]
    transactions: Transactions,
    withdrawals: VariableList<Withdrawal, U16>,
    #[serde(with = "serde_utils::quoted_u64")]
    blob_gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    excess_blob_gas: u64,
}

macro_rules! payload_fields {
    ($p:expr) => {
        vec![
            $p.parent_hash.tree_hash_root(),
            $p.fee_recipient.tree_hash_root(),
            $p.state_root.tree_hash_root(),
            $p.receipts_root.tree_hash_root(),
            $p.logs_bloom.tree_hash_root(),
            $p.prev_randao.tree_hash_root(),
            $p.block_number.tree_hash_root(),
            $p.gas_limit.tree_hash_root(),
            $p.gas_used.tree_hash_root(),
            $p.timestamp.tree_hash_root(),
            $p.extra_data.tree_hash_root(),
            $p.base_fee_per_gas.tree_hash_root(),
            $p.block_hash.tree_hash_root(),
            $p.transactions.tree_hash_root(),
        ]
    };
}

impl PayloadBellatrix {
    fn fields(&self) -> Vec<B256> {
        payload_fields!(self)
    }
}

impl Payload {
    fn fields(&self) -> Vec<B256> {
        let mut f = payload_fields!(self);
        f.push(self.withdrawals.tree_hash_root());
        f
    }
}

impl PayloadDeneb {
    fn fields(&self) -> Vec<B256> {
        let mut f = payload_fields!(self);
        f.push(self.withdrawals.tree_hash_root());
        f.push(self.blob_gas_used.tree_hash_root());
        f.push(self.excess_blob_gas.tree_hash_root());
        f
    }
}

#[derive(Decode, TreeHash, Deserialize)]
struct BlsToExecutionChange {
    #[serde(with = "serde_utils::quoted_u64")]
    validator_index: u64,
    from_bls_pubkey: Bytes48,
    to_execution_address: Bytes20,
}

#[derive(Decode, TreeHash, Deserialize)]
struct SignedBlsToExecutionChange {
    message: BlsToExecutionChange,
    signature: Bytes96,
}

#[derive(Decode, TreeHash, Deserialize)]
struct DepositRequest {
    pubkey: Bytes48,
    withdrawal_credentials: Bytes32,
    #[serde(with = "serde_utils::quoted_u64")]
    amount: u64,
    signature: Bytes96,
    #[serde(with = "serde_utils::quoted_u64")]
    index: u64,
}

#[derive(Decode, TreeHash, Deserialize)]
struct WithdrawalRequest {
    source_address: Bytes20,
    validator_pubkey: Bytes48,
    #[serde(with = "serde_utils::quoted_u64")]
    amount: u64,
}

#[derive(Decode, TreeHash, Deserialize)]
struct ConsolidationRequest {
    source_address: Bytes20,
    source_pubkey: Bytes48,
    target_pubkey: Bytes48,
}

#[derive(Decode, TreeHash, Deserialize)]
struct ExecutionRequests {
    deposits: VariableList<DepositRequest, U8192>,
    withdrawals: VariableList<WithdrawalRequest, U16>,
    consolidations: VariableList<ConsolidationRequest, U2>,
}

#[derive(Decode, Deserialize)]
struct BodyBellatrix {
    randao_reveal: Bytes96,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: VariableList<ProposerSlashing, U16>,
    attester_slashings: VariableList<AttesterSlashing, U2>,
    attestations: VariableList<Attestation, U128>,
    deposits: VariableList<Deposit, U16>,
    voluntary_exits: VariableList<SignedVoluntaryExit, U16>,
    sync_aggregate: SyncAggregate,
    execution_payload: PayloadBellatrix,
}

#[derive(Decode, Deserialize)]
struct BodyCapella {
    randao_reveal: Bytes96,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: VariableList<ProposerSlashing, U16>,
    attester_slashings: VariableList<AttesterSlashing, U2>,
    attestations: VariableList<Attestation, U128>,
    deposits: VariableList<Deposit, U16>,
    voluntary_exits: VariableList<SignedVoluntaryExit, U16>,
    sync_aggregate: SyncAggregate,
    execution_payload: Payload,
    bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, U16>,
}

#[derive(Decode, Deserialize)]
struct BodyDeneb {
    randao_reveal: Bytes96,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: VariableList<ProposerSlashing, U16>,
    attester_slashings: VariableList<AttesterSlashing, U2>,
    attestations: VariableList<Attestation, U128>,
    deposits: VariableList<Deposit, U16>,
    voluntary_exits: VariableList<SignedVoluntaryExit, U16>,
    sync_aggregate: SyncAggregate,
    execution_payload: PayloadDeneb,
    bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, U16>,
    blob_kzg_commitments: VariableList<Bytes48, U4096>,
}

/// Electra's body; Fulu's is the same.
#[derive(Decode, Deserialize)]
struct BodyElectra {
    randao_reveal: Bytes96,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: VariableList<ProposerSlashing, U16>,
    attester_slashings: VariableList<AttesterSlashingElectra, U1>,
    attestations: VariableList<AttestationElectra, U8>,
    deposits: VariableList<Deposit, U16>,
    voluntary_exits: VariableList<SignedVoluntaryExit, U16>,
    sync_aggregate: SyncAggregate,
    execution_payload: PayloadDeneb,
    bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, U16>,
    blob_kzg_commitments: VariableList<Bytes48, U4096>,
    execution_requests: ExecutionRequests,
}

macro_rules! body_head {
    ($b:expr) => {
        vec![
            $b.randao_reveal.tree_hash_root(),
            $b.eth1_data.tree_hash_root(),
            $b.graffiti.tree_hash_root(),
            $b.proposer_slashings.tree_hash_root(),
            $b.attester_slashings.tree_hash_root(),
            $b.attestations.tree_hash_root(),
            $b.deposits.tree_hash_root(),
            $b.voluntary_exits.tree_hash_root(),
            $b.sync_aggregate.tree_hash_root(),
        ]
    };
}

/// A body's field roots and its payload's, and the block hash.
struct Fields {
    body: Vec<B256>,
    payload: Vec<B256>,
    block_hash: B256,
}

trait Body: Decode + DeserializeOwned {
    fn fields(&self) -> Fields;
}

impl Body for BodyBellatrix {
    fn fields(&self) -> Fields {
        let payload = self.execution_payload.fields();
        let mut body = body_head!(self);
        body.push(B256::ZERO);
        Fields {
            body,
            payload,
            block_hash: self.execution_payload.block_hash,
        }
    }
}

impl Body for BodyCapella {
    fn fields(&self) -> Fields {
        let payload = self.execution_payload.fields();
        let mut body = body_head!(self);
        body.push(B256::ZERO);
        body.push(self.bls_to_execution_changes.tree_hash_root());
        Fields {
            body,
            payload,
            block_hash: self.execution_payload.block_hash,
        }
    }
}

impl Body for BodyDeneb {
    fn fields(&self) -> Fields {
        let payload = self.execution_payload.fields();
        let mut body = body_head!(self);
        body.push(B256::ZERO);
        body.push(self.bls_to_execution_changes.tree_hash_root());
        body.push(self.blob_kzg_commitments.tree_hash_root());
        Fields {
            body,
            payload,
            block_hash: self.execution_payload.block_hash,
        }
    }
}

impl Body for BodyElectra {
    fn fields(&self) -> Fields {
        let payload = self.execution_payload.fields();
        let mut body = body_head!(self);
        body.push(B256::ZERO);
        body.push(self.bls_to_execution_changes.tree_hash_root());
        body.push(self.blob_kzg_commitments.tree_hash_root());
        body.push(self.execution_requests.tree_hash_root());
        Fields {
            body,
            payload,
            block_hash: self.execution_payload.block_hash,
        }
    }
}

#[derive(Decode, Deserialize)]
#[serde(bound = "B: DeserializeOwned")]
struct Block<B: Body> {
    #[serde(with = "serde_utils::quoted_u64")]
    slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    proposer_index: u64,
    parent_root: Bytes32,
    state_root: Bytes32,
    body: B,
}

#[derive(Decode, Deserialize)]
#[serde(bound = "B: DeserializeOwned")]
struct Signed<B: Body> {
    message: Block<B>,
    #[allow(dead_code)]
    signature: Bytes96,
}

fn pad(mut v: Vec<B256>) -> Vec<B256> {
    v.resize(v.len().next_power_of_two(), B256::ZERO);
    v
}

fn prove<B: Body>(s: &Signed<B>) -> Result<BodyProof, String> {
    let m = &s.message;
    let mut f = m.body.fields();
    // The execution payload's own root, in its slot among the body's.
    let payload_tree = levels(pad(f.payload.clone()));
    f.body[BODY_EXECUTION_PAYLOAD as usize] = payload_tree.last().expect("root")[0];
    let body_tree = levels(pad(f.body));
    let header = BeaconHeader {
        slot: m.slot,
        proposer_index: m.proposer_index,
        parent_root: m.parent_root,
        state_root: m.state_root,
        body_root: body_tree.last().expect("root")[0],
    };
    let body: Vec<B256> = branch_of(&body_tree, BODY_EXECUTION_PAYLOAD as usize);
    let p = BodyProof {
        slot: m.slot,
        block_root: header.root(),
        block_hash: f.block_hash,
        payload: branch_of(&payload_tree, PAYLOAD_BLOCK_HASH as usize),
        body: body.try_into().map_err(|_| "body depth")?,
        header: header.body_branch(),
    };
    debug_assert_eq!(p.root(), p.block_root);
    Ok(p)
}

/// The slot of an SSZ `SignedBeaconBlock`: the message's first field.
pub fn slot_of(bytes: &[u8]) -> Option<u64> {
    let off = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    Some(u64::from_le_bytes(
        bytes.get(off..off + 8)?.try_into().ok()?,
    ))
}

/// Bellatrix's first slot (epoch 144,896): the first blocks with an
/// execution payload.
pub const BELLATRIX_SLOT: u64 = 144_896 * 32;

/// The fork a slot's block has (from its slot alone: a block that claims
/// another fork's shape will not hash to its root). Bellatrix blocks are
/// decoded only as predecessors (the root an early chunk opens on); the
/// route itself starts at Capella.
fn fork(slot: u64) -> Result<&'static str, String> {
    if slot < BELLATRIX_SLOT {
        Err(format!(
            "slot {slot} is before Bellatrix: no execution payload"
        ))
    } else if slot < csl_eth_store::beacon::CAPELLA_SLOT {
        Ok("bellatrix")
    } else if slot < DENEB_SLOT {
        Ok("capella")
    } else if slot < ELECTRA_SLOT {
        Ok("deneb")
    } else {
        Ok("electra")
    }
}

/// The body proof of an SSZ `SignedBeaconBlock` (Bellatrix to Fulu), its
/// root computed from its bytes. The caller compares the root with the one
/// it trusts.
pub fn body_proof(bytes: &[u8]) -> Result<BodyProof, String> {
    fn de<B: Body>(b: &[u8]) -> Result<BodyProof, String> {
        prove(&Signed::<B>::from_ssz_bytes(b).map_err(|e| format!("ssz: {e:?}"))?)
    }
    match fork(slot_of(bytes).ok_or("not a signed block")?)? {
        "bellatrix" => de::<BodyBellatrix>(bytes),
        "capella" => de::<BodyCapella>(bytes),
        "deneb" => de::<BodyDeneb>(bytes),
        _ => de::<BodyElectra>(bytes),
    }
}

/// The same from the beacon API's JSON (`/eth/v2/beacon/blocks/{id}`).
pub fn body_proof_json(bytes: &[u8]) -> Result<BodyProof, String> {
    fn de<B: Body>(v: serde_json::Value) -> Result<BodyProof, String> {
        prove(&serde_json::from_value::<Signed<B>>(v).map_err(|e| format!("json: {e}"))?)
    }
    let mut v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let slot = v["data"]["message"]["slot"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or("no slot")?;
    let data = v["data"].take();
    match fork(slot)? {
        "bellatrix" => de::<BodyBellatrix>(data),
        "capella" => de::<BodyCapella>(data),
        "deneb" => de::<BodyDeneb>(data),
        _ => de::<BodyElectra>(data),
    }
}

/// Either form: SSZ unless it parses as JSON.
pub fn body_proof_any(bytes: &[u8]) -> Result<BodyProof, String> {
    if bytes.first() == Some(&b'{') {
        body_proof_json(bytes)
    } else {
        body_proof(bytes)
    }
}

#[cfg(test)]
mod tests {
    /// One block in both forms (`CSL_BLOCK_DIR` holding `b.ssz`, `b.json`
    /// and `root.txt`): the same proof, hashing to the root.
    #[test]
    #[ignore = "needs a fetched block"]
    fn ssz_and_json_agree() {
        let dir = std::env::var("CSL_BLOCK_DIR").unwrap();
        let read = |n: &str| std::fs::read(format!("{dir}/{n}")).unwrap();
        let root: alloy_primitives::B256 = String::from_utf8(read("root.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let a = super::body_proof(&read("b.ssz")).unwrap();
        let b = super::body_proof_json(&read("b.json")).unwrap();
        assert_eq!(a.block_root, root);
        assert_eq!(b.block_root, root);
        assert_eq!(a.root(), root);
        assert_eq!(
            (a.slot, a.block_hash, &a.payload, a.body, a.header),
            (b.slot, b.block_hash, &b.payload, b.body, b.header)
        );
    }
}
