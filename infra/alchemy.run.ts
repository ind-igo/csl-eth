// csl-eth on Google Cloud, everything the demo needs in one stack: a public
// bucket that holds both the browser page and the files it reads, and one
// small VM that runs the producer loop and writes to that bucket.
//
// The stack is "csl-eth" and this is its stage "demo", in the GCP project
// csl-eth (package.json pins it, whatever gcloud's default project is):
//
//	bun run plan       what would change
//	bun run deploy     make it so
//	bunx alchemy destroy --stage demo   remove what this stack made (the bucket only if empty)
//
// Then deploy/gcp/apply.sh builds and starts the producer on the VM, and
// deploy/gcp/site.sh uploads the page.
//
// The page is served from the bucket itself, at
// https://storage.googleapis.com/<bucket>/index.html, so it reads the bucket
// from its own origin: no CORS, no web server, no second service. The
// bucket is the only thing readers touch, and they can only read it.
//
// The producer needs no Ethereum node: it fetches the 1/4096 slice over
// devp2p `snap` from mainnet peers each epoch, as it did on fafo-0. A full
// node for full-state measurements is deliberately not here; it is a burst
// to add for a few days and destroy (poc-ethereum milestone 4).
//
// Nothing on the VM listens to the internet except discv4 on UDP 30399.
// SSH comes only through Identity-Aware Proxy, which checks the caller's
// Google account:
//
//	gcloud compute ssh csl-eth-producer --zone asia-east1-b --tunnel-through-iap
//
// The VM writes to the bucket as its own service account, whose only grant
// is object read/write on that bucket; no key exists anywhere. The optional
// FCR RPC URL (it may carry an API key) is written on the VM by hand into
// /etc/csl-eth/fcr.env and never passes through this file or Alchemy's state.
import * as GCP from "@alchemy.run/gcp";
import * as Alchemy from "alchemy";
import * as Output from "alchemy/Output";
import * as Effect from "effect/Effect";

const region = "asia-east1"; // Taiwan
const zone = `${region}-b`;
const cidr = "10.30.0.0/24";
const iap = "35.235.240.0/20"; // the range IAP's TCP forwarding connects from
const bucketName = "csl-eth-demo"; // also in deploy/gcp/*: the publisher and the page upload

// Runs as root on every boot. It only prepares the machine: the data disk
// at /data (the producer's work directory, so it outlives the VM), swap for
// the release build, the build tools, and the user the producer runs as.
// The code, the binary and the service are put there by deploy/gcp/apply.sh.
const startup = `#!/bin/bash
set -euo pipefail
disk=/dev/disk/by-id/google-data
if ! blkid "$disk" >/dev/null; then
  mkfs.ext4 -q -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard "$disk"
fi
mkdir -p /data
grep -q "$disk" /etc/fstab || echo "$disk /data ext4 discard,defaults,nofail 0 2" >> /etc/fstab
mountpoint -q /data || mount /data
if [ ! -f /data/swap ]; then
  fallocate -l 8G /data/swap && chmod 600 /data/swap && mkswap -q /data/swap
fi
swapon --show | grep -q /data/swap || swapon /data/swap
id csl >/dev/null 2>&1 || useradd --system --home-dir /data/home --create-home --shell /usr/sbin/nologin csl
mkdir -p /data/produce /opt/csl-eth /etc/csl-eth
chown csl:csl /data/produce
if ! command -v cc >/dev/null || ! command -v rsync >/dev/null; then
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential clang libclang-dev pkg-config curl rsync git zstd
fi
`;

export default Alchemy.Stack(
  "csl-eth",
  { providers: GCP.providers(), state: GCP.state() },
  Effect.gen(function* () {
    // The bucket: page and data side by side (index.html, viz.html, dist/,
    // pkg/ beside head/, snapshots/, blobs/; no key collides). Readable by
    // anyone; uniform access, so no object carries its own ACL.
    // Soft delete is off (retention 0), set by hand since this resource has
    // no prop for it: `gcloud storage buckets update gs://csl-eth-demo
    // --clear-soft-delete` (2026-11-16). Merged-away delta layers would
    // otherwise stay billable for Google's default seven days. Everything in
    // the bucket can be rebuilt; a deleted object is gone at once.
    const bucket = yield* GCP.Storage.Bucket("bucket", {
      bucketName,
      location: region.toUpperCase(),
      storageClass: "STANDARD",
      uniformBucketLevelAccess: true,
    });
    yield* GCP.IAM.Member("public-read", {
      kind: "storage.bucket",
      name: bucket.bucketName,
      role: "roles/storage.objectViewer",
      member: "allUsers",
    });

    // The producer's identity: object read/write on the bucket and nothing else.
    const producerSa = yield* GCP.IAM.ServiceAccount("producer-sa", {
      accountId: "csl-eth-producer",
      displayName: "csl-eth producer (bucket writes only)",
    });
    yield* GCP.IAM.Member("producer-writes", {
      kind: "storage.bucket",
      name: bucket.bucketName,
      role: "roles/storage.objectUser",
      member: Output.interpolate`serviceAccount:${producerSa.email}`,
    });

    // Its own network, so the default network's open SSH rule doesn't apply.
    const net = yield* GCP.Compute.Network("net", {
      networkName: "csl-eth",
      autoCreateSubnetworks: false,
    });
    const netUrl = Output.interpolate`global/networks/${net.networkName}`;
    const subnet = yield* GCP.Compute.Subnetwork("subnet", {
      subnetworkName: "csl-eth",
      region,
      network: netUrl,
      ipCidrRange: cidr,
    });
    yield* GCP.Compute.Firewall("ssh-from-iap", {
      firewallName: "csl-eth-ssh-from-iap",
      network: netUrl,
      allowed: [{ protocol: "tcp", ports: ["22"] }],
      sourceRanges: [iap],
      targetTags: ["producer"],
    });
    // discv4: the fetcher finds mainnet peers over UDP 30399. Replies to its
    // own pings would pass the stateful firewall anyway; peers that ping
    // first need this, as they reached fafo-0's host network.
    yield* GCP.Compute.Firewall("discv4", {
      firewallName: "csl-eth-discv4",
      network: netUrl,
      allowed: [{ protocol: "udp", ports: ["30399"] }],
      sourceRanges: ["0.0.0.0/0"],
      targetTags: ["producer"],
    });

    // The work directory: slices, the local mirror of the bucket, state.json
    // (what is published, which pointer write is pending). On its own disk so
    // replacing the VM keeps it: a lost state.json leaves old snapshots in the
    // bucket that nothing will ever collect.
    const data = yield* GCP.Compute.Disk("data", {
      diskName: "csl-eth-producer-data",
      zone,
      type: "pd-balanced",
      sizeGb: 30,
    });
    const vm = yield* GCP.Compute.Instance("producer", {
      instanceName: "csl-eth-producer",
      zone,
      // 2 vCPUs, 4 GB: the loop uses well under 1 GB between bursts (it was
      // limited to 3 GB on fafo-0); the release build is the peak, helped by
      // 8 GB of swap on /data. Changing it replaces the VM and keeps /data.
      machineType: "e2-medium",
      bootDiskType: "pd-balanced",
      diskSizeGb: 30,
      network: netUrl,
      subnetwork: Output.interpolate`regions/${region}/subnetworks/${subnet.subnetworkName}`,
      associatePublicIp: true, // for mainnet peers and the beacon API; nothing listens but discv4
      attachedDisks: [{ source: Output.interpolate`zones/${zone}/disks/${data.diskName}`, deviceName: "data" }],
      tags: ["producer"],
      serviceAccount: producerSa.email,
      oauthScopes: ["https://www.googleapis.com/auth/devstorage.read_write"],
      metadata: { "enable-oslogin": "TRUE", "startup-script": startup },
      shieldedInstanceConfig: { enableSecureBoot: true, enableVtpm: true, enableIntegrityMonitoring: true },
    });

    // The full-state node is not in this stack: it is a burst VM with
    // local NVMe SSDs (which Alchemy cannot attach, and which no quota here
    // limits), created and deleted by deploy/gcp/full-export.sh on this
    // network, with the producer's service account and the "node" tag.
    yield* GCP.Compute.Firewall("devp2p", {
      firewallName: "csl-eth-devp2p",
      network: netUrl,
      allowed: [{ protocol: "tcp", ports: ["30303"] }, { protocol: "udp", ports: ["30303"] }],
      sourceRanges: ["0.0.0.0/0"],
      targetTags: ["node"],
    });
    return {
      bucket: bucket.bucketName,
      page: Output.interpolate`https://storage.googleapis.com/${bucket.bucketName}/index.html?open`,
      vm: vm.instanceName,
      zone: vm.zone,
      publicIp: vm.natIP,
      network: net.networkName,
      subnet: subnet.subnetworkName,
      serviceAccount: producerSa.email,
    };
  }),
);
