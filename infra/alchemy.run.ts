// csl-eth on Google Cloud, everything the demo needs in one stack: a public
// bucket that holds both the browser page and the files it reads, and one
// small spot VM that runs the tracker (`csl-eth track`, keeping full/
// current) and writes to that bucket.
//
// The stack is "csl-eth" and this is its stage "demo", in the GCP project
// csl-eth (package.json pins it, whatever gcloud's default project is):
//
//	bun run plan       what would change
//	bun run deploy     make it so
//	bunx alchemy destroy --stage demo   remove what this stack made (the bucket only if empty)
//
// Then deploy/gcp/apply.sh builds and starts the tracker on the VM, and
// deploy/gcp/site.sh uploads the page.
//
// The page is served from the bucket itself, at
// https://storage.googleapis.com/<bucket>/index.html, so it reads the bucket
// from its own origin: no CORS, no web server, no second service. The
// bucket is the only thing readers touch, and they can only read it.
//
// The tracker needs no Ethereum node: it fetches each verified head's
// changed trie nodes over devp2p `snap` from mainnet peers, and keeps no
// copy of the 344 GiB base (it reads the base from the bucket by range
// after a gap). A full node is deliberately not here; it is a burst to add
// for a few days and destroy.
//
// Nothing on the VM listens to the internet except devp2p on TCP and UDP
// 30303.
// SSH comes only through Identity-Aware Proxy, which checks the caller's
// Google account:
//
//	gcloud compute ssh csl-eth-producer --zone <zone> --tunnel-through-iap
//
// The VM writes to the bucket as its own service account, whose only grant
// is object read/write on that bucket; no key exists anywhere.
import * as GCP from "@alchemy.run/gcp";
import * as Alchemy from "alchemy";
import * as Output from "alchemy/Output";
import * as Effect from "effect/Effect";

// Region and project number come from infra/.env (gitignored):
// CSL_ETH_REGION, CSL_ETH_PROJECT_NUMBER.
const need = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`set ${k} in infra/.env`);
  return v;
};
const region = need("CSL_ETH_REGION");
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
resize2fs -f "$disk" >/dev/null 2>&1 || true # after the disk was grown
if [ ! -f /data/swap ]; then
  fallocate -l 8G /data/swap && chmod 600 /data/swap && mkswap -q /data/swap
fi
swapon --show | grep -q /data/swap || swapon /data/swap
# Swap is for the release build. The tracker's node index must stay in
# memory: at the default swappiness the kernel swapped it out for page cache
# and a catch-up's materializing walk slowed to swap speed.
echo "vm.swappiness = 1" > /etc/sysctl.d/90-csl-eth.conf && sysctl -q vm.swappiness=1
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
    // discv4 for the old slice producer (UDP 30399); the tracker uses
    // 30303, opened below with the node's rule.
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
    // 200 GB (100 until 2026-11-17): the tracker's layers, the since-base layer twice while it
    // merges, the node log and sort spill of a catch-up (see
    // docs/delta-producer.md § Disk without the base). Grows in place
    // (the startup script grows the filesystem).
    const data = yield* GCP.Compute.Disk("data", {
      diskName: "csl-eth-producer-data",
      zone,
      type: "pd-balanced",
      sizeGb: 200,
    });
    const vm = yield* GCP.Compute.Instance("producer", {
      instanceName: "csl-eth-producer",
      zone,
      // 4 vCPUs, 16 GB (e2-medium until 2026-11-17: the background
      // since-base merge and the steps shared two vCPUs and slowed each
      // other). Resized in place by stop, set-machine-type, start; this
      // file only records it. Changing it here replaces the VM and keeps /data.
      machineType: "e2-standard-4",
      // Spot: a preemption stops the VM, and the schedule below starts it
      // again; the tracker then catches up from where track.json left it.
      provisioningModel: "SPOT",
      instanceTerminationAction: "STOP",
      bootDiskType: "pd-balanced",
      diskSizeGb: 30,
      network: netUrl,
      subnetwork: Output.interpolate`regions/${region}/subnetworks/${subnet.subnetworkName}`,
      associatePublicIp: true, // for mainnet peers and the beacon API; nothing listens but devp2p
      attachedDisks: [{ source: Output.interpolate`zones/${zone}/disks/${data.diskName}`, deviceName: "data" }],
      tags: ["producer", "node"],
      serviceAccount: producerSa.email,
      oauthScopes: ["https://www.googleapis.com/auth/devstorage.read_write"],
      metadata: { "enable-oslogin": "TRUE", "startup-script": startup },
      shieldedInstanceConfig: { enableSecureBoot: true, enableVtpm: true, enableIntegrityMonitoring: true },
    });

    // Start the VM every hour (a no-op while it runs; Compute Engine allows
    // nothing more frequent): a spot preemption leaves it stopped.
    // Compute Engine's service agent does the start, so it needs the right
    // to. The stack cannot attach the schedule to the instance, so that was
    // done by hand (2026-11-17):
    //   gcloud compute instances add-resource-policies csl-eth-producer \
    //     --zone <zone> --resource-policies csl-eth-restart
    // and again after anything replaces the VM.
    yield* GCP.Compute.ResourcePolicy("restart", {
      resourcePolicyName: "csl-eth-restart",
      region,
      description: "start the spot VM again after a preemption",
      instanceSchedulePolicy: { vmStartSchedule: { schedule: "0 * * * *" }, timeZone: "UTC" },
    });
    yield* GCP.IAM.Member("compute-agent-starts", {
      kind: "project",
      name: "csl-eth",
      role: "roles/compute.instanceAdmin.v1",
      member: `serviceAccount:service-${need("CSL_ETH_PROJECT_NUMBER")}@compute-system.iam.gserviceaccount.com`,
    });

    // The full-state node is not in this stack: it is a burst VM with
    // local NVMe SSDs (which Alchemy cannot attach, and which no quota here
    // limits), created and deleted by deploy/gcp/full-export.sh on this
    // network, with the producer's service account and the "node" tag. The
    // tracker on the producer VM carries the tag too: devp2p on 30303.
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
