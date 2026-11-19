// The burst VMs: a node VM with local NVMe SSDs that lives for one export
// and is deleted. Its own stack ("csl-eth-burst"), one stage per burst, so
// each has its own state and deleting one never touches the other or the
// demo stack:
//
//	--stage export    deploy/gcp/full-export.sh: csl-eth-node, 4 SSDs (1.5 TB), 16 h
//	--stage history   deploy/gcp/history-export.sh: csl-eth-history,
//	                  $CSL_ETH_HISTORY_SSDS SSDs (default 24, 9 TB), 48 h
//
// The scripts make it with `bun run burst:up --stage <stage>` and delete it
// with `bun run burst:down --stage <stage>`; `bun run burst:plan --stage
// <stage>` shows what up would do. up runs with --force, so it creates the
// VM again when Compute Engine has deleted it at its deadline while the
// stage's state still lists it.
//
// It runs on the demo stack's network and subnet (infra/alchemy.run.ts),
// as the producer's service account (bucket writes only), with the "node"
// tag (devp2p firewall) and "producer" (SSH from IAP). Standard, not spot:
// a preemption hours into an export would waste it. Compute Engine deletes
// it at the deadline whatever happens to the script, so a lost laptop or a
// killed script cannot leave it running.
import * as GCP from "@alchemy.run/gcp";
import * as Alchemy from "alchemy";
import * as Effect from "effect/Effect";
import * as Custom from "./resources.ts";

const need = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`set ${k} in infra/.env`);
  return v;
};
const region = need("CSL_ETH_REGION");
const zone = process.env.CSL_ETH_ZONE || `${region}-b`;
const project = "csl-eth"; // as package.json pins it

const historySsds = Number(process.env.CSL_ETH_HISTORY_SSDS || 24);
const bursts: Record<string, { instanceName: string; localSsds: number; hours: number }> = {
  export: { instanceName: "csl-eth-node", localSsds: 4, hours: 16 },
  history: { instanceName: "csl-eth-history", localSsds: historySsds, hours: 48 },
};

// Runs as root on every boot: RAID 0 over the local SSDs at /data (they
// come up empty after any stop, so this formats them each time) and the
// build tools. The code and the burst itself are put there by the script.
const startup = `#!/bin/bash
set -euo pipefail
if ! mountpoint -q /data; then
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q mdadm build-essential clang libclang-dev pkg-config curl rsync git zstd
  devs=$(ls /dev/disk/by-id/google-local-nvme-ssd-* | sort)
  [ -e /dev/md0 ] || mdadm --create /dev/md0 --level=0 --raid-devices=$(echo "$devs" | wc -l) $devs --force --run
  mkfs.ext4 -q -F -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard /dev/md0
  mkdir -p /data && mount -o discard,noatime /dev/md0 /data && chmod 1777 /data
fi
`;

export default Alchemy.Stack(
  "csl-eth-burst",
  { providers: Custom.providers(), state: GCP.state() }, // GCP.providers() and ours
  Effect.gen(function* () {
    const stage = yield* Alchemy.Stage;
    const burst = bursts[stage];
    if (burst === undefined) {
      return yield* Effect.die(new Error(`no burst "${stage}": use --stage ${Object.keys(bursts).join(" or ")}`));
    }
    if (![1, 2, 4, 8, 16, 24].includes(burst.localSsds)) {
      // what n2-highmem-8 takes
      return yield* Effect.die(new Error(`n2-highmem-8 takes 1, 2, 4, 8, 16 or 24 local SSDs, not ${burst.localSsds}`));
    }
    const vm = yield* Custom.BurstInstance("node", {
      instanceName: burst.instanceName,
      zone,
      machineType: "n2-highmem-8",
      localSsds: burst.localSsds,
      sourceImage: "projects/debian-cloud/global/images/family/debian-13",
      bootDiskSizeGb: 50,
      bootDiskType: "pd-balanced",
      network: "global/networks/csl-eth",
      subnetwork: `regions/${region}/subnetworks/csl-eth`,
      serviceAccount: `csl-eth-producer@${project}.iam.gserviceaccount.com`,
      oauthScopes: ["https://www.googleapis.com/auth/devstorage.read_write"],
      tags: ["producer", "node"],
      metadata: { "enable-oslogin": "TRUE", "startup-script": startup },
      maxRunDurationSeconds: burst.hours * 3600,
    });
    return { vm: vm.instanceName, zone: vm.zone, publicIp: vm.natIP };
  }),
);
