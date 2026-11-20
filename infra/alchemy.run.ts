// csl-eth on Google Cloud: a public bucket that holds both the browser
// pages and the files they read. The demo is frozen (2026-11-20,
// docs/decisions.md): nothing writes to the bucket any more, and the tracker
// VM that kept full/ current is gone.
//
// The stack is "csl-eth" and this is its stage "demo", in the GCP project
// csl-eth (package.json pins it, whatever gcloud's default project is):
//
//	bun run plan       what would change
//	bun run deploy     make it so
//
// deploy/gcp/site.sh uploads the pages. They are served from the bucket
// itself, at https://storage.googleapis.com/<bucket>/index.html, so they
// read the bucket from their own origin: no CORS, no web server. The
// bucket is the only thing readers touch, and they can only read it.
//
// What @alchemy.run/gcp has no prop for (the bucket's soft delete) is done
// by the stack's own resources in ./resources.ts. The service account,
// network and firewall rules stay for the burst VMs of
// deploy/gcp/full-export.sh and history-export.sh, a second entrypoint,
// ./burst.run.ts. Their names ("producer") are from the retired producer;
// renaming them would replace them.
import * as GCP from "@alchemy.run/gcp";
import * as Alchemy from "alchemy";
import * as Output from "alchemy/Output";
import * as Effect from "effect/Effect";
import * as Custom from "./resources.ts";

// The region comes from infra/.env (gitignored): CSL_ETH_REGION.
const need = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`set ${k} in infra/.env`);
  return v;
};
const region = need("CSL_ETH_REGION");
const cidr = "10.30.0.0/24";
const iap = "35.235.240.0/20"; // the range IAP's TCP forwarding connects from
const bucketName = "csl-eth-demo"; // also in deploy/gcp/*: the publisher and the page upload

export default Alchemy.Stack(
  "csl-eth",
  { providers: Custom.providers(), state: GCP.state() }, // GCP.providers() and ours
  Effect.gen(function* () {
    // The bucket: page and data side by side (index.html, viz.html, dist/,
    // pkg/ beside head/, snapshots/, blobs/; no key collides). Readable by
    // anyone; uniform access, so no object carries its own ACL.
    const bucket = yield* GCP.Storage.Bucket("bucket", {
      bucketName,
      location: region.toUpperCase(),
      storageClass: "STANDARD",
      uniformBucketLevelAccess: true,
    });
    // Soft delete off (retention 0): merged-away delta layers would
    // otherwise stay billable for Google's default seven days. Everything in
    // the bucket can be rebuilt; a deleted object is gone at once.
    yield* Custom.BucketSoftDelete("bucket-no-soft-delete", {
      bucketName: bucket.bucketName,
      retentionDurationSeconds: 0,
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

    // The tracker VM, its data disk and its restart schedule were removed on
    // 2026-11-20, when the demo was frozen (docs/decisions.md). The service
    // account, network and firewall rules stay: the burst VMs use them.

    // The full-state node is not in this stack: it is a burst VM with
    // local NVMe SSDs, made and deleted by ./burst.run.ts (its own stages,
    // driven by deploy/gcp/full-export.sh and history-export.sh) on this
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
      network: net.networkName,
      subnet: subnet.subnetworkName,
      serviceAccount: producerSa.email,
    };
  }),
);
