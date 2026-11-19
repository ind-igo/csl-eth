// csl-eth's own Alchemy resources, for what @alchemy.run/gcp's resources
// cannot say: a resource policy attached to an instance, a bucket's soft
// delete retention, and a burst VM with local NVMe SSDs. Each calls the
// Compute or Storage API through the same distilled clients the provider
// uses, so they share its credentials and project (package.json pins it).
//
// `providers()` is the stack's providers layer: these three beside
// GCP.providers().
import * as GCP from "@alchemy.run/gcp";
import * as compute from "@distilled.cloud/gcp/compute_v1";
import * as storage from "@distilled.cloud/gcp/storage_v1";
import { unownedUnlessPrevious } from "alchemy/AdoptPolicy";
import { deepEqual, isResolved } from "alchemy/Diff";
import * as Provider from "alchemy/Provider";
import { Resource } from "alchemy/Resource";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schedule from "effect/Schedule";

const lastSegment = (value: string | undefined) => value?.split("/").pop() ?? "";
const regionOf = (zone: string) => zone.replace(/-[a-z]$/, "");

export class ZoneOperationFailed extends Data.TaggedError("CslEth.ZoneOperationFailed")<{
  operation: string;
  code: string;
  message: string;
}> {}

export class InstanceMissing extends Data.TaggedError("CslEth.InstanceMissing")<{
  instanceName: string;
  zone: string;
}> {}

export class BucketMissing extends Data.TaggedError("CslEth.BucketMissing")<{
  bucketName: string;
}> {}

// Poll a zonal operation until it is done; fail with its first error, unless
// that error's code is one the caller says means "already so".
const waitZoneOperation = (
  project: string,
  zone: string,
  op: compute.Operation,
  ignore: string[] = [],
) =>
  Effect.gen(function* () {
    let current = op;
    while (current.status !== "DONE") {
      yield* Effect.sleep("2 seconds");
      current = yield* compute.getZoneOperations({ project, zone, operation: current.name ?? "" }).pipe(
        // a freshly started operation can 404 for a moment
        Effect.retry({ while: (e) => e._tag === "NotFound", times: 5, schedule: Schedule.exponential("250 millis") }),
      );
    }
    const error = current.error?.errors?.[0];
    if (error !== undefined && !ignore.includes(error.code ?? "")) {
      return yield* new ZoneOperationFailed({
        operation: current.name ?? "",
        code: error.code ?? "",
        message: error.message ?? "operation failed",
      });
    }
    return current;
  });

const getInstance = (project: string, zone: string, instance: string) =>
  compute.getInstances({ project, zone, instance }).pipe(Effect.catchTag("NotFound", () => Effect.undefined));

// ---------------------------------------------------------------------------
// Resource policies attached to an instance.

export type InstanceResourcePoliciesProps = {
  /** The instance, by name. Changing it (or the zone) moves the attachment. */
  instanceName: string;
  zone: string;
  /** Regional resource policies (names) in the instance's region. */
  resourcePolicies: string[];
  /**
   * The instance's numeric id. Not used in any call: it changes when the
   * instance is replaced under the same name, which re-runs reconcile, so
   * the new instance gets the policies too.
   */
  instanceId?: string;
};

export type InstanceResourcePolicies = Resource<
  "CslEth.Compute.InstanceResourcePolicies",
  InstanceResourcePoliciesProps,
  {
    instanceName: string;
    zone: string;
    instanceId: string;
    /** The managed policies, by name. */
    resourcePolicies: string[];
    /** Everything attached to the instance, by name, managed or not. */
    attached: string[];
  }
>;

/**
 * Attaches named resource policies to an instance (`instances.addResourcePolicies`),
 * which the provider's Instance has no prop for. Reconcile reads the
 * instance first and only adds the policies it lacks, so re-running it, or
 * adopting an attachment made by hand, changes nothing. It removes only
 * policies it managed before and no longer lists; others on the instance
 * are left alone. Neither call stops or restarts the VM. Delete detaches
 * the managed policies (a missing instance is fine).
 */
export const InstanceResourcePolicies = Resource<InstanceResourcePolicies>(
  "CslEth.Compute.InstanceResourcePolicies",
);

const attachedNames = (instance: compute.Instance, region: string) =>
  (instance.resourcePolicies ?? [])
    .filter((url) => url.includes(`/regions/${region}/`))
    .map(lastSegment);

const policyUrl = (project: string, region: string, name: string) =>
  `https://www.googleapis.com/compute/v1/projects/${project}/regions/${region}/resourcePolicies/${name}`;

const attachmentAttrs = (instance: compute.Instance, props: InstanceResourcePoliciesProps) => ({
  instanceName: props.instanceName,
  zone: props.zone,
  instanceId: instance.id ?? "",
  resourcePolicies: [...props.resourcePolicies],
  attached: attachedNames(instance, regionOf(props.zone)),
});

export const InstanceResourcePoliciesProvider = () =>
  Provider.succeed(InstanceResourcePolicies, {
    stables: ["instanceName", "zone"],

    diff: Effect.fn(function* ({ news, olds }) {
      if (!isResolved(news) || olds === undefined) return undefined;
      if (news.instanceName !== olds.instanceName || news.zone !== olds.zone) {
        return { action: "replace" as const, deleteFirst: false };
      }
      return undefined; // policies or instanceId changed: update; else noop
    }),

    // Present when the instance is: what is attached is in `attached`, and
    // reconcile adds what is missing.
    read: Effect.fn(function* ({ olds, output }) {
      const props = output ?? olds;
      if (props === undefined) return undefined;
      const env = yield* GCP.GcpEnvironment.current;
      const instance = yield* getInstance(env.project, props.zone, props.instanceName);
      return instance === undefined ? undefined : attachmentAttrs(instance, props);
    }),

    reconcile: Effect.fn(function* ({ news, olds }) {
      const env = yield* GCP.GcpEnvironment.current;
      const { instanceName, zone } = news;
      const region = regionOf(zone);
      const instance = yield* getInstance(env.project, zone, instanceName);
      if (instance === undefined) return yield* new InstanceMissing({ instanceName, zone });
      const attached = new Set(attachedNames(instance, region));
      const remove = (olds?.resourcePolicies ?? []).filter(
        (name) => attached.has(name) && !news.resourcePolicies.includes(name),
      );
      const add = news.resourcePolicies.filter((name) => !attached.has(name));
      if (remove.length > 0) {
        const op = yield* compute.removeResourcePoliciesInstances({
          project: env.project,
          zone,
          instance: instanceName,
          body: { resourcePolicies: remove.map((name) => policyUrl(env.project, region, name)) },
        });
        yield* waitZoneOperation(env.project, zone, op);
      }
      if (add.length > 0) {
        const op = yield* compute.addResourcePoliciesInstances({
          project: env.project,
          zone,
          instance: instanceName,
          body: { resourcePolicies: add.map((name) => policyUrl(env.project, region, name)) },
        });
        yield* waitZoneOperation(env.project, zone, op);
      }
      const after =
        remove.length + add.length > 0 ? yield* getInstance(env.project, zone, instanceName) : instance;
      if (after === undefined) return yield* new InstanceMissing({ instanceName, zone });
      return attachmentAttrs(after, news);
    }),

    delete: Effect.fn(function* ({ output }) {
      const env = yield* GCP.GcpEnvironment.current;
      const region = regionOf(output.zone);
      const instance = yield* getInstance(env.project, output.zone, output.instanceName);
      if (instance === undefined) return;
      const attached = new Set(attachedNames(instance, region));
      const remove = output.resourcePolicies.filter((name) => attached.has(name));
      if (remove.length === 0) return;
      const op = yield* compute
        .removeResourcePoliciesInstances({
          project: env.project,
          zone: output.zone,
          instance: output.instanceName,
          body: { resourcePolicies: remove.map((name) => policyUrl(env.project, region, name)) },
        })
        .pipe(Effect.catchTag("NotFound", () => Effect.undefined));
      if (op !== undefined) yield* waitZoneOperation(env.project, output.zone, op, ["RESOURCE_NOT_FOUND"]);
    }),
  });

// ---------------------------------------------------------------------------
// A bucket's soft delete retention.

export type BucketSoftDeleteProps = {
  bucketName: string;
  /** How long deleted objects stay restorable (and billable); 0 turns soft delete off. */
  retentionDurationSeconds: number;
};

export type BucketSoftDelete = Resource<
  "CslEth.Storage.BucketSoftDelete",
  BucketSoftDeleteProps,
  BucketSoftDeleteProps
>;

/**
 * Sets `softDeletePolicy.retentionDurationSeconds` on a bucket the stack
 * already has (what `gcloud storage buckets update --clear-soft-delete`
 * does for 0), which the provider's Bucket has no prop for. Reconcile reads
 * the bucket and patches only that one field, only when it differs; the
 * provider's own patches never send it, so the two do not fight. Delete
 * does nothing: dropping this resource leaves the bucket's retention as it
 * is (deleting the bucket deletes it all anyway).
 */
export const BucketSoftDelete = Resource<BucketSoftDelete>("CslEth.Storage.BucketSoftDelete");

const getBucket = (bucket: string) =>
  storage.getBuckets({ bucket }).pipe(Effect.catchTag("NotFound", () => Effect.undefined));

const retentionOf = (bucket: storage.Bucket) =>
  Number(bucket.softDeletePolicy?.retentionDurationSeconds ?? 0);

export const BucketSoftDeleteProvider = () =>
  Provider.succeed(BucketSoftDelete, {
    stables: ["bucketName"],

    diff: Effect.fn(function* ({ news, olds }) {
      if (!isResolved(news) || olds === undefined) return undefined;
      return news.bucketName !== olds.bucketName
        ? { action: "replace" as const, deleteFirst: false }
        : undefined;
    }),

    read: Effect.fn(function* ({ olds, output }) {
      const bucketName = (output ?? olds)?.bucketName;
      if (bucketName === undefined) return undefined;
      const bucket = yield* getBucket(bucketName);
      return bucket === undefined
        ? undefined
        : { bucketName, retentionDurationSeconds: retentionOf(bucket) };
    }),

    reconcile: Effect.fn(function* ({ news }) {
      const { bucketName, retentionDurationSeconds } = news;
      const bucket = yield* getBucket(bucketName);
      if (bucket === undefined) return yield* new BucketMissing({ bucketName });
      if (retentionOf(bucket) === retentionDurationSeconds) return { ...news };
      const patched = yield* storage.patchBuckets({
        bucket: bucketName,
        body: { softDeletePolicy: { retentionDurationSeconds: String(retentionDurationSeconds) } },
      });
      return { bucketName, retentionDurationSeconds: retentionOf(patched) };
    }),

    delete: () => Effect.void,
  });

// ---------------------------------------------------------------------------
// A burst VM with local NVMe SSDs.

export type BurstInstanceProps = {
  instanceName: string;
  zone: string;
  machineType: string;
  /** Local NVMe SSDs (375 GB each); the machine type limits the count. */
  localSsds: number;
  /** Boot disk image, e.g. `projects/debian-cloud/global/images/family/debian-13`. */
  sourceImage: string;
  bootDiskSizeGb: number;
  bootDiskType: string;
  network: string;
  subnetwork: string;
  serviceAccount: string;
  oauthScopes: string[];
  tags: string[];
  metadata: Record<string, string>;
  /** Compute Engine deletes the VM after this long, whatever else happens. */
  maxRunDurationSeconds: number;
};

export type BurstInstance = Resource<
  "CslEth.Compute.BurstInstance",
  BurstInstanceProps,
  {
    instanceName: string;
    zone: string;
    instanceId: string;
    status: string | undefined;
    natIP: string | undefined;
  }
>;

/**
 * A standard (not spot) VM with local NVMe SSDs and a maximum run duration
 * after which Compute Engine deletes it, which the provider's Instance
 * cannot express (it attaches persistent disks only). Every prop is fixed
 * at create: any change replaces the VM, and reconcile never changes a
 * running one; it creates the VM if it is missing (also after Compute
 * Engine deleted it at its deadline) and otherwise only reads it. It
 * carries Alchemy's ownership labels; one without them is not adopted
 * unless asked (`--adopt`). Delete deletes it; already gone is fine.
 */
export const BurstInstance = Resource<BurstInstance>("CslEth.Compute.BurstInstance");

const burstAttrs = (instance: compute.Instance, zone: string) => ({
  instanceName: instance.name ?? "",
  zone,
  instanceId: instance.id ?? "",
  status: instance.status,
  natIP: instance.networkInterfaces?.[0]?.accessConfigs?.[0]?.natIP,
});

const burstBody = (p: BurstInstanceProps, labels: Record<string, string>): compute.Instance => ({
  name: p.instanceName,
  machineType: `zones/${p.zone}/machineTypes/${p.machineType}`,
  labels,
  tags: { items: p.tags },
  metadata: { items: Object.entries(p.metadata).map(([key, value]) => ({ key, value })) },
  serviceAccounts: [{ email: p.serviceAccount, scopes: p.oauthScopes }],
  shieldedInstanceConfig: { enableSecureBoot: true, enableVtpm: true, enableIntegrityMonitoring: true },
  scheduling: {
    provisioningModel: "STANDARD",
    maxRunDuration: { seconds: String(p.maxRunDurationSeconds) },
    instanceTerminationAction: "DELETE",
  },
  disks: [
    {
      boot: true,
      autoDelete: true,
      type: "PERSISTENT",
      initializeParams: {
        sourceImage: p.sourceImage,
        diskSizeGb: String(p.bootDiskSizeGb),
        diskType: `zones/${p.zone}/diskTypes/${p.bootDiskType}`,
      },
    },
    ...Array.from({ length: p.localSsds }, () => ({
      type: "SCRATCH" as const,
      autoDelete: true,
      interface: "NVME" as const,
      initializeParams: { diskType: `zones/${p.zone}/diskTypes/local-ssd` },
    })),
  ],
  networkInterfaces: [
    {
      network: p.network,
      subnetwork: p.subnetwork,
      accessConfigs: [{ type: "ONE_TO_ONE_NAT", name: "external-nat" }],
    },
  ],
});

export const BurstInstanceProvider = () =>
  Provider.succeed(BurstInstance, {
    stables: ["instanceName", "zone"],

    diff: Effect.fn(function* ({ news, olds }) {
      if (!isResolved(news) || olds === undefined) return undefined;
      return deepEqual(olds, news) ? undefined : { action: "replace" as const, deleteFirst: true };
    }),

    read: Effect.fn(function* ({ id, olds, output, previous }) {
      const props = output ?? olds;
      if (props === undefined) return undefined;
      const env = yield* GCP.GcpEnvironment.current;
      const instance = yield* getInstance(env.project, props.zone, props.instanceName);
      if (instance === undefined) return undefined;
      const attrs = burstAttrs(instance, props.zone);
      return (yield* GCP.hasAlchemyLabels(id, instance.labels ?? undefined))
        ? attrs
        : unownedUnlessPrevious(attrs, previous, "instanceName");
    }),

    reconcile: Effect.fn(function* ({ id, news }) {
      const env = yield* GCP.GcpEnvironment.current;
      const { instanceName, zone } = news;
      let instance = yield* getInstance(env.project, zone, instanceName);
      if (instance === undefined) {
        const labels = yield* GCP.createInternalLabels(id);
        const op = yield* compute
          .insertInstances({ project: env.project, zone, body: burstBody(news, labels) })
          .pipe(Effect.catchTag("Conflict", () => Effect.undefined)); // made meanwhile
        if (op !== undefined) yield* waitZoneOperation(env.project, zone, op, ["RESOURCE_ALREADY_EXISTS"]);
        instance = yield* getInstance(env.project, zone, instanceName);
      }
      if (instance === undefined) return yield* new InstanceMissing({ instanceName, zone });
      return burstAttrs(instance, zone);
    }),

    delete: Effect.fn(function* ({ output }) {
      const env = yield* GCP.GcpEnvironment.current;
      const op = yield* compute
        .deleteInstances({ project: env.project, zone: output.zone, instance: output.instanceName })
        .pipe(Effect.catchTag("NotFound", () => Effect.undefined));
      if (op !== undefined) yield* waitZoneOperation(env.project, output.zone, op, ["RESOURCE_NOT_FOUND"]);
    }),
  });

// ---------------------------------------------------------------------------

/**
 * GCP.providers() and these three, as one layer for a stack's `providers:`.
 * Ours are fed GCP.providers() (provideMerge), so the stack gets both sets.
 * Their lifecycle calls need nothing at build time: they run in the stack's
 * context, where GCP.providers() has put the GCP environment, credentials
 * and HTTP client, just as the provider's own resources do.
 */
export const providers = () =>
  Layer.mergeAll(
    InstanceResourcePoliciesProvider(),
    BucketSoftDeleteProvider(),
    BurstInstanceProvider(),
  ).pipe(Layer.provideMerge(GCP.providers()));
