import { createHmac, randomBytes } from "node:crypto";
import fs from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { parseGatewayLockPayload } from "../../infra/gateway-lock-payload.js";
import { readGatewayOwnerLeaseFromDatabase } from "../../infra/gateway-owner-lease.read.js";
import { resolveGatewayStateOwnerPath } from "../../infra/gateway-state-owner.js";
import { withExistingOpenClawStateDatabaseCurrentReadOnly } from "../../state/openclaw-state-db-readonly.js";
import { resolveOpenClawStateSqlitePath } from "../../state/openclaw-state-db.paths.js";
import { isOAuthRefreshFence } from "./oauth-refresh-marker.js";
import { coercePersistedAuthProfileStore } from "./persisted-store.js";
import type { ScopedOAuthAuthorityAssertion } from "./scoped-oauth-delegation.js";
import { inspectAuthProfileJsonCell } from "./sqlite-json.js";
import type { AuthProfileCredential } from "./types.js";

// This key is deliberately distinct from the existing execution binding key.
// Unlike the binding proof, a generation changes on any credential rotation.
const generationKey = randomBytes(32);

export function fingerprintScopedOAuthGeneration(
  profileId: string,
  credential: AuthProfileCredential,
): string {
  return createHmac("sha256", generationKey)
    .update(JSON.stringify([profileId, credential]))
    .digest("hex");
}

type ScopedOAuthAuthorityObservation = Readonly<{
  owner: string;
  generation?: string;
  fenced: boolean;
}>;

/** Retain only a keyed generation and non-secret owner identity, not a credential or DB handle. */
export function captureScopedOAuthAuthorityAssertion(
  expectedGeneration: string,
  read: () => ScopedOAuthAuthorityObservation | undefined,
): ScopedOAuthAuthorityAssertion {
  let initial: ScopedOAuthAuthorityObservation | undefined;
  try {
    initial = read();
  } catch {
    return () => "stale";
  }
  if (!initial) {
    return () => "stale";
  }
  if (initial.fenced) {
    return () => "fenced";
  }
  if (initial.generation !== expectedGeneration) {
    return () => "stale";
  }
  const owner = initial.owner;
  let retired: "stale" | "fenced" | undefined;
  return () => {
    if (retired) {
      return retired;
    }
    try {
      const current = read();
      if (!current || current.owner !== owner) {
        return (retired = "stale");
      }
      if (current.fenced) {
        return (retired = "fenced");
      }
      if (current.generation !== expectedGeneration) {
        return (retired = "stale");
      }
      return "current";
    } catch {
      return (retired = "stale");
    }
  };
}

/** Capture the physical Gateway before any asynchronous shared-row preparation. */
export function captureScopedOAuthPhysicalOwnerId(env: NodeJS.ProcessEnv): string | undefined {
  try {
    const path = resolveGatewayStateOwnerPath(resolveOpenClawStateSqlitePath(env));
    const owner = parseGatewayLockPayload(fs.readFileSync(path, "utf8"));
    return owner?.role === "gateway" && owner.startTime != null && owner.processNamespace
      ? owner.ownerId
      : undefined;
  } catch {
    return undefined;
  }
}

/** Fresh shared-state read: no writer, refresh path or retained native connection.
 * Require both the live listening lease and its matching physical Gateway lock.
 * An unavailable or unverifiable owner is never treated as current.
 */
export function readScopedOAuthAuthority(
  env: NodeJS.ProcessEnv,
  profileId: string,
  expectedPhysicalOwnerId?: string,
): ScopedOAuthAuthorityObservation | undefined {
  const databasePath = resolveOpenClawStateSqlitePath(env);
  const ownerPath = resolveGatewayStateOwnerPath(databasePath);
  const before = fs.readFileSync(ownerPath, "utf8");
  const physical = parseGatewayLockPayload(before);
  if (
    !physical?.ownerId ||
    (expectedPhysicalOwnerId !== undefined && physical.ownerId !== expectedPhysicalOwnerId) ||
    physical.role !== "gateway" ||
    physical.startTime == null ||
    !physical.processNamespace
  ) {
    return undefined;
  }
  const observation = withExistingOpenClawStateDatabaseCurrentReadOnly(
    ({ db }) => {
      const lease = readGatewayOwnerLeaseFromDatabase(db);
      if (
        !lease ||
        lease.state !== "live" ||
        lease.expired ||
        lease.listeningAt === undefined ||
        lease.startedAt == null ||
        lease.pid !== physical.pid ||
        lease.startedAt !== physical.startTime ||
        !isDeepStrictEqual(lease.processNamespace, physical.processNamespace)
      ) {
        return undefined;
      }
      const cell = inspectAuthProfileJsonCell(db, "store", "shared-state");
      if (cell.status !== "readable") {
        return undefined;
      }
      const credential = coercePersistedAuthProfileStore(cell.raw)?.profiles[profileId];
      return {
        owner: JSON.stringify([physical.ownerId, lease.owner, lease.pid, lease.startedAt]),
        generation: credential
          ? fingerprintScopedOAuthGeneration(profileId, credential)
          : undefined,
        fenced: credential?.type === "oauth" && isOAuthRefreshFence(credential),
      };
    },
    { env, path: databasePath, allowNativeRead: true },
  );
  return fs.readFileSync(ownerPath, "utf8") === before ? observation : undefined;
}
