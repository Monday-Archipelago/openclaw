import { CLAUDE_CLI_PROFILE_ID } from "./constants.js";
import { captureScopedOAuthAuthorityAssertion, captureScopedOAuthPhysicalOwnerId, fingerprintScopedOAuthGeneration, readScopedOAuthAuthority } from "./scoped-oauth-authority.js";
import { createScopedOAuthDelegation, type ScopedOAuthDelegation } from "./scoped-oauth-delegation.js";
import { captureOpenClawStateWorkerContext } from "../../state/openclaw-state-worker-context.js";
import { captureAuthProfileCredentialAuthority } from "../../state/user-model-account-authority.js";
import {
  resolveSharedAuthStoreOwnership,
  resolveSharedAuthStoreOwnershipAsync,
} from "./path-resolve.js";
import { resolveAuthProfilePortability } from "./portability.js";
import {
  createEmptyAuthProfileStore,
  pruneAuthProfileStoreReferences,
} from "./runtime-snapshot-owner.js";
import { loadPersistedAuthProfileStoreFromRows, readSharedAuthProfileRows } from "./sqlite-read.js";
import type { AuthProfileCredential, AuthProfileStore } from "./types.js";

/** Prepare the shared read-through view; the scope owner validates it immediately before entry. */
export async function prepareScopedSharedAuthProfileStore(env: NodeJS.ProcessEnv): Promise<{
  sharedStore: AuthProfileStore | undefined;
  oauthDelegation?: ScopedOAuthDelegation;
  assertCurrent: () => void;
}> {
  const context = captureOpenClawStateWorkerContext({ env });
  const ownership = await resolveSharedAuthStoreOwnershipAsync(context);
  let sharedStore: AuthProfileStore | undefined;
  let oauthDelegation: ScopedOAuthDelegation | undefined;
  const assertCurrent = () => {
    context.admission.assertCurrent();
    context.maintenanceScope?.assertAdmission();
    if (resolveSharedAuthStoreOwnership(env).location !== ownership.location) {
      throw new Error("Shared auth store ownership changed during scope preparation; retry the operation.");
    }
  };
  if (ownership.location === "state-db") {
    const physicalOwnerId = captureScopedOAuthPhysicalOwnerId(env);
    sharedStore =
      loadPersistedAuthProfileStoreFromRows(
        await readSharedAuthProfileRows(context),
        context.admission.databasePath,
      ) ?? createEmptyAuthProfileStore();
    const candidates = Object.entries(sharedStore.profiles).flatMap(([profileId, credential]) => {
      // Ordinary OAuth/native login flows retain their existing portability behavior.
      // Phase A targets the existing ChatGPT token-sharing bearer transport.
      if (credential.type !== "oauth" || credential.provider !== "openai" ||
          credential.authFlow !== "chatgpt-token-sharing") {
        return [];
      }
      const supported = Boolean(physicalOwnerId) &&
        profileId !== CLAUDE_CLI_PROFILE_ID && credential.copyToAgents !== false;
      const read = () => {
        assertCurrent();
        return readScopedOAuthAuthority(env, profileId, physicalOwnerId);
      };
      const generation = fingerprintScopedOAuthGeneration(profileId, credential);
      return [{ profileId, provider: credential.provider, credential,
        assertCurrent: supported ? captureScopedOAuthAuthorityAssertion(generation, read) : () => "stale" as const,
      }];
    });
    if (candidates.length) {
      oauthDelegation = createScopedOAuthDelegation(candidates);
    }
    // Temporary runs must not acquire a second OAuth refresh owner. This view
    // stays inside the operation scope and is never persisted into an agent store.
    sharedStore.profiles = Object.fromEntries(
      Object.entries(sharedStore.profiles).filter(
        ([, credential]) =>
          resolveAuthProfilePortability(credential).reason === "portable-static-credential",
      ),
    );
    pruneAuthProfileStoreReferences(sharedStore, new Set(Object.keys(sharedStore.profiles)));
  }
  return {
    sharedStore,
    oauthDelegation,
    assertCurrent,
  };
}

/** Retain live shared authority without extending the scope's static-credential policy. */
export async function prepareScopedSharedAuthProfileCredentialRead(
  env: NodeJS.ProcessEnv,
  profileId: string,
): Promise<() => AuthProfileCredential | undefined> {
  const context = captureOpenClawStateWorkerContext({ env });
  const authority = captureAuthProfileCredentialAuthority(
    context,
    {
      identity: `${context.admission.identity.key}:${context.admission.identity.birthtime ?? ""}`,
      databasePath: context.admission.databasePath,
    },
    profileId,
  );
  const store = loadPersistedAuthProfileStoreFromRows(
    await readSharedAuthProfileRows(context),
    context.admission.databasePath,
  );
  authority.observe(store?.profiles[profileId]);
  return () => {
    const credential = authority.readCurrentCredential();
    return credential &&
      resolveAuthProfilePortability(credential).reason === "portable-static-credential"
      ? credential
      : undefined;
  };
}
