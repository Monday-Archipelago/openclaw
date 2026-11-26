import { uniqueStrings } from "@openclaw/normalization-core/string-normalization";
import { resolveProviderIdForAuth } from "../provider-auth-aliases.js";
import { getScopedOAuthCandidate, getScopedOAuthCandidates } from "./runtime-scope.js";
import type { AuthProfileStore } from "./types.js";

/** Deduplicates profile ids while preserving first-seen order. */
export const dedupeProfileIds: (profileIds: string[]) => string[] = uniqueStrings;

export function listProfilesForProvider(store: AuthProfileStore, provider: string): string[] {
  const providerKey = resolveProviderIdForAuth(provider);
  return dedupeProfileIds([
    ...Object.entries(store.profiles)
      .filter(([, cred]) => resolveProviderIdForAuth(cred.provider) === providerKey)
      .map(([id]) => id),
    ...getScopedOAuthCandidates()
      .filter((candidate) => resolveProviderIdForAuth(candidate.provider) === providerKey)
      .map((candidate) => candidate.profileId),
  ]);
}

export function resolveSubscriptionAuthModeForProfiles(params: {
  store: AuthProfileStore;
  profileIds: ReadonlyArray<string | undefined>;
}): "oauth" | "token" | undefined {
  for (const profileId of params.profileIds) {
    const type = getScopedOAuthCandidate(profileId)
      ? "oauth"
      : profileId
        ? params.store.profiles[profileId]?.type
        : undefined;
    if (type === "oauth" || type === "token") {
      return type;
    }
  }
  return undefined;
}
