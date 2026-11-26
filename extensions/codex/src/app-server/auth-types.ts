import type { AuthProfileStore } from "openclaw/plugin-sdk/agent-runtime";
import type { CodexLoginAccountParams } from "./protocol.js";

export type CodexAppServerPreparedAuthProfileSnapshot = {
  inferenceAuth?: "host-oauth";
  /** A runtime-only delegated proof must not be resolved as a persisted OAuth grant. */
  scopedOAuthDelegation?: true;
  loginParams: CodexLoginAccountParams;
  secretFreeCacheKey: string;
  /** Genuine ChatGPT principal id; email/profile fallbacks are not authorization identity. */
  chatgptAccountId?: string;
};

export type CodexAppServerPreparedAuth =
  | { kind: "api-key"; apiKey: string }
  | {
      kind: "profile";
      profileId: string;
      store: AuthProfileStore;
      snapshot?: CodexAppServerPreparedAuthProfileSnapshot;
    };

export type CodexAppServerResolvedPreparedAuth =
  | Extract<CodexAppServerPreparedAuth, { kind: "api-key" }>
  | (Extract<CodexAppServerPreparedAuth, { kind: "profile" }> & {
      snapshot: CodexAppServerPreparedAuthProfileSnapshot;
    });

export type CodexAppServerAuthRequirement = "api-key" | "environment-api-key" | "subscription";
export type CodexAppServerAuthHandoff = Readonly<{
  accessFingerprint: string;
  chatgptAccountId: string;
}>;
