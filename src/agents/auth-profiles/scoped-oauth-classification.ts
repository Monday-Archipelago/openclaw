import type { AuthProfileCredential } from "./types.js";

/**
 * Recover a missing runtime flow only from the canonical provider's recorded grant.
 * Mirrors the granted-scope distinction in extensions/openai/token-sharing-oauth.runtime.ts.
 * Native Codex imports and requested scopes alone do not establish a sharing grant.
 * This is routing metadata, not new OAuth authority or a persisted repair.
 */
export function recoverScopedOAuthAuthFlow(
  credential: AuthProfileCredential,
): "chatgpt-token-sharing" | undefined {
  if (
    credential.type !== "oauth" ||
    credential.provider !== "openai" ||
    credential.authFlow !== undefined ||
    credential.issuer !== "https://auth.openai.com" ||
    credential.tokenEndpoint !== "https://auth.openai.com/api/accounts/oauth/token" ||
    !credential.clientId?.trim() ||
    credential.clientId === "dynamic_agent_client" ||
    !credential.accountId?.trim() ||
    !credential.grantedScope
  ) {
    return undefined;
  }
  const granted = new Set(credential.grantedScope.split(/\s+/u));
  return granted.has("resource.invoke") &&
    (granted.has("chatpass.enable.request.direct") || granted.has("chatgpt.tokens.use.direct"))
    ? "chatgpt-token-sharing"
    : undefined;
}
