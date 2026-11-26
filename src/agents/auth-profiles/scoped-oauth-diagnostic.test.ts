import { describe, expect, it } from "vitest";
import { summarizeScopedOAuthRows } from "./scoped-oauth-diagnostic.js";
import type { OAuthCredential } from "./types.js";

describe("scoped OAuth admission diagnostics", () => {
  it("distinguishes missing flows from matching but copy-denied synthetic rows", () => {
    const oauth: OAuthCredential = {
      type: "oauth",
      provider: "openai",
      access: "synthetic-access",
      refresh: "synthetic-refresh",
      expires: 1_800_000_000_000,
      authFlow: "chatgpt-token-sharing",
    };
    const rows = {
      matching: oauth,
      denied: { ...oauth, copyToAgents: false },
      missing: { ...oauth, authFlow: undefined },
      foreign: { ...oauth, provider: "synthetic-provider" },
    };
    const summary = summarizeScopedOAuthRows(rows);
    expect(summary).toEqual({
      oauthRows: 4,
      openAiOAuthRows: 3,
      openAiMissingFlowRows: 1,
      matchingFlowRows: 2,
      recoveredFlowRows: 0,
      copyToAgentsDeniedRows: 1,
    });
    expect(JSON.stringify(summary)).not.toContain("synthetic");
  });
});
