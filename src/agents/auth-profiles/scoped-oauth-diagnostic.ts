import { resolveGlobalSingleton } from "../../shared/global-singleton.js";
import { recoverScopedOAuthAuthFlow } from "./scoped-oauth-classification.js";
import type { AuthProfileStore } from "./types.js";

export function scopedOAuthDiagnosticsEnabled(): boolean {
  return process.env.OPENCLAW_SCOPED_OAUTH_DIAGNOSTICS === "1";
}

/** Counts only normalized rows; never returns identifiers or credential material. */
export function summarizeScopedOAuthRows(profiles: AuthProfileStore["profiles"]) {
  let oauthRows = 0;
  let openAiOAuthRows = 0;
  let openAiMissingFlowRows = 0;
  let matchingFlowRows = 0;
  let recoveredFlowRows = 0;
  let copyToAgentsDeniedRows = 0;
  for (const row of Object.values(profiles)) {
    if (row.type !== "oauth") {
      continue;
    }
    oauthRows++;
    if (row.provider !== "openai") {
      continue;
    }
    openAiOAuthRows++;
    if (row.authFlow === undefined) {
      openAiMissingFlowRows++;
    }
    const recoveredAuthFlow = recoverScopedOAuthAuthFlow(row);
    if (row.authFlow === "chatgpt-token-sharing") {
      matchingFlowRows++;
    } else if (recoveredAuthFlow) {
      recoveredFlowRows++;
    }
    if (
      (row.authFlow === "chatgpt-token-sharing" || recoveredAuthFlow) &&
      row.copyToAgents === false
    ) {
      copyToAgentsDeniedRows++;
    }
  }
  return {
    oauthRows,
    openAiOAuthRows,
    openAiMissingFlowRows,
    matchingFlowRows,
    recoveredFlowRows,
    copyToAgentsDeniedRows,
  };
}

type AdmissionDiagnostic = {
  stage: "admission";
  ownership: "state-db" | "legacy-main";
  rows: ReturnType<typeof summarizeScopedOAuthRows> | null;
  physicalOwnerPresent: boolean | null;
  candidateMarkers: number;
};

export type ScopedOAuthRuntimeDiagnosticStage = "scope-entry" | "order" | "codex";

type RuntimeDiagnostic = {
  stage: ScopedOAuthRuntimeDiagnosticStage;
  mode: "none" | "env-only" | "agent-dir";
  scopePresent: boolean;
  scopeReadable: boolean | null;
  candidateMarkers: number | null;
  explicitOrderPresent: boolean | null;
  explicitOrderMatchesMarker: boolean | null;
  selectedProfilePresent: boolean | null;
  selectedProfileMatchesMarker: boolean | null;
  sameRuntimeModuleAsEntry: boolean | null;
};

type Diagnostic = AdmissionDiagnostic | RuntimeDiagnostic;

function diagnosticState() {
  // Diagnostic metadata only: no scope, credential, identifier or store reference.
  return resolveGlobalSingleton(Symbol.for("openclaw.scopedOAuthDiagnostic.v1"), () => ({
    entryModule: undefined as symbol | undefined,
    counts: new Map<Diagnostic["stage"], number>(),
  }));
}

export function observeScopedOAuthRuntimeModule(
  stage: ScopedOAuthRuntimeDiagnosticStage,
  moduleId: symbol,
): boolean | null {
  const state = diagnosticState();
  if (stage === "scope-entry") {
    state.entryModule = moduleId;
  }
  return state.entryModule === undefined ? null : state.entryModule === moduleId;
}

/** Explicit lab opt-in, at most 12 fixed-schema events per stage per process. */
export function reportScopedOAuthDiagnostic(event: Diagnostic): void {
  if (!scopedOAuthDiagnosticsEnabled()) {
    return;
  }
  const { counts } = diagnosticState();
  const count = counts.get(event.stage) ?? 0;
  if (count >= 12) {
    return;
  }
  counts.set(event.stage, count + 1);
  // Do not forward objects from auth stores, errors, or caller-provided messages.
  try {
    process.stderr.write(`[scoped-oauth-diagnostic] ${JSON.stringify(event)}\n`);
  } catch {
    // Diagnostics must not affect auth selection or failure handling.
  }
}
