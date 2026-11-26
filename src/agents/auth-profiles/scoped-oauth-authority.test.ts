import { describe, expect, it, vi } from "vitest";
import {
  captureScopedOAuthAuthorityAssertion,
  fingerprintScopedOAuthGeneration,
} from "./scoped-oauth-authority.js";
import type { AuthProfileCredential } from "./types.js";

describe("scoped OAuth authority", () => {
  it("uses a separate keyed generation proof that changes on token rotation", () => {
    const row: AuthProfileCredential = {
      type: "oauth",
      provider: "test",
      access: "synthetic-access",
      refresh: "synthetic-refresh",
      expires: 1_800_000_000_000,
      accountId: "test-account",
    };
    const proof = fingerprintScopedOAuthGeneration("test:one", row);
    expect(fingerprintScopedOAuthGeneration("test:one", { ...row })).toBe(proof);
    expect(fingerprintScopedOAuthGeneration("test:other", row)).not.toBe(proof);
    expect(
      fingerprintScopedOAuthGeneration("test:one", { ...row, refresh: "synthetic-rotated" }),
    ).not.toBe(proof);
    expect(proof).not.toContain(row.refresh);
  });

  it.each([
    [{ owner: "replacement", generation: "generation", fenced: false }, "stale"],
    [{ owner: "owner", generation: "new-generation", fenced: false }, "stale"],
    [{ owner: "owner", generation: "generation", fenced: true }, "fenced"],
    [undefined, "stale"],
  ] as const)("permanently retires an observed changed authority", (changed, denial) => {
    const initial = { owner: "owner", generation: "generation", fenced: false };
    let observation: Parameters<
      typeof captureScopedOAuthAuthorityAssertion
    >[1] extends () => infer T
      ? T
      : never = initial;
    const read = vi.fn(() => observation);
    const assertCurrent = captureScopedOAuthAuthorityAssertion("generation", read);
    expect(assertCurrent()).toBe("current");
    observation = changed;
    expect(assertCurrent()).toBe(denial);
    observation = initial;
    expect(assertCurrent()).toBe(denial);
    expect(read).toHaveBeenCalledTimes(3);
  });

  it("denies missing, fenced and mismatched admission without later revival", () => {
    const read = vi.fn(() => ({ owner: "owner", generation: "other", fenced: false }));
    const stale = captureScopedOAuthAuthorityAssertion("generation", read);
    expect(stale()).toBe("stale");
    expect(captureScopedOAuthAuthorityAssertion("generation", () => undefined)()).toBe("stale");
    expect(
      captureScopedOAuthAuthorityAssertion("generation", () => ({
        owner: "owner",
        generation: "other",
        fenced: true,
      }))(),
    ).toBe("fenced");
  });

  it("sanitizes a failed live read and retires the assertion", () => {
    const read = vi.fn(() => ({ owner: "owner", generation: "generation", fenced: false }));
    const assertCurrent = captureScopedOAuthAuthorityAssertion("generation", read);
    read.mockImplementationOnce(() => {
      throw new Error("synthetic-private-diagnostic");
    });
    expect(assertCurrent()).toBe("stale");
    expect(assertCurrent()).toBe("stale");
  });
});
