import { execFile, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocketServer } from "ws";
import { GATEWAY_SERVER_CAPS } from "../../packages/gateway-protocol/src/server-capabilities.js";
import { awaitGateBeforeSettlement, createDeferred } from "../../test/helpers/promise.js";
import { isProcessAlive } from "../../test/helpers/process-wait.js";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import { createManagedWorktreeOwnerPolicy } from "../agents/worktrees/owner-protection.js";
import { updateRegistryWorktree } from "../agents/worktrees/registry.js";
import { IDLE_GC_MS, ManagedWorktreeService } from "../agents/worktrees/service.js";
import {
  materializeManagedWorktreeFixture,
  useManagedWorktreeTestRepository,
} from "../agents/worktrees/service.test-support.js";
import type { ManagedWorktreeRecord } from "../agents/worktrees/types.js";
import {
  buildMinimalGatewayHelloOkPayload,
  closeMinimalGatewayServer,
  parseMinimalGatewayRequestFrame,
  sendMinimalGatewayConnectChallenge,
  sendMinimalGatewayResponse,
} from "../gateway/minimal-gateway.test-helpers.js";
import {
  createSessionMutationTestClient,
  createSessionMutationTestContext,
} from "../gateway/server-methods/sessions-mutations.owner.test-support.js";
import { createWorktreesHandlers } from "../gateway/server-methods/worktrees.js";
import { startWorktreeMaintenance } from "../gateway/worktree-maintenance.js";
import {
  acquireGatewayLock,
  readActiveGatewayLockIdentity,
  resolveGatewayLockPaths,
  type GatewayLockHandle,
} from "../infra/gateway-lock.js";
import { resolveRuntimeWorkerArgv, resolveRuntimeWorkerUrl } from "../infra/runtime-worker-url.js";
import { closeOpenClawStateDatabaseAsync } from "../state/openclaw-state-db.js";
import {
  createGatewaySchedulerClock,
  createTestGatewayScheduler,
} from "../test-utils/gateway-scheduler-clock.js";
import {
  acquireTestPortBlock,
  reserveTestPortListener,
  type TestPortClaim,
} from "../test-utils/port-claims.js";
import { seedInstalledPluginIndex } from "../plugins/test-helpers/installed-plugin-index.js";
import { withOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { localStateOwnerFixtureEntrypoint } from "./cli-entrypoint.test-support.js";
import { captureCliProcessTree } from "./cli-process-tree.test-support.js";
import { runCliProcessChild } from "./cli-process-child.test-helpers.js";
import { registerWorktreeListingOwnerTests } from "./local-state-owner-listing.test-support.js";

const execFileAsync = promisify(execFile);
const roots = useAutoCleanupTempDirTracker(afterAll);
const token = "synthetic-routing-owner-token";
const entrypoint = resolveRuntimeWorkerArgv(
  resolveRuntimeWorkerUrl(localStateOwnerFixtureEntrypoint),
);

function environment(root: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    HOME: root,
    USERPROFILE: root,
    OPENCLAW_HOME: root,
    OPENCLAW_STATE_DIR: path.join(root, "state"),
    OPENCLAW_CONFIG_PATH: path.join(root, "openclaw.json"),
    OPENCLAW_GATEWAY_TOKEN: token,
    OPENCLAW_NO_RESPAWN: "1",
    OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
    NODE_DISABLE_COMPILE_CACHE: "1",
  };
}

async function git(repo: string, ...args: string[]) {
  return (await execFileAsync("git", ["-C", repo, ...args])).stdout.trim();
}

describe("same-root local mutation routing", () => {
  const initializeRepository = useManagedWorktreeTestRepository();
  let root: string;
  let repo: string;
  let repoSelector: string;
  let decoyRepo: string | undefined;
  let env: NodeJS.ProcessEnv;
  let server: WebSocketServer;
  let claim: TestPortClaim;
  let owner: GatewayLockHandle | null;
  let service: ManagedWorktreeService;
  let repoFingerprint: string;
  const maintenanceClock = createGatewaySchedulerClock(Date.now());
  const scheduler = createTestGatewayScheduler(maintenanceClock.clock);
  let maintenance: ReturnType<typeof startWorktreeMaintenance>;
  let mode: "normal" | "old" | "refused" | "lost-reply" = "normal";
  const requests: string[] = [];
  const methods: string[] = [];
  const failures: unknown[] = [];

  beforeAll(async () => {
    root = roots.make("openclaw-local-owner-online-");
    env = environment(root);
    repo = await initializeRepository(root);
    for (const file of ["alpha/a.txt", "beta/b.txt", "excluded/no.txt"]) {
      await fs.mkdir(path.dirname(path.join(repo, file)), { recursive: true });
      await fs.writeFile(path.join(repo, file), file);
    }
    await fs.mkdir(path.join(repo, ".openclaw", "worktree-profiles"), { recursive: true });
    await fs.writeFile(path.join(repo, ".openclaw", "worktree-profiles", "alpha"), "alpha\n");
    await fs.writeFile(path.join(repo, ".openclaw", "worktree-profiles", "beta"), "beta\n");
    if (process.platform !== "win32") {
      const setup = path.join(repo, ".openclaw", "worktree-setup.sh");
      await fs.writeFile(setup, "#!/bin/sh\nprintf 'owner setup complete\\n' > setup-proof.txt\n");
      await fs.chmod(setup, 0o755);
    }
    await git(repo, "add", ".");
    await git(repo, "commit", "-m", "source profiles");
    await git(repo, "push", "origin", "main");
    repoSelector = repo;
    if (process.platform !== "win32") {
      const entry = path.join(root, "entry");
      const anchor = path.join(root, "anchor");
      await fs.mkdir(entry);
      await fs.mkdir(anchor);
      await fs.symlink(anchor, path.join(entry, "link"), "dir");
      decoyRepo = path.join(entry, "repo");
      await git(root, "clone", "--no-hardlinks", repo, decoyRepo);
      // Preserve .. so filesystem lookup follows the link before ascending.
      repoSelector = `${path.join(entry, "link")}/../repo`;
    }
    claim = await acquireTestPortBlock({ offsets: [0] });
    await fs.writeFile(
      env.OPENCLAW_CONFIG_PATH!,
      JSON.stringify({
        gateway: { mode: "local", port: claim.port, auth: { mode: "token", token } },
      }),
    );
    vi.stubEnv("OPENCLAW_STATE_DIR", env.OPENCLAW_STATE_DIR);
    vi.stubEnv("OPENCLAW_CONFIG_PATH", env.OPENCLAW_CONFIG_PATH);
    vi.stubEnv("HOME", root);
    vi.stubEnv("USERPROFILE", root);
    const cfg = { worktreeRoot: path.join(root, "gateway-worktrees"), worktreeAcceleration: false };
    service = new ManagedWorktreeService({ env, getConfig: () => cfg });
    repoFingerprint = (await service.resolveRepositoryIdentity(repo)).fingerprint;
    owner = await acquireGatewayLock({ env, port: claim.port, allowInTests: true, timeoutMs: 0 });
    expect(owner).not.toBeNull();
    const handlers = createWorktreesHandlers(service);
    const context = createSessionMutationTestContext(cfg);
    maintenance = startWorktreeMaintenance({
      scheduler,
      getRuntimeConfig: context.getRuntimeConfig,
      runGc: () => service.gc(createManagedWorktreeOwnerPolicy(cfg)),
      onComplete: () => {},
      onError: (error) => failures.push(error),
    });
    const client = createSessionMutationTestClient();
    client.connect.scopes = ["operator.admin"];
    server = new WebSocketServer({ host: "127.0.0.1", port: claim.port });
    server.on("connection", (ws) => {
      let authenticated = false;
      sendMinimalGatewayConnectChallenge(ws);
      ws.on("message", (data) => {
        void (async () => {
          const frame = parseMinimalGatewayRequestFrame(data);
          if (!frame.id) {
            return;
          }
          if (frame.method === "connect") {
            authenticated = frame.params?.auth?.token === token;
            expect(authenticated).toBe(true);
            const hello = buildMinimalGatewayHelloOkPayload({
              methods: Object.keys(handlers),
              auth: { role: "operator", scopes: ["operator.admin"] },
              snapshot: { stateDir: env.OPENCLAW_STATE_DIR, configPath: env.OPENCLAW_CONFIG_PATH },
            });
            sendMinimalGatewayResponse(ws, frame.id, {
              ...hello,
              features: {
                ...hello.features,
                capabilities: mode === "old" ? [] : Object.values(GATEWAY_SERVER_CAPS),
              },
            });
            return;
          }
          expect(authenticated).toBe(true);
          const method = frame.method!;
          expect(handlers[method]).toBeTypeOf("function");
          methods.push(method);
          if (method === "worktrees.create") {
            requests.push(String(frame.params?.name));
          }
          await handlers[method]!({
            req: { type: "req", id: frame.id, method, params: frame.params },
            params: {
              ...frame.params,
              ...(mode === "refused" ? { expectedOwnerId: "retired-owner" } : {}),
            },
            client,
            context,
            isWebchatConnect: () => false,
            hasCurrentClientAuthority: () => authenticated,
            respond: (ok, payload, error) => {
              if (mode === "lost-reply" && ok) {
                ws.close(
                  1011,
                  "lost reply ws://fixture-user:fixture-pass@gw.invalid/?token=fixture-secret",
                );
              } else {
                ws.send(JSON.stringify({ type: "res", id: frame.id, ok, payload, error }));
              }
            },
          });
        })().catch((error: unknown) => {
          failures.push(error);
          ws.terminate();
        });
      });
    });
    await once(server, "listening");
  });

  beforeEach(() => {
    mode = "normal";
    vi.stubEnv("OPENCLAW_STATE_DIR", env.OPENCLAW_STATE_DIR);
    vi.stubEnv("OPENCLAW_CONFIG_PATH", env.OPENCLAW_CONFIG_PATH);
    vi.stubEnv("HOME", root);
    vi.stubEnv("USERPROFILE", root);
  });

  afterAll(async () => {
    await maintenance.stop();
    await scheduler.stop();
    await closeMinimalGatewayServer(server);
    await closeOpenClawStateDatabaseAsync();
    await owner?.release();
    await claim.release();
    vi.unstubAllEnvs();
    expect(failures).toEqual([]);
  });

  const create = (name: string, extra: string[] = [], selector = repo) =>
    runCliProcessChild({
      nodeArgs: [
        ...entrypoint,
        "worktrees",
        "create",
        selector,
        "--name",
        name,
        "--base-ref",
        "HEAD",
        "--json",
        ...extra,
      ],
      // A configured remote URL must not redirect this same-root operation.
      env: { ...env, OPENCLAW_GATEWAY_URL: "ws://127.0.0.1:1" },
    });

  registerWorktreeListingOwnerTests(
    () => ({
      root,
      repo,
      env,
      service,
      methods,
      port: claim.port,
      get owner() {
        return owner;
      },
      set owner(value: GatewayLockHandle | null) {
        owner = value;
      },
    }),
    entrypoint,
  );

  it("runs the CLI create in the live owner and exposes committed profile results", async () => {
    const result = await create(
      "routed",
      ["--source-profile", "alpha", "--source-profile", "beta"],
      repoSelector,
    );
    expect(result.code, result.stderr).toBe(0);
    const record: ManagedWorktreeRecord = JSON.parse(result.stdout);
    expect({
      repoRoot: record.repoRoot,
      sourceBranch: await git(repo, "branch", "--list", "openclaw/routed"),
      ...(decoyRepo
        ? { decoyBranch: await git(decoyRepo, "branch", "--list", "openclaw/routed") }
        : {}),
    }).toEqual({
      repoRoot: repo,
      sourceBranch: "+ openclaw/routed",
      ...(decoyRepo ? { decoyBranch: "" } : {}),
    });
    expect(record.path).toContain(path.join(root, "gateway-worktrees"));
    expect(record.ownerKind).toBe("manual");
    if (process.platform !== "win32") {
      expect(await fs.readFile(path.join(record.path, "setup-proof.txt"), "utf8")).toBe(
        "owner setup complete\n",
      );
    }
    expect(await service.listRegistryRecords()).toContainEqual(
      expect.objectContaining({ id: record.id, path: record.path }),
    );
    expect(await fs.readFile(path.join(record.path, "alpha/a.txt"), "utf8")).toBe("alpha/a.txt");
    expect(await fs.readFile(path.join(record.path, "beta/b.txt"), "utf8")).toBe("beta/b.txt");
    await expect(fs.access(path.join(record.path, "excluded/no.txt"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(await git(record.path, "rev-parse", "HEAD")).toBe(await git(repo, "rev-parse", "HEAD"));
    expect(requests).toEqual(["routed"]);
    await fs.writeFile(path.join(record.path, "alpha/a.txt"), "retained routed work\n");
    for (const restore of [false, true]) {
      if (restore) {
        await service.remove({ id: record.id, reason: "create restore fixture" });
      }
      const repeated = await create("routed");
      expect(repeated.code, repeated.stderr).toBe(0);
      expect(JSON.parse(repeated.stdout)).toMatchObject({ id: record.id, path: record.path });
      expect(await fs.readFile(path.join(record.path, "alpha/a.txt"), "utf8")).toBe(
        "retained routed work\n",
      );
      expect(
        (await service.listRegistryRecords()).find((item) => item.id === record.id)?.removedAt,
      ).toBeUndefined();
    }
  });

  it.each(["old", "refused", "lost-reply"] as const)(
    "does not fall back locally after %s",
    async (scenario) => {
      mode = scenario;
      const before = requests.length;
      const result = await create(scenario);
      expect(result.code, result.stderr).toBe(1);
      if (scenario === "old") {
        expect(result.stderr).toMatch(/capabilit/iu);
        expect(result.stderr).toContain("Update the Gateway");
        expect(requests).toHaveLength(before);
      } else {
        expect(requests).toHaveLength(before + 1);
        expect(result.stderr).toContain(
          scenario === "refused" ? "No local mutation" : "outcome may be partial",
        );
      }
      const records = (await service.listRegistryRecords()).filter(
        (record) => record.name === scenario,
      );
      expect(records).toHaveLength(scenario === "lost-reply" ? 1 : 0);
      if (records[0]) {
        expect(records[0].path).toContain(path.join(root, "gateway-worktrees"));
      }
      expect(await git(repo, "branch", "--list", `openclaw/${scenario}`)).toBe(
        scenario === "lost-reply" ? "+ openclaw/lost-reply" : "",
      );
      if (scenario === "lost-reply") {
        for (const output of [result.stderr, result.stdout]) {
          expect(output).not.toMatch(/fixture-(?:user|pass|secret)/u);
        }
      }
    },
  );

  const operations = [
    { kind: "exact-remove", method: "worktrees.remove", scenario: "live" },
    { kind: "exact-remove", method: "worktrees.remove", scenario: "offline" },
    { kind: "gc-partial", method: "worktrees.gc", scenario: "live" },
  ] as const;
  type Operation = (typeof operations)[number];
  let sequence = 0;

  async function prepareOperation(kind: Operation["kind"]) {
    const name = `mutation-${++sequence}`;
    const record = await materializeManagedWorktreeFixture({
      env,
      stateDir: env.OPENCLAW_STATE_DIR!,
      repoRoot: repo,
      repoFingerprint,
      name,
      now: Date.now(),
      ownerKind: kind === "gc-partial" ? "workboard" : "manual",
    });
    const readRecord = async () =>
      (await service.listRegistryRecords()).find((candidate) => candidate.id === record.id);
    if (kind === "exact-remove") {
      const head = await git(record.path, "rev-parse", "HEAD");
      await git(record.path, "checkout", "--detach", "HEAD");
      await fs.writeFile(path.join(record.path, "README.md"), "staged\n");
      await git(record.path, "add", "README.md");
      await fs.writeFile(path.join(record.path, "README.md"), "working\n");
      const index = await fs.readFile(
        path.resolve(record.path, await git(record.path, "rev-parse", "--git-path", "index")),
      );
      const exactState = {
        ownerKind: record.ownerKind,
        createdAt: record.createdAt,
        lastActiveAt: record.lastActiveAt,
        head,
        branchHead: head,
        indexSha256: createHash("sha256").update(index).digest("hex"),
      };
      const filename = path.join(root, `${name}.json`);
      await fs.writeFile(filename, JSON.stringify(exactState));
      return {
        args: ["worktrees", "remove", record.id, "--exact-state", filename, "--json"],
        cleanup: async () => {},
        verify: async (mutated: boolean, payload?: Record<string, unknown>) => {
          expect((await readRecord())?.removedAt !== undefined).toBe(mutated);
          const retained = payload?.recoveryPath;
          expect(retained).toBeTypeOf("string");
          expect(await fs.readFile(path.join(String(retained), "README.md"), "utf8")).toBe(
            "working\n",
          );
          expect(payload).toMatchObject({
            removed: true,
            recoveryRetainedUntil: expect.any(Number),
          });
          await expect(fs.stat(record.path)).rejects.toMatchObject({ code: "ENOENT" });
        },
      };
    }
    await updateRegistryWorktree(env, record.id, { lastActiveAt: Date.now() - IDLE_GC_MS - 1 });
    const brokenRepo = await initializeRepository(path.join(root, name));
    const broken = await materializeManagedWorktreeFixture({
      env,
      repoRoot: brokenRepo,
      stateDir: path.join(root, name, "worktrees"),
      name: `${name}-broken`,
      now: Date.now() - IDLE_GC_MS - 1,
      ownerKind: "workboard",
    });
    await fs.rename(brokenRepo, `${brokenRepo}-away`);
    return {
      args: ["worktrees", "gc", "--json"],
      cleanup: async () => {
        await fs.rename(`${brokenRepo}-away`, brokenRepo);
        await updateRegistryWorktree(env, broken.id, { lastActiveAt: Date.now() });
      },
      verify: async (mutated: boolean, payload?: Record<string, unknown>) => {
        expect((await readRecord())?.removedAt !== undefined).toBe(mutated);
        if (mutated) {
          expect(payload).toMatchObject({
            outcome: "partial",
            removed: expect.arrayContaining([record.id]),
          });
          await expect(fs.stat(record.path)).rejects.toMatchObject({ code: "ENOENT" });
          expect(payload?.issues).toEqual(
            expect.arrayContaining([expect.objectContaining({ id: broken.id, outcome: "failed" })]),
          );
        }
      },
    };
  }

  it.each(operations)(
    "$kind: $scenario preserves the operation contract and custody",
    async ({ kind, method, scenario }) => {
      const prepared = await prepareOperation(kind);
      const before = methods.length;
      if (scenario === "offline") {
        await closeOpenClawStateDatabaseAsync();
        await owner?.release();
        owner = null;
      }
      try {
        const result = await runCliProcessChild({
          nodeArgs: [...entrypoint, ...prepared.args],
          env,
        });
        if (scenario === "offline") {
          owner = await acquireGatewayLock({
            env,
            port: claim.port,
            allowInTests: true,
            timeoutMs: 0,
          });
          expect(owner).not.toBeNull();
        }
        const observation = JSON.parse(
          await fs.readFile(path.join(root, "control", "sql-observation.json"), "utf8"),
        );
        expect(result.code, result.stderr).toBe(0);
        expect(methods.slice(before)).toEqual(scenario === "live" ? [method] : []);
        if (scenario === "offline") {
          expect(observation.missingCustody).toBe(0);
          for (const pid of observation.ownerPids) {
            expect(pid).toBe(observation.pid);
          }
        } else {
          expect(observation.worktreeSql).toBe(0);
        }
        let payload = JSON.parse(result.stdout);
        if (kind === "gc-partial") {
          expect(payload).toMatchObject({
            jobId: expect.any(String),
            state: "queued",
            startedAt: null,
            completedAt: null,
          });
          await prepared.verify(false);
          await maintenanceClock.advanceBy(0);
          const progress = await runCliProcessChild({
            nodeArgs: [...entrypoint, "worktrees", "gc", "--job", payload.jobId, "--json"],
            env,
          });
          expect(progress.code, progress.stderr).toBe(1);
          expect(methods.slice(before)).toEqual([method, method]);
          const completed = JSON.parse(progress.stdout);
          expect(completed).toMatchObject({
            jobId: payload.jobId,
            state: "completed",
            completedAt: expect.any(Number),
          });
          expect(
            JSON.parse(
              await fs.readFile(path.join(root, "control", "sql-observation.json"), "utf8"),
            ).worktreeSql,
          ).toBe(0);
          payload = completed;
        }
        await prepared.verify(true, payload);
      } finally {
        if (!owner) {
          owner = await acquireGatewayLock({
            env,
            port: claim.port,
            allowInTests: true,
            timeoutMs: 0,
          });
        }
        await prepared.cleanup();
      }
    },
  );

  it.each([
    ["mcp logout", ["mcp", "logout", "synthetic-server"]],
    ["models auth logout", ["models", "auth", "logout", "synthetic:manual", "--yes"]],
    ["models auth activate", ["models", "auth", "activate", "synthetic:setup"]],
    ["sandbox recreate", ["sandbox", "recreate", "--all", "--force"]],
    [
      "migration import",
      [
        "migrate",
        "apply",
        "synthetic-missing-provider",
        "--yes",
        "--no-backup",
        "--force",
        "--json",
      ],
    ],
    ["exec-policy preset", ["exec-policy", "preset", "deny-all"]],
  ])(
    "refuses live %s before changing local state or dispatching to the owner",
    async (_name, args) => {
      const before = methods.length;
      const configBefore = await fs.readFile(env.OPENCLAW_CONFIG_PATH!, "utf8");
      const result = await runCliProcessChild({
        nodeArgs: [...entrypoint, ...args],
        env,
      });
      expect(result.code, result.stderr).toBe(1);
      expect(result.stderr).toContain("exclusive offline state ownership");
      expect(methods).toHaveLength(before);
      expect(await fs.readFile(env.OPENCLAW_CONFIG_PATH!, "utf8")).toBe(configBefore);
      expect(
        JSON.parse(await fs.readFile(path.join(root, "control", "sql-observation.json"), "utf8"))
          .worktreeSql,
      ).toBe(0);
    },
  );
});

async function waitForChildStdoutMarker(
  child: ChildProcessWithoutNullStreams,
  marker: string,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let stdout = "";
    const cleanup = () => {
      child.stdout.off("data", onData);
      child.stdout.off("end", onEnd);
      child.stdout.off("error", onError);
      child.off("exit", onExit);
      child.off("error", onError);
    };
    const succeed = () => {
      cleanup();
      resolve();
    };
    const fail = (message: string, cause?: unknown) => {
      cleanup();
      reject(new Error(message, cause === undefined ? undefined : { cause }));
    };
    const onData = (chunk: string | Buffer) => {
      stdout += chunk.toString();
      if (stdout.includes(marker)) {
        succeed();
      }
    };
    const onEnd = () => fail(`CLI stdout ended before marker ${JSON.stringify(marker)}`);
    const onExit = (code: number | null, signal: NodeJS.Signals | null) =>
      fail(
        `CLI exited before marker ${JSON.stringify(marker)} (code=${code} signal=${signal})`,
      );
    const onError = (error: Error) =>
      fail(`CLI failed before marker ${JSON.stringify(marker)}: ${error.message}`, error);

    child.stdout.on("data", onData);
    child.stdout.once("end", onEnd);
    child.once("exit", onExit);
    child.stdout.once("error", onError);
    child.once("error", onError);
  });
}

function processRows(tree: string): Array<{ pid: number; ppid: number }> {
  return tree
    .split("\n")
    .flatMap((line) => {
      try {
        const value = JSON.parse(line) as { pid?: unknown; ppid?: unknown };
        return typeof value.pid === "number" && typeof value.ppid === "number"
          ? [{ pid: value.pid, ppid: value.ppid }]
          : [];
      } catch {
        return [];
      }
    });
}

async function assertNaturalExitAfterOutput(
  child: ChildProcessWithoutNullStreams,
  marker: string,
  timeoutMs = 5_000,
): Promise<void> {
  await waitForChildStdoutMarker(child, marker);
  const descendants =
    process.platform === "win32"
      ? []
      : processRows(await captureCliProcessTree(child.pid))
          .filter((row) => row.pid !== child.pid)
          .map((row) => row.pid);
  if (child.exitCode === null && child.signalCode === null) {
    const exit = once(child, "exit");
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`CLI did not exit within ${timeoutMs}ms after final output`)),
        timeoutMs,
      );
      timer.unref();
    });
    try {
      await Promise.race([exit, deadline]);
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }
  expect(
    descendants.filter(isProcessAlive),
    `descendant processes remained after auth-activate completion: ${descendants.join(", ")}`,
  ).toEqual([]);
}

describe("models auth activate process lifecycle", () => {
  it("activates a plugin-owned saved sign-in offline and exits naturally", async () => {
    await withOpenClawTestState(
      { label: "models-auth-activate-process", applyEnv: false },
      async (state) => {
        const pluginId = "auth-activate-runtime";
        const providerId = "fixture-provider";
        const modelId = "proof-model";
        const modelRef = `${providerId}/${modelId}`;
        const profileId = `${providerId}:setup-process`;
        const pluginDir = state.statePath("pending-auth-runtime");
        const lifecyclePath = state.statePath("auth-activate-lifecycle.jsonl");
        await fs.mkdir(pluginDir, { recursive: true });
        await fs.writeFile(
          path.join(pluginDir, "package.json"),
          JSON.stringify({
            name: "@fixture/auth-activate-runtime",
            version: "1.0.0",
            type: "commonjs",
            openclaw: { extensions: ["./index.cjs"] },
          }),
        );
        await fs.writeFile(
          path.join(pluginDir, "openclaw.plugin.json"),
          JSON.stringify({
            id: pluginId,
            activation: { onAgentHarnesses: [pluginId] },
            configSchema: { type: "object", properties: {}, additionalProperties: false },
          }),
        );
        await fs.writeFile(
          path.join(pluginDir, "index.cjs"),
          `
const fs = require("node:fs");
const record = phase =>
  fs.appendFileSync(process.env.AUTH_ACTIVATE_LIFECYCLE_PATH, JSON.stringify({ phase, pid: process.pid }) + "\\n");
const assistant = {
  role: "assistant",
  content: [{ type: "text", text: "OK" }],
  api: "openai-responses",
  provider: ${JSON.stringify(providerId)},
  model: ${JSON.stringify(modelId)},
  usage: {
    input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  },
  stopReason: "stop",
  timestamp: Date.now(),
};
module.exports = {
  id: ${JSON.stringify(pluginId)},
  register(api) {
    record("register");
    api.lifecycle.onDispose(() => record("dispose"));
    api.registerAgentHarness({
      id: ${JSON.stringify(pluginId)},
      label: "Auth activate lifecycle fixture",
      supports: ({ provider }) =>
        provider === ${JSON.stringify(providerId)}
          ? { supported: true, priority: 100 }
          : { supported: false },
      conversationToolPolicySupport: "exact",
      supportsTurnScopedToolRestrictions: true,
      async runAttempt() {
        record("attempt");
        return {
          terminal: { kind: "ok" },
          sessionIdUsed: "auth-activate-proof-session",
          messagesSnapshot: [assistant],
          assistantTexts: ["OK"],
          toolMetas: [],
          lastAssistant: assistant,
          didSendViaMessagingTool: false,
          messagingToolSentTexts: [],
          messagingToolSentMediaUrls: [],
          messagingToolSentTargets: [],
          cloudCodeAssistFormatError: false,
          replayMetadata: { hadPotentialSideEffects: false, replaySafe: true },
          itemLifecycle: { startedCount: 0, completedCount: 0, activeCount: 0 },
          runtimeArtifact: { id: "fixture-runtime", fingerprint: "fixture-runtime-v1" },
        };
      },
      runtimeArtifact: {
        async validate(artifact) {
          return artifact.id === "fixture-runtime" && artifact.fingerprint === "fixture-runtime-v1";
        },
      },
    });
  },
};
`,
        );
        const savedConfig = {
          plugins: {
            allow: [pluginId],
            entries: { [pluginId]: { enabled: true } },
            slots: { memory: "none" },
          },
          agents: {
            defaults: {
              workspace: state.workspaceDir,
              skipBootstrap: true,
              skills: [],
              models: { [modelRef]: { agentRuntime: { id: pluginId } } },
            },
          },
          models: {
            mode: "replace",
            providers: {
              [providerId]: {
                api: "openai-responses",
                baseUrl: "https://example.invalid/v1",
                models: [
                  {
                    id: modelId,
                    name: "Lifecycle fixture",
                    reasoning: false,
                    input: ["text"],
                    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
                    contextWindow: 32_000,
                    maxTokens: 1_000,
                  },
                ],
              },
            },
          },
        };
        await seedInstalledPluginIndex(
          {
            [pluginId]: {
              source: "path",
              sourcePath: pluginDir,
              installPath: pluginDir,
            },
          },
          {
            stateDir: state.stateDir,
            env: state.env,
            config: savedConfig,
            candidates: [
              {
                idHint: pluginId,
                source: path.join(pluginDir, "index.cjs"),
                rootDir: pluginDir,
                origin: "global",
              },
            ],
          },
        );
        await state.writeConfig({
          plugins: { slots: { memory: "none" } },
          agents: {
            defaults: {
              workspace: state.workspaceDir,
              skipBootstrap: true,
              skills: [],
            },
          },
        });
        await state.writeAuthProfiles({
          version: 1,
          profiles: {
            [profileId]: {
              type: "api_key",
              provider: providerId,
              key: "synthetic-auth-activate-key",
              setup: {
                replacement: false,
                modelRef,
                configJson: JSON.stringify(savedConfig),
                pluginId,
                agentRuntimeId: pluginId,
              },
            },
          },
        });
        const env: NodeJS.ProcessEnv = {
          ...state.env,
          AUTH_ACTIVATE_LIFECYCLE_PATH: lifecyclePath,
          OPENCLAW_NO_RESPAWN: "1",
          OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
          NODE_DISABLE_COMPILE_CACHE: "1",
        };
        let childPid: number | undefined;
        const result = await runCliProcessChild({
          nodeArgs: [...entrypoint, "models", "auth", "activate", profileId],
          env,
          interact: async (child) => {
            childPid = child.pid;
            child.stdin.end();
            await assertNaturalExitAfterOutput(
              child,
              "Sign-in verified and saved. The running connection could not be confirmed.",
            );
          },
        });
        expect(result.code, result.stderr).toBe(0);
        expect(result.signal).toBeNull();
        expect(result.stdout).toContain(`Inference verified: ${modelRef}`);
        const lifecycle = (await fs.readFile(lifecyclePath, "utf8"))
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as { phase: string; pid: number });
        const phases = lifecycle.map(({ phase }) => phase);
        expect(phases).toContain("attempt");
        expect(phases).toContain("dispose");
        expect(phases.filter((phase) => phase === "register").length).toBeGreaterThanOrEqual(2);
        expect(childPid).toBeDefined();
        expect(new Set(lifecycle.map(({ pid }) => pid))).toEqual(new Set([childPid!]));
      },
    );
  });
});

describe("offline local mutation custody", () => {
  const initializeRepository = useManagedWorktreeTestRepository();
  afterEach(() => vi.unstubAllEnvs());

  it.skipIf(process.platform === "win32")(
    "retains offline CLI custody through its POSIX setup hook while Gateway startup races",
    async () => {
      const root = roots.make("openclaw-local-owner-offline-");
      const env = environment(root);
      vi.stubEnv("HOME", root);
      vi.stubEnv("USERPROFILE", root);
      const repo = await initializeRepository(root);
      await fs.writeFile(env.OPENCLAW_CONFIG_PATH!, "{}\n");
      const setupReady = createDeferred<Socket>();
      const reservation = await reserveTestPortListener({
        offsets: [0],
        createListener: createServer,
      });
      let setupSocket: Socket | undefined;
      reservation.listener.once("connection", (socket) => {
        setupSocket = socket;
        socket.once("data", () => setupReady.resolve(socket));
      });
      const setup = path.join(repo, ".openclaw", "worktree-setup.sh");
      await fs.mkdir(path.dirname(setup), { recursive: true });
      await fs.writeFile(
        setup,
        `#!/usr/bin/env node
const socket = require("node:net").connect(${reservation.claim.port}, "127.0.0.1", () => socket.write("ready"));
socket.on("data", () => {
  require("node:fs").writeFileSync("setup-proof.txt", "local setup complete\\n");
  socket.end();
});
`,
      );
      await fs.chmod(setup, 0o755);
      try {
        const result = await runCliProcessChild({
          nodeArgs: [
            ...entrypoint,
            "worktrees",
            "create",
            repo,
            "--name",
            "offline",
            "--base-ref",
            "HEAD",
            "--json",
          ],
          env,
          interact: async (child) => {
            const socket = await awaitGateBeforeSettlement(
              setupReady.promise,
              once(child, "exit"),
              "CLI exited before setup hook",
            );
            await expect(
              acquireGatewayLock({ env, allowInTests: true, timeoutMs: 0 }),
            ).rejects.toThrow("state ownership");
            socket.write("release");
            child.stdin.end();
          },
        });
        expect(result.code, result.stderr).toBe(0);
        const record: ManagedWorktreeRecord = JSON.parse(result.stdout);
        expect(await fs.readFile(path.join(record.path, "README.md"), "utf8")).toBe("base\n");
        expect(await fs.readFile(path.join(record.path, "setup-proof.txt"), "utf8")).toBe(
          "local setup complete\n",
        );
        expect(record.path).toContain(path.join(env.OPENCLAW_STATE_DIR!, "worktrees"));
        await expect(fs.access(resolveGatewayLockPaths(env).ownerLockPath)).rejects.toMatchObject({
          code: "ENOENT",
        });
        const successor = await acquireGatewayLock({ env, allowInTests: true, timeoutMs: 0 });
        expect(successor).not.toBeNull();
        await successor?.release();
      } finally {
        setupSocket?.destroy();
        await reservation.releaseListener();
        await reservation.claim.release();
      }
    },
  );

  it.each(process.platform === "win32" ? [false] : [false, true])(
    "holds Gateway startup through accepted work and database close; signal=%s",
    async (interrupt) => {
      const root = roots.make("openclaw-local-owner-settlement-");
      const env = environment(root);
      vi.stubEnv("HOME", root);
      vi.stubEnv("USERPROFILE", root);
      const repo = await initializeRepository(root);
      await fs.writeFile(env.OPENCLAW_CONFIG_PATH!, "{}\n");
      const pending = createDeferred();
      const interrupted = createDeferred();
      const result = await runCliProcessChild({
        nodeArgs: [...entrypoint, "settlement", repo],
        env,
        onStdout: (text) => {
          if (text.includes("pending:false")) {
            pending.resolve();
          }
          if (text.includes("interrupted")) {
            interrupted.resolve();
          }
        },
        interact: async (child) => {
          const exited = once(child, "exit");
          await awaitGateBeforeSettlement(
            pending.promise,
            exited,
            "CLI exited before retained continuation",
          );
          await expect(
            acquireGatewayLock({ env, allowInTests: true, timeoutMs: 0 }),
          ).rejects.toThrow("state ownership");
          if (interrupt) {
            child.kill("SIGTERM");
            await awaitGateBeforeSettlement(
              interrupted.promise,
              exited,
              "CLI exited before signal settlement",
            );
            await expect(
              acquireGatewayLock({ env, allowInTests: true, timeoutMs: 0 }),
            ).rejects.toThrow("state ownership");
          }
          child.stdin.end("continue\n");
        },
      });
      expect(result.code, result.stderr).toBe(interrupt ? 143 : 0);
      expect(JSON.parse(await fs.readFile(path.join(root, "settlement.json"), "utf8"))).toEqual({
        databaseOpen: false,
      });
      expect(await git(repo, "branch", "--list", "openclaw/settled")).toBe("+ openclaw/settled");
      await expect(fs.access(resolveGatewayLockPaths(env).ownerLockPath)).rejects.toMatchObject({
        code: "ENOENT",
      });
      const successor = await acquireGatewayLock({
        env,
        port: 18789,
        allowInTests: true,
        timeoutMs: 0,
      });
      expect(successor).not.toBeNull();
      expect(await readActiveGatewayLockIdentity({ env, requireInspection: true })).toMatchObject({
        pid: process.pid,
      });
      await successor?.release();
    },
  );
});
