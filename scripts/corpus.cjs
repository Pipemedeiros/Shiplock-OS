/* Reproducible local evaluation. Acquisition is explicit; evaluation cannot network. */
/* eslint-disable @typescript-eslint/no-require-imports -- This Node-only CJS runner installs a TypeScript require hook without adding a runtime dependency. */
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { Readable, Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const { execFileSync } = require("node:child_process");
const Module = require("node:module");
const root = path.resolve(__dirname, "..");
// SHIPLOCK_CORPUS selects another manifest (Q23 docs/CORPUS-2.json); the 7-repository baseline stays the default.
const manifestPath = process.env.SHIPLOCK_CORPUS ? path.resolve(root, process.env.SHIPLOCK_CORPUS) : path.join(root, "docs/CORPUS.json");
const manifestBytes = fs.readFileSync(manifestPath);
const manifest = JSON.parse(manifestBytes);
const cache = path.join(root, ".cache/shiplock-corpus");
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
// A planted pin (R1) reads its base repository's archive: archiveId names it.
const archivePath = (pin) => path.join(cache, `${pin.archiveId ?? pin.id}.tar.gz`);
const endpoint = (pin) => `https://api.github.com/repos/${pin.repository}/tarball/${pin.commit}`;

async function fileHash(file) {
  const hash = crypto.createHash("sha256");
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

function validateManifest() {
  if (manifest.version !== 1 || !manifest.prediction || !Array.isArray(manifest.repositories)) {
    throw new Error("Unsupported or incomplete corpus manifest");
  }
  const ids = new Set();
  for (const pin of manifest.repositories) {
    if (!/^[a-z0-9-]+$/.test(pin.id) || ids.has(pin.id) ||
        !/^[\w.-]+\/[\w.-]+$/.test(pin.repository) ||
        !/^[a-f0-9]{40}$/.test(pin.commit) || !/^[a-f0-9]{64}$/.test(pin.archiveSha256)) {
      throw new Error(`Invalid or duplicate corpus pin: ${pin.id}`);
    }
    ids.add(pin.id);
  }
}

async function acquire(pin) {
  const destination = archivePath(pin);
  if (fs.existsSync(destination) && await fileHash(destination) === pin.archiveSha256) {
    console.log(`${pin.id}: verified cache`);
    return;
  }
  const temporary = `${destination}.${crypto.randomUUID()}.partial`;
  try {
    const response = await fetch(endpoint(pin), {
      headers: { "User-Agent": "ShipLock-local-corpus", Accept: "application/vnd.github+json" },
      signal: AbortSignal.timeout(300000),
    });
    if (!response.ok || !response.body) throw new Error(`Acquisition HTTP ${response.status}`);
    let bytes = 0;
    const bound = new Transform({
      transform(chunk, _encoding, callback) {
        bytes += chunk.length;
        callback(bytes > 512 * 1024 * 1024 ? new Error("Archive exceeds 512 MiB acquisition limit") : null, chunk);
      },
    });
    await pipeline(Readable.fromWeb(response.body), bound, fs.createWriteStream(temporary, { flags: "wx" }));
    const digest = await fileHash(temporary);
    if (digest !== pin.archiveSha256) {
      throw new Error(`Archive checksum mismatch: expected ${pin.archiveSha256}, received ${digest}`);
    }
    // Do not replace an unverified existing archive; retain it for diagnosis.
    if (fs.existsSync(destination)) throw new Error("Existing archive checksum failed; move it aside before reacquiring");
    await fsp.rename(temporary, destination);
    console.log(`${pin.id}: acquired and verified (${bytes} bytes)`);
  } finally {
    await fsp.unlink(temporary).catch((error) => { if (error.code !== "ENOENT") throw error; });
  }
}

function loadProductModules() {
  const ts = require("typescript");
  const loaded = {};
  const resolve = Module._resolveFilename;
  Module._resolveFilename = function (request, parent, ...rest) {
    return resolve.call(this, request.startsWith("@/") ? path.join(root, request.slice(2)) : request, parent, ...rest);
  };
  require.extensions[".ts"] = (module, file) => {
    const source = fs.readFileSync(file, "utf8");
    if (file.startsWith(path.join(root, "lib") + path.sep) || file === path.join(root, "scripts", "corpusModel.ts")) loaded[path.relative(root, file)] = sha(source);
    module._compile(ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    }).outputText, file);
  };
  return {
    loaded,
    ...require("../lib/deep/repoArchive.ts"),
    ...require("../lib/graph/routeInventory.ts"),
    ...require("../lib/graph/applicationEntries.ts"),
    ...require("../lib/agent/attack.ts"),
    ...require("../lib/agent/attackGuard.ts"),
    ...require("../lib/agent/stack.ts"),
    ...require("../lib/agent/schema.ts"),
    ...require("../lib/agent/domain.ts"),
    ...require("../lib/agent/crossTenantNotes.ts"),
    ...require("../lib/agent/possessionGate.ts"),
    ...require("../lib/agent/unassessed.ts"),
    ...require("../lib/agent/evaluation.ts"),
    ...require("../lib/agent/deterministicFindings.ts"),
    ...require("../lib/agent/findings.ts"),
    ...require("../lib/eval/benchmark.ts"),
    ...require("../lib/agent/confirmed.ts"),
    ...require("../lib/agent/signIn.ts"),
    ...require("../lib/eval/plant.ts"),
    // The harness's own model calls; the product makes none (Felipe, 2026-10-01).
    ...require("./corpusModel.ts"),
  };
}

// The deterministic stage shared by evaluate and holdout: routes, reasoning
// order and the candidates ShipLock would ask a model about. No model call.
async function analyzePin(product, pin) {
  global.fetch = async (url) => {
    if (url !== endpoint(pin)) throw new Error(`Network forbidden during evaluation: ${url}`);
    return new Response(Readable.toWeb(fs.createReadStream(archivePath(pin))));
  };
  const archive = await product.fetchRepoArchive("offline-placeholder", pin.repository, pin.commit);
  // R1: a planted pin removes one recorded control before anything reads the
  // files; applyPlant refuses unless the bytes sit at the recorded offset.
  if (pin.plant) {
    const file = archive.files.find((f) => f.path === pin.plant.file);
    if (!file) throw new Error(`${pin.id}: planted file ${pin.plant.file} is not in the archive`);
    file.content = product.applyPlant(file.content, pin.plant);
  }
  // Route handlers, entry server actions and tRPC procedures, exactly as the
  // audit sees them (7E-3, 7G-2).
  const { routes } = product.applicationEntries(archive.files);
  const stack = product.detectStack(archive.files);
  const tables = [...new Set([...product.extractTables(archive.files), ...routes.flatMap((route) => route.tables)])].sort();
  const domain = product.inferDomain(tables, routes, product.extractColumns(archive.files));
  const files = new Map(archive.files.map((file) => [file.path, file]));
  const notes = product.crossTenantNotes(routes, files);
  const noted = new Set(notes.map((note) => note.path));
  const reasoned = routes.filter((route) => !noted.has(route.path));
  const prompted = product.rankRoutes(reasoned.filter((route) => route.tables.length > 0), new Set(domain.sensitive))
    .slice(0, product.MAX_PROMPT_ROUTES);
  // Model candidates come from the prompted routes; permission gaps are
  // rendered deterministically from every route (as in the audit), so the
  // reasoning budget must not hide them here either (7C, 7E-3).
  const modelCandidates = prompted.filter((route) => route.identityReadable &&
    route.ownershipReadable && route.dataReadable && route.machineGateReadable && route.serviceRoleReadable &&
    ((!route.authenticated && !route.machineGated) || !route.ownershipFiltered));
  const candidates = [...new Set([...modelCandidates, ...routes.filter((route) => (route.permissionGaps?.length ?? 0) > 0)])];
  return { archive, routes, stack, tables, domain, files, notes, reasoned, prompted, candidates };
}

function blockNetwork() {
  for (const protocol of [require("node:http"), require("node:https")]) {
    protocol.request = protocol.get = () => { throw new Error("Network forbidden during evaluation"); };
  }
}

// Step 7B: the deterministic candidate stage against independent held-out
// labels (docs/evaluation/labels-*-holdout-*.json), keyed by route file.
async function holdout(labelsFile) {
  blockNetwork();
  const labelDoc = JSON.parse(fs.readFileSync(path.resolve(root, labelsFile), "utf8"));
  const pin = manifest.repositories.find((candidate) => candidate.repository === labelDoc.labels[0].repository);
  if (!pin) throw new Error("Labels name a repository that is not pinned in docs/CORPUS.json");
  if (await fileHash(archivePath(pin)) !== pin.archiveSha256 || pin.archiveSha256 !== labelDoc.archive.sha256) {
    throw new Error(`${pin.id}: archive checksum does not match the labels' archive`);
  }
  const product = loadProductModules();
  const { routes, prompted, candidates } = await analyzePin(product, pin);
  // Route files are repository-relative, the same form the labels use.
  const byFile = (set) => new Set(set.map((route) => route.file));
  const observed = byFile(routes), promptedFiles = byFile(prompted), candidateFiles = byFile(candidates);
  const rows = labelDoc.labels.map((label) => ({ route: label.route, verdict: label.verdict,
    observed: observed.has(label.route), prompted: promptedFiles.has(label.route), candidate: candidateFiles.has(label.route) }));
  const of = (verdict) => rows.filter((row) => row.verdict === verdict);
  const rate = (hit, all) => all.length ? hit.length / all.length : null;
  const positives = of("vulnerable"), negatives = of("benign");
  const result = {
    experiment: "held-out-candidate-stage", capturedAt: new Date().toISOString(),
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    labels: labelsFile, thresholds: "docs/evaluation/thresholds-corpus-a-holdout-2026-09.json",
    repository: pin.repository, commit: pin.commit, modelCalls: 0, paidApiSpendUsd: 0,
    routesInInventory: routes.length, promptedRoutes: prompted.length, candidateRoutes: candidates.length,
    positives: positives.length, negatives: negatives.length, contested: of("contested").length,
    candidateRecall: rate(positives.filter((row) => row.candidate), positives),
    falseCandidateRate: rate(negatives.filter((row) => row.candidate), negatives),
    unobserved: rows.filter((row) => !row.observed).map((row) => row.route),
    rows,
  };
  console.log(JSON.stringify(result, null, 2));
}

async function evaluate() {
  // Block SDK transports too, not merely fetch. Offline tests must remain free
  // even if a future imported helper unexpectedly attempts a model request.
  blockNetwork();
  // Verify EVERY pin before generating outputs. Missing/corrupt archives fail
  // loudly and never produce a smaller corpus that appears more accurate.
  for (const pin of manifest.repositories) {
    if (!fs.existsSync(archivePath(pin))) throw new Error(`${pin.id}: archive missing; run npm run corpus:acquire`);
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
  }
  const product = loadProductModules();
  const output = path.join(root, "docs/evaluation/runs", `${manifest.experiment}-${crypto.randomUUID()}`);
  await fsp.mkdir(output, { recursive: true });
  const write = (name, value) => fsp.writeFile(path.join(output, name), JSON.stringify(value, null, 2) + "\n", { flag: "wx" });
  const records = [];
  for (const pin of manifest.repositories) {
    // The production loader itself consumes the cached archive (analyzePin);
    // all other fetches throw; the runner never invokes proposeAttacks.
    const { archive, routes, stack, tables, domain, files, notes, reasoned, prompted, candidates } = await analyzePin(product, pin);
    const gates = product.possessionGates(routes, files);
    const labels = manifest.labels.filter((label) => label.repository === pin.id);
    const proposals = labels.map((label) => ({
      entry: label.route, attackClass: "missing_authentication", title: "Historical missing-identity proposal replay",
      consequence: "An anonymous caller may reach data without an identity check.",
      citedFiles: routes.filter((route) => route.path === label.route).map((route) => route.file),
    }));
    const replay = product.guardHypotheses(proposals, {
      entries: new Set(routes.map((route) => route.path)), files: new Set(files.keys()), tables: new Set(tables),
      routes: new Map(routes.map((route) => [route.path, route])), possessionGates: gates,
    });
    const input = { routes: reasoned, stack, tables, domain, files: [...files.keys()], liveFacts: [] };
    const userPrompt = product.buildPrompt(input);
    const sourceDigests = archive.files.map((file) => ({ path: file.path, sha256: sha(file.content) }));
    const record = {
      id: pin.id, repository: pin.repository, commit: pin.commit, acquisitionEndpoint: endpoint(pin),
      archiveSha256: pin.archiveSha256,
      filesRead: archive.files.length, bytesRead: archive.bytesRead, skipped: archive.skipped, truncated: archive.truncated,
      inputDigest: sha(JSON.stringify(sourceDigests)), userPromptSha256: sha(userPrompt),
      routes: routes.length, prompted: prompted.length, candidates: candidates.length, notes: notes.length,
      unassessed: product.summarizeUnassessed(routes),
      evaluation: product.summarizeEvaluation(labels, new Set(routes.map((route) => route.path)),
        new Set(candidates.map((route) => route.path)), new Set(replay.admitted.map((proposal) => proposal.entry)),
        new Set(replay.admitted.filter((proposal) => proposal.attackClass === "possession_gated").map((proposal) => proposal.entry))),
      modelCalls: 0, rawModelResponses: [],
      plannedModel: product.PROPOSE_MODEL,
      plannedMaxTokens: product.maxTokensFor(reasoned.filter((route) => route.tables.length > 0).length) + product.THINKING_HEADROOM,
      temperature: 0,
    };
    await write(`${pin.id}-inputs.json`, { input, sourceDigests, routes, prompted, candidates, notes, gates: [...gates], labels });
    await write(`${pin.id}-replay.json`, { syntheticProposals: proposals, guardedReplay: replay });
    await fsp.writeFile(path.join(output, `${pin.id}-prompt.txt`), userPrompt, { flag: "wx" });
    records.push(record);
    console.log(JSON.stringify(record));
  }
  const summary = {
    experiment: manifest.experiment, capturedAt: new Date().toISOString(),
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    dirtyTree: execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim().length > 0,
    manifestSha256: sha(manifestBytes), packageLockSha256: sha(fs.readFileSync(path.join(root, "package-lock.json"))),
    runtime: process.version, runnerSha256: sha(fs.readFileSync(__filename)), toolSources: product.loaded, prediction: manifest.prediction,
    labelProvenance: manifest.labelProvenance, systemPromptSha256: sha(product.SYSTEM),
    plannedModel: product.PROPOSE_MODEL,
    modelCalls: 0, paidApiSpendUsd: 0, repositories: records,
  };
  await write("summary.json", summary);
  await write("manifest.json", manifest);
  await fsp.writeFile(path.join(output, "system-prompt.txt"), product.SYSTEM, { flag: "wx" });
  console.log(`Artifacts: ${output}`);
}

// Q11: worst-case dollars for one paid pass, decided before any call. Input is
// bounded at chars / 2 tokens (above any real tokenizer rate for code) and
// output at each call's own max_tokens, so the real bill cannot exceed it.
function paidPlan(plans, prices, maxUsd) {
  const priceFor = (model) => prices[model] ?? prices[model.replace(/-\d{8}$/, "")];
  const unpriced = [...new Set(plans.filter((p) => !priceFor(p.model)).map((p) => p.model))];
  if (unpriced.length) return { ok: false, reason: `no --price for ${unpriced.join(", ")}`, rows: [], worstCaseUsd: null };
  const rows = plans.map((p) => {
    const price = priceFor(p.model);
    const inputTokens = Math.ceil(p.inputChars / 2);
    return { ...p, inputTokensBound: inputTokens, price, worstCaseUsd: (inputTokens * price.input + p.maxTokens * price.output) / 1_000_000 };
  });
  const worstCaseUsd = rows.reduce((sum, r) => sum + r.worstCaseUsd, 0);
  if (!(worstCaseUsd <= maxUsd)) {
    return { ok: false, reason: `worst case $${worstCaseUsd.toFixed(4)} exceeds the cap $${maxUsd}`, rows, worstCaseUsd };
  }
  return { ok: true, rows, worstCaseUsd };
}

// Q11: one paid pass of the audit's own model call (proposeAttacks) per pinned
// repository, on ShipLock's key, only with Felipe's --confirm-paid and a
// --max-usd cap the worst case fits. `evaluate` and `holdout` stay offline.
async function paid(args) {
  if (!args.includes("--confirm-paid")) throw new Error("Refusing: paid mode spends ShipLock's API key. Re-run with --confirm-paid.");
  const capIndex = args.indexOf("--max-usd");
  const maxUsd = capIndex >= 0 ? Number(args[capIndex + 1]) : NaN;
  if (!(maxUsd > 0)) throw new Error("Refusing: give a dollar cap with --max-usd <amount>.");
  const valueOf = (flag) => (args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined);
  const modelOverride = valueOf("--model");
  const only = valueOf("--only");
  const pins = manifest.repositories.filter((pin) => !only || pin.id === only);
  if (pins.length === 0) throw new Error(`Refusing: --only ${only} names no pinned repository.`);
  const { parsePrices } = await import("./cost-report.mjs");
  const prices = parsePrices(args.flatMap((arg, i) => (args[i - 1] === "--price" ? [arg] : [])));
  if (!process.env.ANTHROPIC_API_KEY) {
    const line = fs.existsSync(path.join(root, ".env.local"))
      ? fs.readFileSync(path.join(root, ".env.local"), "utf8").split("\n").find((l) => l.startsWith("ANTHROPIC_API_KEY=")) : null;
    if (line) process.env.ANTHROPIC_API_KEY = line.slice("ANTHROPIC_API_KEY=".length).trim().replace(/^["']|["']$/g, "");
  }
  if (!process.env.ANTHROPIC_API_KEY) throw new Error("Refusing: no ANTHROPIC_API_KEY in the environment or .env.local.");
  for (const pin of pins) {
    if (!fs.existsSync(archivePath(pin))) throw new Error(`${pin.id}: archive missing; run npm run corpus:acquire`);
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
  }
  const product = loadProductModules();
  const realFetch = global.fetch;
  // Same input the audit builds (lib/agent/audit.ts), all offline.
  const inputs = [];
  for (const pin of pins) {
    const { routes, stack, tables, domain, files, reasoned } = await analyzePin(product, pin);
    const input = { routes: reasoned, stack, tables, domain, files: [...files.keys()], liveFacts: [],
      possessionGates: product.possessionGates(routes, files), ...(modelOverride ? { model: modelOverride } : {}) };
    const interesting = reasoned.filter((route) => route.tables.length > 0).length;
    inputs.push({ pin, input, interesting,
      model: modelOverride ?? product.PROPOSE_MODEL,
      inputChars: product.SYSTEM.length + product.buildPrompt(input).length,
      maxTokens: product.maxTokensFor(interesting) + (modelOverride ? 0 : product.THINKING_HEADROOM) });
  }
  const callable = inputs.filter((i) => i.interesting > 0);
  const plan = paidPlan(callable.map((i) => ({ id: i.pin.id, model: i.model, inputChars: i.inputChars, maxTokens: i.maxTokens })), prices, maxUsd);
  console.log(JSON.stringify({ plan: plan.rows.map((r) => ({ id: r.id, model: r.model, inputTokensBound: r.inputTokensBound,
    maxTokens: r.maxTokens, worstCaseUsd: r.worstCaseUsd })), worstCaseUsd: plan.worstCaseUsd, capUsd: maxUsd }));
  if (!plan.ok) throw new Error(`Refusing, nothing spent: ${plan.reason}`);

  const output = path.join(root, "docs/evaluation/runs", `${manifest.experiment}-paid-${crypto.randomUUID()}`);
  await fsp.mkdir(output, { recursive: true });
  const write = (name, value) => fsp.writeFile(path.join(output, name), JSON.stringify(value, null, 2) + "\n", { flag: "wx" });
  const records = [];
  let spentUsd = 0;
  for (const item of callable) {
    global.fetch = realFetch; // analyzePin pins fetch to the cached archive; the model call needs the real one
    const outcome = await product.proposeAttacks(item.input);
    const row = plan.rows.find((r) => r.id === item.pin.id);
    const usage = outcome.usage ?? null;
    const usd = usage ? (usage.input_tokens * row.price.input + usage.output_tokens * row.price.output) / 1_000_000 : 0;
    spentUsd += usd;
    const record = { id: item.pin.id, repository: item.pin.repository, commit: item.pin.commit, model: outcome.model,
      skipped: outcome.skipped, skipReason: outcome.skipReason ?? null, truncated: outcome.truncated ?? false,
      parseFailed: outcome.parseFailed ?? false, usage, usd, admitted: outcome.admitted.length, rejected: outcome.rejected.length,
      unassessed: outcome.unassessed.length };
    await write(`${item.pin.id}-paid.json`, { record, outcome });
    records.push(record);
    console.log(JSON.stringify(record));
  }
  const summary = {
    experiment: `${manifest.experiment}-paid`, capturedAt: new Date().toISOString(),
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    dirtyTree: execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim().length > 0,
    systemPromptSha256: sha(product.SYSTEM), modelOverride: modelOverride ?? null, only: only ?? null,
    capUsd: maxUsd, worstCaseUsd: plan.worstCaseUsd,
    modelCalls: records.filter((r) => !r.skipped).length, paidApiSpendUsd: Math.round(spentUsd * 1e6) / 1e6, repositories: records,
  };
  await write("summary.json", summary);
  console.log(`Spent $${summary.paidApiSpendUsd} of a $${maxUsd} cap. Artifacts: ${output}`);
}

// P1: the skeptical verifier over a paid run's admitted hypotheses, scored
// against a blind label file when one is given. Paid: same refusals as paid().
async function verify(runDir, args) {
  if (!args.includes("--confirm-paid")) throw new Error("Refusing: verify spends ShipLock's API key. Re-run with --confirm-paid.");
  const valueOf = (flag) => (args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined);
  const maxUsd = Number(valueOf("--max-usd"));
  if (!(maxUsd > 0)) throw new Error("Refusing: give a dollar cap with --max-usd <amount>.");
  const { parsePrices } = await import("./cost-report.mjs");
  const prices = parsePrices(args.flatMap((arg, i) => (args[i - 1] === "--price" ? [arg] : [])));
  const dir = path.resolve(root, runDir);
  const runs = fs.readdirSync(dir).filter((n) => n.endsWith("-paid.json")).sort()
    .map((n) => JSON.parse(fs.readFileSync(path.join(dir, n), "utf8"))).filter((r) => r.outcome.admitted.length > 0);
  if (runs.length === 0) throw new Error(`Refusing: no admitted hypotheses in ${runDir}`);
  if (!process.env.ANTHROPIC_API_KEY) {
    const line = fs.existsSync(path.join(root, ".env.local"))
      ? fs.readFileSync(path.join(root, ".env.local"), "utf8").split("\n").find((l) => l.startsWith("ANTHROPIC_API_KEY=")) : null;
    if (line) process.env.ANTHROPIC_API_KEY = line.slice("ANTHROPIC_API_KEY=".length).trim().replace(/^["']|["']$/g, "");
  }
  if (!process.env.ANTHROPIC_API_KEY) throw new Error("Refusing: no ANTHROPIC_API_KEY in the environment or .env.local.");
  const realFetch = global.fetch;
  const product = { ...loadProductModules(), ...require("../lib/agent/verify.ts") };
  const model = valueOf("--model") ?? product.VERIFY_MODEL;
  const maxTokens = Number(valueOf("--max-tokens") ?? 12000);
  const budgetChars = Number(valueOf("--budget-chars") ?? 100000);
  const batches = [];
  for (const run of runs) {
    const pin = manifest.repositories.find((p) => p.id === run.record.id);
    if (!pin || pin.commit !== run.record.commit) throw new Error(`Refusing: ${run.record.id} ran on another commit`);
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
    const { routes, files } = await analyzePin(product, pin);
    const contents = new Map([...files].map(([p, f]) => [p, typeof f === "string" ? f : f.content]));
    const items = run.outcome.admitted.map((h, i) => ({ id: `${pin.id}#${i}`, entry: h.entry, attackClass: h.attackClass, title: h.title,
      consequence: h.consequence, citedFiles: h.citedFiles ?? [], handlerFile: routes.find((r) => r.path === h.entry)?.file }));
    for (let i = 0; i < items.length; i += product.VERIFY_BATCH) batches.push({ pin, items: items.slice(i, i + product.VERIFY_BATCH), files: contents });
  }
  const plan = paidPlan(batches.map((b, i) => ({ id: `${b.pin.id}/${i}`, model, maxTokens,
    inputChars: product.VERIFY_SYSTEM.length + budgetChars + 4000 })), prices, maxUsd);
  console.log(JSON.stringify({ calls: batches.length, worstCaseUsd: plan.worstCaseUsd, capUsd: maxUsd }));
  if (!plan.ok) throw new Error(`Refusing, nothing spent: ${plan.reason}`);
  const output = path.join(dir, `verify-${crypto.randomUUID()}`);
  await fsp.mkdir(output, { recursive: true });
  const verdicts = [];
  let spentUsd = 0;
  for (const [i, batch] of batches.entries()) {
    global.fetch = realFetch; // analyzePin pins fetch to the cached archive; the model call needs the real one
    const outcome = await product.verifyAttacks({ items: batch.items, files: batch.files, model, maxTokens, budgetChars });
    const row = plan.rows[i];
    const usd = outcome.usage ? (outcome.usage.input_tokens * row.price.input + outcome.usage.output_tokens * row.price.output) / 1_000_000 : 0;
    spentUsd += usd;
    for (const v of outcome.verdicts) verdicts.push({ repository: batch.pin.repository, pin: batch.pin.id, ...v,
      entry: batch.items.find((it) => it.id === v.id)?.entry });
    console.log(JSON.stringify({ batch: row.id, skipped: outcome.skipped, skipReason: outcome.skipReason ?? null, usd: Math.round(usd * 1e4) / 1e4,
      confirmed: outcome.verdicts.filter((v) => v.verdict === "confirmed").length, omitted: outcome.omitted.length }));
  }
  const labelsPath = valueOf("--labels");
  let score = null;
  if (labelsPath) {
    const labels = JSON.parse(fs.readFileSync(path.resolve(root, labelsPath), "utf8")).statements.filter((s) => s.inPost !== false);
    const both = (s, key, value) => s.labelerA?.[key] === value && s.labelerB?.[key] === value;
    const queue = new Map();
    for (const s of labels) { const k = `${s.repository}|${s.entry}`; queue.set(k, [...(queue.get(k) ?? []), s]); }
    for (const v of verdicts) { const list = queue.get(`${v.repository}|${v.entry}`) ?? []; v.label = list.shift() ?? null; }
    const judged = verdicts.filter((v) => v.label);
    const tally = (set) => ({ n: set.length, realAgreed: set.filter((v) => both(v.label, "vulnerability", "yes")).length,
      strict: set.filter((v) => both(v.label, "vulnerability", "yes") && both(v.label, "accurate", "yes")).length });
    score = { matched: judged.length, of: verdicts.length, all: tally(judged),
      confirmed: tally(judged.filter((v) => v.verdict === "confirmed")),
      refuted: tally(judged.filter((v) => v.verdict === "refuted")), unverified: tally(judged.filter((v) => v.verdict === "unverified")) };
  }
  const summary = { experiment: "P1-verify", capturedAt: new Date().toISOString(), runDir, model, maxTokens, budgetChars,
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    systemPromptSha256: sha(product.VERIFY_SYSTEM), calls: batches.length, capUsd: maxUsd, worstCaseUsd: plan.worstCaseUsd,
    paidApiSpendUsd: Math.round(spentUsd * 1e6) / 1e6, score };
  await fsp.writeFile(path.join(output, "verdicts.json"), JSON.stringify(verdicts, null, 2) + "\n");
  await fsp.writeFile(path.join(output, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
  console.log(JSON.stringify(summary, null, 1));
}

// Q23: what a customer would read for a paid run's admitted hypotheses,
// rendered offline through the audit's own buildFindings with the same gates
// (possession and Q21 one-id) the audit passes. Free; the labelers read this.
async function render(runDir) {
  blockNetwork();
  const dir = path.resolve(root, runDir);
  const outcomes = fs.existsSync(dir) ? fs.readdirSync(dir).filter((name) => name.endsWith("-paid.json")).sort() : [];
  if (outcomes.length === 0) throw new Error(`Refusing: no paid run outcomes in ${runDir}`);
  const runs = outcomes.map((name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")));
  for (const { record } of runs) {
    const pin = manifest.repositories.find((candidate) => candidate.id === record.id);
    if (!pin || pin.commit !== record.commit) throw new Error(`Refusing: ${record.id} ran on ${record.commit}, not the pinned commit`);
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
  }
  const product = { ...loadProductModules(), ...require("../lib/agent/findings.ts") };
  const statements = [];
  // Q24: the paid run's admitted hypotheses are guarded again against TODAY's
  // route facts, so a fact change is replayed for free; what the guard now
  // refuses or leaves unjudged is counted, never silently dropped.
  const reguard = { admittedAtRun: 0, admittedNow: 0, rejectedNow: [], unassessedNow: [] };
  for (const { record, outcome } of runs) {
    if (!outcome.admitted?.length) continue;
    const pin = manifest.repositories.find((candidate) => candidate.id === record.id);
    const { routes, stack, files, tables } = await analyzePin(product, pin);
    const guarded = product.guardHypotheses(outcome.admitted, {
      entries: new Set(routes.map((route) => route.path)), files: new Set(files.keys()), tables: new Set(tables),
      facts: new Set(), routes: new Map(routes.map((route) => [route.path, route])),
      possessionGates: product.possessionGates(routes, files) });
    reguard.admittedAtRun += outcome.admitted.length;
    reguard.admittedNow += guarded.admitted.length;
    for (const r of guarded.rejected) reguard.rejectedNow.push({ repository: pin.repository, entry: r.hypothesis?.entry, reason: r.reason });
    for (const u of guarded.unassessed) reguard.unassessedNow.push({ repository: pin.repository, entry: u });
    const findings = product.buildFindings({ admitted: guarded.admitted, deterministic: [], routes, stack,
      repositoryId: pin.id, hasDatabase: false, liveFacts: [],
      possessionGates: product.possessionGates(routes, files), oneIdAccess: product.oneIdAccess(routes, files) });
    for (const finding of findings) {
      statements.push({ repository: pin.repository, commit: pin.commit, id: finding.id, entry: finding.entry,
        file: finding.file, attackClass: finding.attackClass, severity: finding.severity, confidence: finding.confidence,
        title: finding.title, consequence: finding.consequence, claims: finding.claims });
    }
  }
  const out = path.join(dir, `rendered-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
  await fsp.writeFile(out, JSON.stringify({ experiment: `${manifest.experiment}-rendered`, capturedAt: new Date().toISOString(),
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    dirtyTree: execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim().length > 0,
    modelCalls: 0, reguard, statements }, null, 2) + "\n", { flag: "wx" });
  console.log(`${statements.length} statements; re-guarded ${reguard.admittedNow} of ${reguard.admittedAtRun}. Artifacts: ${out}`);
}

// Plan item 4 (2026-10-06): what the audit shows a founder when no agent has
// answered. The production assembly, offline: deterministic checks plus
// buildFindings with nothing admitted. No model, network blocked.
async function shown() {
  blockNetwork();
  for (const pin of manifest.repositories) {
    if (!fs.existsSync(archivePath(pin))) throw new Error(`${pin.id}: archive missing; run npm run corpus:acquire`);
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
  }
  const product = loadProductModules();
  const records = [];
  for (const pin of manifest.repositories) {
    const { archive, routes, stack, files } = await analyzePin(product, pin);
    const findings = product.buildFindings({
      admitted: [], deterministic: product.deterministicFindings(archive.files.map((f) => ({ path: f.path, content: f.content }))),
      routes, stack, repositoryId: pin.id, hasDatabase: false, liveFacts: [],
      possessionGates: product.possessionGates(routes, files), oneIdAccess: product.oneIdAccess(routes, files),
    });
    records.push({ id: pin.id, repository: pin.repository, commit: pin.commit, routes: routes.length, truncated: archive.truncated,
      status: findings.some((f) => f.severity === "CRITICAL") ? "exposed" : findings.some((f) => f.severity === "WARNING") ? "at_risk" : "no_open_issues",
      findings: findings.map((f) => ({ id: f.id, severity: f.severity, attackClass: f.attackClass, title: f.title, consequence: f.consequence, file: f.file, entry: f.entry })) });
  }
  const out = path.join(root, "docs/evaluation/runs", `${manifest.experiment}-shown-${crypto.randomUUID()}`);
  await fsp.mkdir(out, { recursive: true });
  await fsp.writeFile(path.join(out, "shown.json"), JSON.stringify({ manifest: path.relative(root, manifestPath), modules: product.loaded, records }, null, 2) + "\n", { flag: "wx" });
  const count = (s) => records.reduce((n, r) => n + r.findings.filter((f) => f.severity === s).length, 0);
  console.log(`${records.length} repositories; ${count("CRITICAL")} critical, ${count("WARNING")} warning, ${count("INFO")} info; exposed ${records.filter((r) => r.status === "exposed").length}, at risk ${records.filter((r) => r.status === "at_risk").length}. Artifact: ${out}`);
}

// Plan item H (Felipe 2026-10-06: launch only at 90%+ precision). A label pack
// is what two blind labelers read: every finding that sets a status, its
// statement, repository, commit and file, never the product's severity or
// class, in a fixed order shuffled by an opaque key.
function labelPack(records) {
  const pack = [];
  for (const r of records) {
    for (const f of r.findings) {
      if (f.severity === "INFO") continue;
      // A1: the gate measures what sets the status, confirmed issues only.
      if (f.confirmed === false) continue;
      pack.push({ key: sha(`${r.id}\u0000${f.id}`).slice(0, 12), repo: r.id, id: f.id, repository: r.repository, commit: r.commit,
        file: f.file ?? null, statement: f.consequence ? `${f.title}. ${f.consequence}` : f.title });
    }
  }
  return pack.sort((a, b) => a.key.localeCompare(b.key));
}

/** Each labeler's answers, keyed by packet, merged into labels. */
function mergeAnswers(pack, answerSets) {
  const byKey = new Map(pack.map((p) => [p.key, { repo: p.repo, id: p.id, labelers: [] }]));
  const unknownKeys = [];
  for (const answers of answerSets) {
    for (const a of answers) {
      const label = byKey.get(a.key);
      if (!label) { unknownKeys.push(a.key); continue; }
      label.labelers.push({ accurate: a.accurate, real: a.real });
    }
  }
  return { labels: [...byKey.values()], unknownKeys };
}

function benchInputs(shownFile, packFile, answerFiles) {
  const shownDoc = JSON.parse(fs.readFileSync(path.resolve(root, shownFile), "utf8"));
  const pack = JSON.parse(fs.readFileSync(path.resolve(root, packFile), "utf8"));
  const answers = answerFiles.map((file) => JSON.parse(fs.readFileSync(path.resolve(root, file), "utf8")).answers);
  const { labels, unknownKeys } = mergeAnswers(pack.packets, answers);
  const findings = shownDoc.records.flatMap((r) => r.findings.filter((f) => f.confirmed !== false)
    .map((f) => ({ repo: r.id, id: f.id, severity: f.severity, attackClass: f.attackClass })));
  return { findings, labels, unknownKeys };
}

function releaseGate() {
  const g = JSON.parse(fs.readFileSync(path.join(root, "docs/evaluation/thresholds-release-2026-10-14.json"), "utf8")).gates;
  return { observedPrecisionAtLeast: g.statusSetting.observedPrecisionAtLeast, lowerBound95AtLeast: g.statusSetting.lowerBound95AtLeast,
    minimumLabeledFindings: g.statusSetting.minimumLabeledFindings, repositoriesWithCorrectStatusAtLeast: g.statusCorrectness.repositoriesWithCorrectStatusAtLeast };
}

// A8's running total, recomputed from the batch run directories (each with
// shown.json, pack.json and answers-*.json), in the order given. Re-check
// directories go after the batch they re-read; a finding counts once.
async function gateTotal(outArg, dirs) {
  const product = loadProductModules();
  const batches = dirs.map((dir) => {
    const answers = fs.readdirSync(dir).filter((n) => /^answers-.+\.json$/.test(n)).sort().map((n) => path.join(dir, n));
    if (answers.length < 2) throw new Error(`${dir}: needs two labelers' answers`);
    const { findings, labels, unknownKeys } = benchInputs(path.join(dir, "shown.json"), path.join(dir, "pack.json"), answers);
    if (unknownKeys.length) throw new Error(`${dir}: answers for keys not in the pack: ${unknownKeys.join(", ")}`);
    return { name: dir, findings, labels };
  });
  const { findings, labels, duplicates } = product.combineBatches(batches);
  const report = product.scoreBenchmark(findings, labels, releaseGate());
  await fsp.writeFile(path.resolve(root, outArg), JSON.stringify({ batches: dirs, thresholds: "docs/evaluation/thresholds-release-2026-10-14.json",
    duplicates, report }, null, 2) + "\n", { flag: "wx" });
  const s = report.statusSetting;
  console.log(`Running total over ${dirs.length} runs: ${s.labeled} labeled, ${s.tp} true, precision ${s.precision === null ? "unavailable" : (s.precision * 100).toFixed(1) + "%"}`
    + `${s.lower95 === null ? "" : `, lower bound ${(s.lower95 * 100).toFixed(1)}%`}; status right on ${report.statusCorrect.correct} of ${report.statusCorrect.judged}; `
    + `${duplicates.length} duplicate findings folded. Gate: ${report.gate.result}. Report: ${outArg}`);
}

async function bench(shownFile, packFile, answerFiles) {
  const { findings, labels, unknownKeys } = benchInputs(shownFile, packFile, answerFiles);
  const gate = releaseGate();
  const product = loadProductModules();
  const report = product.scoreBenchmark(findings, labels, gate);
  const out = path.join(path.dirname(path.resolve(root, shownFile)), `bench-${crypto.randomUUID()}.json`);
  await fsp.writeFile(out, JSON.stringify({ shown: shownFile, pack: packFile, answers: answerFiles, thresholds: "docs/evaluation/thresholds-release-2026-10-14.json",
    unknownKeys, report }, null, 2) + "\n", { flag: "wx" });
  const s = report.statusSetting;
  console.log(`Status-setting findings: ${s.n}; labeled ${s.labeled}; true ${s.tp}; precision ${s.precision === null ? "unavailable" : (s.precision * 100).toFixed(1) + "%"}` +
    `${s.lower95 === null ? "" : `, lower bound ${(s.lower95 * 100).toFixed(1)}%`}; provisional (every available labeler said yes) ${s.provisionalTp}. Status right on ${report.statusCorrect.correct} of ${report.statusCorrect.judged} repositories.`);
  console.log(`Gate: ${report.gate.result}${report.gate.reasons.length ? ` (${report.gate.reasons.join("; ")})` : ""}. Report: ${out}`);
}

// Plan item H, option B (Felipe 2026-10-06): the customer agent's path,
// offline. agent-tasks writes each repository's reasoning brief (production's
// own, lib/eval/agentPath.ts); the customer's agent (Claude Code here, on the
// customer's subscription; never a ShipLock key) writes {"hypotheses": [...]}
// beside it; agent-admit guards the answer and writes verification briefs with
// the listed sources; the agent writes {"verdicts": [...]}; agent-shown admits
// quoted proof and writes a shown.json that label-pack and bench read.
function loadAgentModules() {
  // lib/env parses at import; the harness never calls Supabase or GitHub.
  const dummy = { NEXT_PUBLIC_SUPABASE_URL: "https://offline.supabase.co", NEXT_PUBLIC_SUPABASE_ANON_KEY: "offline", SUPABASE_SERVICE_ROLE_KEY: "offline",
    RESEND_API_KEY: "offline", RESEND_FROM_EMAIL: "offline@example.com", NEXT_PUBLIC_APP_URL: "https://offline.example",
    ENCRYPTION_KEY: "0123456789abcdef0123456789abcdef", CRON_SECRET: "offline" };
  for (const [k, v] of Object.entries(dummy)) if (!process.env[k]) process.env[k] = v;
  return { ...loadProductModules(), ...require("../lib/intelligence/reasoning.ts"), ...require("../lib/eval/agentPath.ts") };
}
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const numbered = (content) => content.split("\n").map((line, i) => `${String(i + 1).padStart(5)}  ${line}`).join("\n");

async function agentContexts(product) {
  const out = [];
  for (const pin of manifest.repositories) {
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
    const { archive, routes, stack, tables, domain, files, reasoned } = await analyzePin(product, pin);
    // Production pages the route inventory (lib/intelligence/reasoning.ts);
    // the harness asks the agent about every page, as production does.
    const pages = product.reasoningPages({ routes: reasoned, stack, tables, domain, files: [...files.keys()], liveFacts: [],
      possessionGates: product.possessionGates(routes, files), oneIdAccess: product.oneIdAccess(routes, files), hasDatabase: false,
      openByDesign: product.openByDesign({ routes, stack, tables, archive }) });
    out.push({ pin, pages, files });
  }
  return out;
}
// Page 1 keeps the repository id as its name, so one-page runs read as before.
const pageName = (id, index) => (index === 0 ? id : `${id}.p${index + 1}`);

async function agentTasks(outArg) {
  blockNetwork();
  const product = loadAgentModules();
  const dir = outArg ? path.resolve(root, outArg) : path.join(root, "docs/evaluation/runs", `${manifest.experiment}-agent-${crypto.randomUUID()}`);
  await fsp.mkdir(dir, { recursive: true });
  let written = 0;
  const skipped = [];
  for (const { pin, pages } of await agentContexts(product)) {
    if (pages.length === 0) { skipped.push(pin.id); continue; }
    for (const [index, context] of pages.entries()) {
      const name = pageName(pin.id, index);
      await fsp.writeFile(path.join(dir, `${name}.reason.json`), JSON.stringify({ repo: pin.id, page: index + 1, pages: pages.length,
        repository: pin.repository, commit: pin.commit, answerFile: `${name}.reason.answer.json`,
        answerShape: '{"hypotheses": [ ...objects as the brief asks... ]}', brief: product.reasoningBrief(context) }, null, 2) + "\n", { flag: "wx" });
      written++;
    }
  }
  await fsp.writeFile(path.join(dir, "manifest.json"), JSON.stringify({ manifest: path.relative(root, manifestPath), head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    reasoningTasks: written, skipped }, null, 2) + "\n");
  console.log(`${written} reasoning tasks, ${skipped.length} repositories with nothing to ask. Directory: ${dir}`);
}

async function agentAdmit(dirArg) {
  blockNetwork();
  const product = loadAgentModules();
  const dir = path.resolve(root, dirArg);
  let tasks = 0, admitted = 0, rejected = 0, answered = 0;
  for (const { pin, pages, files } of await agentContexts(product)) {
    for (const [index, context] of pages.entries()) {
      const page = pageName(pin.id, index);
      const answerFile = path.join(dir, `${page}.reason.answer.json`);
      if (!fs.existsSync(answerFile)) continue;
      answered++;
      const guard = product.guardAnswer(context, readJson(answerFile).hypotheses);
      admitted += guard.admitted.length; rejected += guard.rejected.length;
      const contentOf = (p) => { const f = files.get(p); return f === undefined ? null : (typeof f === "string" ? f : f.content); };
      for (const t of product.verificationTasks(context, guard.admitted, contentOf)) {
        const name = `${page}.verify-${t.index}`;
        await fsp.writeFile(path.join(dir, `${name}.json`), JSON.stringify({ repo: pin.id, answerFile: `${name}.answer.json`,
          answerShape: '{"verdicts": [ ...objects as the brief asks, one per claim id... ]}', brief: t.brief,
          sources: t.sources.map((s) => ({ path: s.path, numbered: numbered(s.content) })) }, null, 2) + "\n");
        await fsp.writeFile(path.join(dir, `${name}.state.json`), JSON.stringify({ page: index, hypotheses: t.hypotheses, items: t.items,
          sources: t.sources.map((s) => s.path) }, null, 2) + "\n");
        tasks++;
      }
      await fsp.writeFile(path.join(dir, `${page}.guard.json`), JSON.stringify({ admitted: guard.admitted.length, rejected: guard.rejected.length,
        reasons: guard.rejected.map((r) => r.reason).slice(0, 40), unassessed: guard.unassessed.slice(0, 40) }, null, 2) + "\n");
    }
  }
  console.log(`${answered} answers read; ${admitted} hypotheses admitted, ${rejected} rejected; ${tasks} verification tasks written.`);
}

async function agentShown(dirArg) {
  blockNetwork();
  const product = loadAgentModules();
  const dir = path.resolve(root, dirArg);
  const records = [];
  const totals = { confirmed: 0, refuted: 0, unverified: 0, agentFindings: 0, unanswered: 0 };
  for (const { pin, pages, files } of await agentContexts(product)) {
    const { archive, routes, stack, tables } = await analyzePin(product, pin);
    const deterministic = product.buildFindings({
      admitted: [], deterministic: product.deterministicFindings(archive.files.map((f) => ({ path: f.path, content: f.content }))),
      routes, stack, repositoryId: pin.id, hasDatabase: false, liveFacts: [],
      possessionGates: product.possessionGates(routes, files), oneIdAccess: product.oneIdAccess(routes, files),
      openByDesign: product.openByDesign({ routes, stack, tables, archive }),
    });
    const agent = [];
    const ownVerify = new RegExp(`^${pin.id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\.p\\d+)?\\.verify-\\d+\\.state\\.json$`);
    for (const name of fs.readdirSync(dir).filter((n) => ownVerify.test(n))) {
      const base = name.slice(0, -".state.json".length);
      const answer = path.join(dir, `${base}.answer.json`);
      if (!fs.existsSync(answer)) { totals.unanswered++; continue; }
      const state = readJson(path.join(dir, name));
      const context = pages[state.page ?? 0];
      const sources = state.sources.map((p) => { const f = files.get(p); return { path: p, content: typeof f === "string" ? f : f.content }; });
      const result = product.admitVerified(context, { hypotheses: state.hypotheses, items: state.items, sources }, readJson(answer).verdicts ?? [], pin.id);
      totals.confirmed += result.confirmed; totals.refuted += result.refuted; totals.unverified += result.unverified;
      agent.push(...result.findings);
    }
    totals.agentFindings += agent.length;
    const seen = new Set();
    const findings = [...agent, ...deterministic].filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
    records.push({ id: pin.id, repository: pin.repository, commit: pin.commit, routes: routes.length,
      status: findings.some((f) => f.severity === "CRITICAL") ? "exposed" : findings.some((f) => f.severity === "WARNING") ? "at_risk" : "no_open_issues",
      findings: findings.map((f) => ({ id: f.id, severity: f.severity, attackClass: f.attackClass, title: f.title, consequence: f.consequence,
        file: f.file, entry: f.entry, source: agent.includes(f) ? "agent" : "deterministic", confirmed: product.isConfirmed(f) })) });
  }
  await fsp.writeFile(path.join(dir, "shown.json"), JSON.stringify({ manifest: path.relative(root, manifestPath), path: "agent", totals, records }, null, 2) + "\n");
  console.log(`Agent path: ${totals.confirmed} confirmed, ${totals.refuted} refuted, ${totals.unverified} unverified, ${totals.unanswered} unanswered; `
    + `${totals.agentFindings} agent findings. ${path.join(dir, "shown.json")}`);
}

// R1, recall on planted holes (Felipe 2026-10-07: "how are we measuring
// recall?"). `plant <out.json> [max]` writes a manifest of planted pins from
// the current manifest: per repository at most one route the audit reads as
// signed in (and, for an owner filter, scoped to the caller), with one control
// removed by lib/eval/plant.ts. The selection is mechanical and recorded before
// any agent runs. `plant-extract <dir>` writes each planted copy for the agent
// to read; `recall <run dir>` scores the run's shown.json against the plants.
const ROUTE_HANDLER_FILE = /(^|\/)app\/(.*\/)?route\.[jt]sx?$|(^|\/)pages\/api\//;
async function plant(outArg, maxArg) {
  blockNetwork();
  const product = loadProductModules();
  const max = Number(maxArg ?? 60);
  const pins = [];
  let examined = 0;
  for (const pin of manifest.repositories) {
    if (pins.length >= max) break;
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
    examined++;
    const { routes, files } = await analyzePin(product, pin);
    const byFile = new Map();
    for (const r of routes) byFile.set(r.file, [...(byFile.get(r.file) ?? []), r]);
    const options = [];
    for (const [file, rs] of [...byFile].sort(([a], [b]) => a.localeCompare(b))) {
      const r = rs[0];
      if (rs.length !== 1 || !ROUTE_HANDLER_FILE.test(file) || r.tables.length === 0 || !r.authenticated) continue;
      const f = files.get(file);
      const content = typeof f === "string" ? f : f.content;
      for (const p of product.findPlants(content, { defaultExportHandles: /(^|\/)pages\/api\//.test(file) })) {
        if (p.operator === "remove_owner_scope" && !r.ownershipFiltered) continue;
        options.push({ route: r, file, plant: p });
      }
    }
    if (!options.length) continue;
    // Alternate the preferred operator by plant count, so both kinds of hole are measured.
    const prefer = pins.length % 2 === 0 ? "remove_auth_guard" : "remove_owner_scope";
    const chosen = options.find((o) => o.plant.operator === prefer) ?? options[0];
    const planted = { ...pin, id: `${pin.id}--plant`, archiveId: pin.id,
      plant: { file: chosen.file, entry: chosen.route.path, operator: chosen.plant.operator, attackClasses: chosen.plant.attackClasses,
        start: chosen.plant.start, removed: chosen.plant.removed } };
    // What the deterministic layer reads once the control is gone (stage 1).
    const after = (await analyzePin(product, planted)).routes.find((r) => r.path === chosen.route.path);
    planted.plant.factsAfter = after ? { authenticated: after.authenticated, ownershipFiltered: after.ownershipFiltered,
      identityReadable: after.identityReadable, ownershipReadable: after.ownershipReadable } : null;
    pins.push(planted);
  }
  const out = { version: 1, experiment: `${manifest.experiment}-plants`,
    prediction: `Recorded before any agent run on these plants (${new Date().toISOString().slice(0, 10)}): no prediction of recall.`,
    scope: "Recall on planted holes: one control removed per repository from a route the audit read as signed in (and, for an owner filter, scoped to the caller). Ground truth is the plant itself.",
    selection: { rule: "lib/eval/plant.ts findPlants over route-handler files with exactly one route, tables read, authenticated (and ownershipFiltered for an owner filter); files in path order; first plant of the preferred operator, alternating by plant count; at most one per repository; manifest order.",
      base: path.relative(root, manifestPath), examined, max,
      head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim() },
    repositories: pins };
  await fsp.writeFile(path.resolve(root, outArg), JSON.stringify(out, null, 1) + "\n", { flag: "wx" });
  console.log(`${pins.length} plants from ${examined} repositories examined. ${path.resolve(root, outArg)}`);
}

async function plantExtract(dirArg) {
  const product = loadProductModules();
  const dir = path.resolve(root, dirArg);
  for (const pin of manifest.repositories.filter((p) => p.plant)) {
    const dest = path.join(dir, pin.id);
    if (fs.existsSync(dest)) throw new Error(`${dest} exists; extract into an empty directory`);
    await fsp.mkdir(dest, { recursive: true });
    execFileSync("tar", ["-xzf", archivePath(pin), "-C", dest, "--strip-components=1"]);
    const target = path.join(dest, pin.plant.file);
    if (!path.resolve(target).startsWith(dest + path.sep)) throw new Error(`${pin.id}: planted path leaves the extract`);
    await fsp.writeFile(target, product.applyPlant(await fsp.readFile(target, "utf8"), pin.plant));
  }
  console.log(`Planted copies written under ${dir}`);
}

async function recall(dirArg) {
  const product = loadProductModules();
  const dir = path.resolve(root, dirArg);
  const shown = readJson(path.join(dir, "shown.json"));
  const rows = [];
  for (const pin of manifest.repositories.filter((p) => p.plant)) {
    const record = shown.records.find((r) => r.id === pin.id);
    const at = (record?.findings ?? []).filter((f) => f.entry === pin.plant.entry);
    // Every page of this repository's reasoning (pageName): page 1 is the id.
    const esc = pin.id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const names = fs.readdirSync(dir);
    const briefs = names.filter((n) => new RegExp(`^${esc}(\\.p\\d+)?\\.reason\\.json$`).test(n));
    const proposed = names.filter((n) => new RegExp(`^${esc}(\\.p\\d+)?\\.reason\\.answer\\.json$`).test(n))
      .flatMap((n) => readJson(path.join(dir, n)).hypotheses ?? []).filter((h) => h?.entry === pin.plant.entry).length;
    const admitted = names.filter((n) => new RegExp(`^${esc}(\\.p\\d+)?\\.verify-\\d+\\.state\\.json$`).test(n))
      .flatMap((n) => readJson(path.join(dir, n)).hypotheses).filter((h) => h.entry === pin.plant.entry).length;
    const facts = pin.plant.factsAfter;
    // The facts this run's brief carried (they move with the product code);
    // the frozen factsAfter only when no brief exists.
    const line = briefs.flatMap((n) => String(readJson(path.join(dir, n)).brief?.prompt ?? "").split("\n"))
      .find((l) => l.startsWith(`${pin.plant.entry} `));
    const factsFlag = line !== undefined
      ? (pin.plant.operator === "remove_auth_guard" ? / id=anonymous | unrefused=/.test(line) : / scope=unscoped /.test(line))
      : Boolean(facts && (pin.plant.operator === "remove_auth_guard" ? !facts.authenticated && facts.identityReadable
        : !facts.ownershipFiltered && facts.ownershipReadable));
    rows.push({ id: pin.id, entry: pin.plant.entry, operator: pin.plant.operator, factsFlag,
      reasoningTask: briefs.length > 0, inBrief: line !== undefined, proposed, admitted,
      shown: at.length > 0,
      caught: at.some((f) => f.confirmed && pin.plant.attackClasses.includes(f.attackClass)),
      caughtOtherClass: at.some((f) => f.confirmed && !pin.plant.attackClasses.includes(f.attackClass)) });
  }
  const n = rows.length, k = rows.filter((r) => r.caught).length;
  const by = (op) => { const rs = rows.filter((r) => r.operator === op); const c = rs.filter((r) => r.caught).length;
    return { plants: rs.length, caught: c, recall: rs.length ? c / rs.length : null }; };
  const report = { experiment: "planted-recall", head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    manifest: path.relative(root, manifestPath), plants: n, caught: k, recall: n ? k / n : null,
    lower95: n ? product.clopperPearsonLower(k, n) : null,
    funnel: { factsFlag: rows.filter((r) => r.factsFlag).length, reasoningTask: rows.filter((r) => r.reasoningTask).length,
      inBrief: rows.filter((r) => r.inBrief).length,
      proposed: rows.filter((r) => r.proposed > 0).length, admitted: rows.filter((r) => r.admitted > 0).length,
      shownAtEntry: rows.filter((r) => r.shown).length, confirmed: k },
    byOperator: { remove_auth_guard: by("remove_auth_guard"), remove_owner_scope: by("remove_owner_scope") }, rows };
  const out = path.join(dir, `recall-${crypto.randomUUID()}.json`);
  await fsp.writeFile(out, JSON.stringify(report, null, 2) + "\n", { flag: "wx" });
  console.log(`Planted recall: ${k} of ${n}${n ? ` (${(k / n * 100).toFixed(1)}%, lower bound ${(report.lower95 * 100).toFixed(1)}%)` : " (unavailable)"}. `
    + `Funnel: facts flag ${report.funnel.factsFlag}, reasoning task ${report.funnel.reasoningTask}, proposed ${report.funnel.proposed}, admitted ${report.funnel.admitted}, shown ${report.funnel.shownAtEntry}, confirmed ${k}. ${out}`);
}

// W1: every repository in the manifest, unpacked for the blind labelers.
// Release attempt 5's batch script unpacked only repositories with reasoning
// tasks, so a packet from the deterministic checks alone pointed at no code.
async function extractAll(outArg) {
  const out = path.resolve(root, outArg);
  let extracted = 0;
  for (const pin of manifest.repositories) {
    if (await fileHash(archivePath(pin)) !== pin.archiveSha256) throw new Error(`${pin.id}: archive checksum mismatch`);
    const dir = path.join(out, pin.id);
    if (fs.existsSync(dir)) continue;
    await fsp.mkdir(dir, { recursive: true });
    execFileSync("tar", ["-xzf", archivePath(pin), "-C", dir, "--strip-components", "1"]);
    extracted++;
  }
  console.log(`${extracted} repositories extracted, ${manifest.repositories.length - extracted} already present, under ${out}`);
}

// P7: JEV as a second judge, measured on labeled findings. Paid (Felipe's
// TypeSafe key, TYPESAFE_API_KEY) and refused without --confirm-paid and a
// --max-usd cap. Evidence per packet is what the labelers start from: the
// cited file, root middleware, the Prisma schema and the README, read from
// an --extract directory of unpacked repositories.
async function jevMeasure(args) {
  if (!args.includes("--confirm-paid")) throw new Error("Refusing: JEV is a paid call on Felipe's key. Re-run with --confirm-paid.");
  const cap = Number(args[args.indexOf("--max-usd") + 1]);
  if (!(cap > 0) || !args.includes("--max-usd")) throw new Error("Refusing: give a dollar cap with --max-usd <amount>.");
  const extract = args.includes("--extract") ? path.resolve(root, args[args.indexOf("--extract") + 1]) : null;
  if (!extract) throw new Error("Give --extract <dir> holding the unpacked repositories.");
  const key = process.env.TYPESAFE_API_KEY;
  if (!key) throw new Error("TYPESAFE_API_KEY is not set in this shell.");
  const flags = new Set(["--confirm-paid", "--max-usd", "--extract"]);
  const rest = args.filter((a, i) => !flags.has(a) && !flags.has(args[i - 1]));
  const [outArg, ...dirs] = rest;
  if (!outArg || dirs.length === 0) throw new Error("Usage: corpus.cjs jev <out.json> --extract <dir> --confirm-paid --max-usd <n> <run dir>...");
  loadProductModules(); // installs the .ts loader the two requires below need
  const { jevRequest, jevVerdict } = require("../lib/judge/jev.ts");
  const { systemOne, JEV_USD_PER_INPUT_TOKEN } = require("./jevClient.ts");
  const read = (repo, rel) => { try { return fs.readFileSync(path.join(extract, repo, rel), "utf8"); } catch { return null; } };
  const rows = [];
  let spent = 0;
  for (const dir of dirs) {
    const pack = readJson(path.join(dir, "pack.json")).packets;
    const answers = fs.readdirSync(dir).filter((n) => /^answers-.+\.json$/.test(n)).sort().map((n) => readJson(path.join(dir, n)).answers);
    const { labels } = mergeAnswers(pack, answers);
    for (const [i, packet] of pack.entries()) {
      const vs = labels[i].labelers;
      const yes = vs.filter((v) => v.accurate === "yes" && v.real === "yes").length;
      const label = vs.length >= 3 ? yes >= 2 : vs.length >= 2 && yes === vs.length;
      const files = [packet.file, "middleware.ts", "src/middleware.ts", "proxy.ts", "src/proxy.ts", "prisma/schema.prisma", "README.md"]
        .filter((p, j, all) => p && all.indexOf(p) === j).map((p) => ({ path: p, content: read(packet.repo, p) })).filter((f) => f.content !== null);
      const request = jevRequest({ statement: packet.statement, files });
      const estimate = Buffer.byteLength(JSON.stringify(request)) / 3 * JEV_USD_PER_INPUT_TOKEN;
      if (spent + estimate > cap) { console.log(`Cap reached at $${spent.toFixed(4)}; stopping.`); break; }
      try {
        const response = await systemOne(request, key);
        spent += (response.usage?.input_tokens ?? 0) * JEV_USD_PER_INPUT_TOKEN;
        rows.push({ run: path.basename(dir), key: packet.key, label, ...jevVerdict(response, { keepAtLeast: 0.5 }) });
      } catch (err) {
        rows.push({ run: path.basename(dir), key: packet.key, label, error: err instanceof Error ? err.message : "failed" });
      }
    }
  }
  const scored = rows.filter((r) => typeof r.p === "number");
  const tp = scored.filter((r) => r.label), fp = scored.filter((r) => !r.label);
  let auc = null;
  if (tp.length && fp.length) { let s = 0; for (const a of tp) for (const b of fp) s += a.p > b.p ? 1 : a.p === b.p ? 0.5 : 0; auc = s / (tp.length * fp.length); }
  const cuts = Object.fromEntries([0.3, 0.5, 0.7].map((t) => {
    const kt = tp.filter((r) => r.p >= t).length, kf = fp.filter((r) => r.p >= t).length;
    return [t, { trueKept: kt, falseKept: kf, precision: kt + kf ? kt / (kt + kf) : null }];
  }));
  await fsp.writeFile(path.resolve(root, outArg), JSON.stringify({ experiment: "jev-judge", runs: dirs, spentUsd: spent, scored: scored.length,
    errors: rows.length - scored.length, true: tp.length, false: fp.length, auc, cuts, rows }, null, 2) + "\n", { flag: "wx" });
  console.log(`JEV judged ${scored.length} (${rows.length - scored.length} errors), AUC ${auc === null ? "unavailable" : auc.toFixed(3)}, spent $${spent.toFixed(4)}. ${outArg}`);
}

async function main() {
  validateManifest();
  if (process.argv[2] === "acquire") {
    await fsp.mkdir(cache, { recursive: true });
    // Two downloads at once, not seven, to bound disk/network pressure.
    for (let index = 0; index < manifest.repositories.length; index += 2) {
      await Promise.all(manifest.repositories.slice(index, index + 2).map(acquire));
    }
  } else if (process.argv[2] === "shown") {
    await shown();
  } else if (process.argv[2] === "gate-total" && process.argv[3] && process.argv[4]) {
    await gateTotal(process.argv[3], process.argv.slice(4));
  } else if (process.argv[2] === "jev") {
    await jevMeasure(process.argv.slice(3));
  } else if (process.argv[2] === "extract" && process.argv[3]) {
    await extractAll(process.argv[3]);
  } else if (process.argv[2] === "agent-tasks") {
    await agentTasks(process.argv[3]);
  } else if (process.argv[2] === "agent-admit" && process.argv[3]) {
    await agentAdmit(process.argv[3]);
  } else if (process.argv[2] === "agent-shown" && process.argv[3]) {
    await agentShown(process.argv[3]);
  } else if (process.argv[2] === "label-pack" && process.argv[3] && process.argv[4]) {
    const records = JSON.parse(fs.readFileSync(path.resolve(root, process.argv[3]), "utf8")).records;
    await fsp.writeFile(path.resolve(root, process.argv[4]), JSON.stringify({ shown: process.argv[3], packets: labelPack(records) }, null, 2) + "\n", { flag: "wx" });
    console.log(`${labelPack(records).length} packets written to ${process.argv[4]}`);
  } else if (process.argv[2] === "bench" && process.argv[5]) {
    await bench(process.argv[3], process.argv[4], process.argv.slice(5));
  } else if (process.argv[2] === "plant" && process.argv[3]) {
    await plant(process.argv[3], process.argv[4]);
  } else if (process.argv[2] === "plant-extract" && process.argv[3]) {
    await plantExtract(process.argv[3]);
  } else if (process.argv[2] === "recall" && process.argv[3]) {
    await recall(process.argv[3]);
  } else if (process.argv[2] === "evaluate") {
    await evaluate();
  } else if (process.argv[2] === "holdout" && process.argv[3]) {
    await holdout(process.argv[3]);
  } else if (process.argv[2] === "paid") {
    await paid(process.argv.slice(3));
  } else if (process.argv[2] === "verify" && process.argv[3]) {
    await verify(process.argv[3], process.argv.slice(4));
  } else if (process.argv[2] === "render" && process.argv[3]) {
    await render(process.argv[3]);
  } else {
    throw new Error("Usage: node scripts/corpus.cjs acquire|evaluate|shown|extract <dir>|agent-tasks [dir]|agent-admit <dir>|agent-shown <dir>|label-pack <shown.json> <pack.json>|plant <out.json> [max]|plant-extract <dir>|recall <run dir>|gate-total <out.json> <run dir>...|bench <shown.json> <pack.json> <answers.json>...|holdout <labels.json>|render <paid run dir>|paid --confirm-paid --max-usd <usd> --price <model=in,out>... [--model claude-sonnet-5] [--only <id>]");
  }
}

module.exports = { paidPlan, loadProductModules, analyzePin, manifest, labelPack, mergeAnswers };
if (require.main === module) main().catch((error) => { console.error(process.env.CORPUS_DEBUG ? error.stack : error.message); process.exitCode = 1; });
