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
const manifestPath = path.join(root, "docs/CORPUS.json");
const manifestBytes = fs.readFileSync(manifestPath);
const manifest = JSON.parse(manifestBytes);
const cache = path.join(root, ".cache/shiplock-corpus");
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const archivePath = (pin) => path.join(cache, `${pin.id}.tar.gz`);
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
    if (file.startsWith(path.join(root, "lib") + path.sep)) loaded[path.relative(root, file)] = sha(source);
    module._compile(ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    }).outputText, file);
  };
  return {
    loaded,
    ...require("../lib/deep/repoArchive.ts"),
    ...require("../lib/graph/routeInventory.ts"),
    ...require("../lib/agent/attack.ts"),
    ...require("../lib/agent/attackGuard.ts"),
    ...require("../lib/agent/stack.ts"),
    ...require("../lib/agent/schema.ts"),
    ...require("../lib/agent/domain.ts"),
    ...require("../lib/agent/crossTenantNotes.ts"),
    ...require("../lib/agent/possessionGate.ts"),
    ...require("../lib/agent/unassessed.ts"),
    ...require("../lib/agent/evaluation.ts"),
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
  const routes = product.collectRoutes(archive.files);
  const stack = product.detectStack(archive.files);
  const tables = [...new Set([...product.extractTables(archive.files), ...routes.flatMap((route) => route.tables)])].sort();
  const domain = product.inferDomain(tables, routes, product.extractColumns(archive.files));
  const files = new Map(archive.files.map((file) => [file.path, file]));
  const notes = product.crossTenantNotes(routes, files);
  const noted = new Set(notes.map((note) => note.path));
  const reasoned = routes.filter((route) => !noted.has(route.path));
  const prompted = product.rankRoutes(reasoned.filter((route) => route.tables.length > 0), new Set(domain.sensitive))
    .slice(0, product.MAX_PROMPT_ROUTES);
  const candidates = prompted.filter((route) => (route.permissionGaps?.length ?? 0) > 0 || (route.identityReadable &&
    route.ownershipReadable && route.dataReadable && route.machineGateReadable && route.serviceRoleReadable &&
    ((!route.authenticated && !route.machineGated) || !route.ownershipFiltered)));
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
      plannedModel: reasoned.filter((route) => route.tables.length > 0).length >= product.SONNET_ENTRY_THRESHOLD
        ? product.SONNET : product.HAIKU,
      plannedMaxTokens: product.maxTokensFor(reasoned.filter((route) => route.tables.length > 0).length),
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
    plannedModels: { haiku: product.HAIKU, sonnet: product.SONNET, threshold: product.SONNET_ENTRY_THRESHOLD },
    modelCalls: 0, paidApiSpendUsd: 0, repositories: records,
  };
  await write("summary.json", summary);
  await write("manifest.json", manifest);
  await fsp.writeFile(path.join(output, "system-prompt.txt"), product.SYSTEM, { flag: "wx" });
  console.log(`Artifacts: ${output}`);
}

async function main() {
  validateManifest();
  if (process.argv[2] === "acquire") {
    await fsp.mkdir(cache, { recursive: true });
    // Two downloads at once, not seven, to bound disk/network pressure.
    for (let index = 0; index < manifest.repositories.length; index += 2) {
      await Promise.all(manifest.repositories.slice(index, index + 2).map(acquire));
    }
  } else if (process.argv[2] === "evaluate") {
    await evaluate();
  } else if (process.argv[2] === "holdout" && process.argv[3]) {
    await holdout(process.argv[3]);
  } else {
    throw new Error("Usage: node scripts/corpus.cjs acquire|evaluate|holdout <labels.json>");
  }
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
