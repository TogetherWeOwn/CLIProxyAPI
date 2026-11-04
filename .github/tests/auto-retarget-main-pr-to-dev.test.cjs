const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const vm = require("node:vm");

const root = path.resolve(__dirname, "../..");
const workflow = fs.readFileSync(path.join(root, ".github/workflows/auto-retarget-main-pr-to-dev.yml"), "utf8");
const script = workflow.split("          script: |\n")[1]
  .split("\n").map((line) => line.slice(12)).join("\n");
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const retarget = new AsyncFunction("context", "github", "core", "process", script);
const jobCondition = workflow.match(/    if: >-\n([\s\S]*?)    runs-on:/)[1].trim();
const bindingCheck = workflow.match(/        run: \|\n([\s\S]*?)\n      - name:/)[1]
  .split("\n").map((line) => line.slice(10)).join("\n");

function pullRequest() {
  return {
    number: 42,
    state: "open",
    base: { ref: "main", repo: { full_name: "TogetherWeOwn/CLIProxyAPI" } },
    head: { ref: "fix/example", sha: "a".repeat(40), repo: { full_name: "contributor/fork" } },
  };
}

async function run({ mutate = () => {}, liveMutate = () => {}, action = "opened",
  actor = "contributor", appSlug = "pr-automation", failAt } = {}) {
  const pr = pullRequest();
  mutate(pr);
  const current = structuredClone(pr);
  liveMutate(current);
  const calls = [];
  const failures = [];
  const warnings = [];
  const api = (name, result) => async (args) => {
    calls.push({ name, args });
    if (failAt === name) throw new Error("sensitive upstream error");
    return result;
  };
  await retarget(
    { repo: { owner: "TogetherWeOwn", repo: "CLIProxyAPI" }, actor,
      payload: { action, pull_request: pr } },
    { rest: {
      pulls: { get: api("get", { data: current }), update: api("update", {}) },
      issues: { createComment: api("comment", {}) },
    } },
    { info() {}, setFailed: (message) => failures.push(message), warning: (message) => warnings.push(message) },
    { env: { APP_SLUG: appSlug } },
  );
  return { calls, failures, warnings };
}

for (const action of ["opened", "reopened", "edited"]) {
  test(`${action}: updates an existing eligible PR and comments with the App client`, async () => {
    const result = await run({ action });
    assert.deepEqual(result.calls.map(({ name }) => name), ["get", "update", "comment"]);
    assert.deepEqual(result.calls[1].args, {
      owner: "TogetherWeOwn", repo: "CLIProxyAPI", pull_number: 42, base: "dev",
    });
    assert.equal(result.calls[2].args.issue_number, 42);
    assert.match(result.calls[2].args.body, /automatically changed to `dev`/);
    assert.deepEqual(result.failures, []);
  });
}

for (const [name, mutate] of [
  ["already dev", (pr) => { pr.base.ref = "dev"; }],
  ["other base", (pr) => { pr.base.ref = "release"; }],
  ["dev promotion", (pr) => { pr.head.ref = "dev"; }],
  ["closed PR", (pr) => { pr.state = "closed"; }],
]) {
  test(`${name}: no API operations`, async () => {
    const result = await run({ mutate });
    assert.deepEqual(result.calls, []);
    assert.deepEqual(result.failures, []);
  });
}

for (const [name, mutate] of [
  ["foreign base repository", (pr) => { pr.base.repo.full_name = "other/repository"; }],
  ["missing base", (pr) => { delete pr.base; }],
  ["missing head", (pr) => { delete pr.head; }],
  ["invalid number", (pr) => { pr.number = "42; unexpected"; }],
  ["zero number", (pr) => { pr.number = 0; }],
  ["invalid SHA", (pr) => { pr.head.sha = "not-a-sha"; }],
]) {
  test(`${name}: validation fails before API operations`, async () => {
    const result = await run({ mutate });
    assert.deepEqual(result.calls, []);
    assert.deepEqual(result.failures, ["Invalid pull request metadata."]);
  });
}

for (const [name, liveMutate] of [
  ["already retargeted", (pr) => { pr.base.ref = "dev"; }],
  ["closed meanwhile", (pr) => { pr.state = "closed"; }],
  ["head moved", (pr) => { pr.head.sha = "b".repeat(40); }],
  ["head renamed", (pr) => { pr.head.ref = "fix/other"; }],
]) {
  test(`${name}: stale event cannot update or comment`, async () => {
    const result = await run({ liveMutate });
    assert.deepEqual(result.calls.map(({ name }) => name), ["get"]);
    assert.deepEqual(result.failures, []);
  });
}

test("invalid current metadata fails closed", async () => {
  const result = await run({ liveMutate: (pr) => { pr.number = 43; } });
  assert.deepEqual(result.calls.map(({ name }) => name), ["get"]);
  assert.deepEqual(result.failures, ["Invalid current pull request metadata."]);
});

test("App-authored opened events remain eligible", async () => {
  const result = await run({ actor: "pr-automation[bot]" });
  assert.equal(result.calls[1].name, "update");
});

test("own App edited events cannot loop even with a main-base payload", async () => {
  const result = await run({ action: "edited", actor: "pr-automation[bot]" });
  assert.deepEqual(result.calls, []);
});

test("unsupported action and missing App identity cannot write", async () => {
  assert.deepEqual((await run({ action: "synchronize" })).calls, []);
  const missingIdentity = await run({ appSlug: "" });
  assert.deepEqual(missingIdentity.calls, []);
  assert.deepEqual(missingIdentity.failures, ["PR automation App identity is missing."]);
});

for (const failAt of ["get", "update"]) {
  test(`${failAt} failure stops publication without logging upstream errors`, async () => {
    const result = await run({ failAt });
    assert.equal(result.calls.some(({ name }) => name === "comment"), false);
    assert.deepEqual(result.failures, ["Failed to retarget PR #42 to dev."]);
  });
}

test("comment failure warns without retrying the successful retarget", async () => {
  const result = await run({ failAt: "comment" });
  assert.deepEqual(result.calls.map(({ name }) => name), ["get", "update", "comment"]);
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.warnings, ["Failed to comment on PR #42."]);
});

test("untrusted branch text is data, never executable source or comment content", async () => {
  const result = await run({ mutate: (pr) => { pr.head.ref = "${{ secrets.KEY }}; `throw new Error()`"; } });
  assert.deepEqual(result.failures, []);
  assert.equal(result.calls[1].name, "update");
  assert.doesNotMatch(result.calls[2].args.body, /secrets|throw/);
  assert.doesNotMatch(script, /\$\{\{/);
});

test("job gate preserves the default-token actor exclusion and allowed branch pair", () => {
  const eligible = (pr, actor = "contributor") => vm.runInNewContext(jobCondition, {
    github: { actor, event: { pull_request: pr } },
  });
  const pr = pullRequest();
  assert.equal(eligible(pr), true);
  assert.equal(eligible(pr, "github-actions[bot]"), false);
  assert.equal(eligible(pr, "pr-automation[bot]"), true);
  pr.head.ref = "dev";
  assert.equal(eligible(pr), false);
  pr.head.ref = "fix/example";
  pr.base.ref = "dev";
  assert.equal(eligible(pr), false);
  pr.base.ref = "main";
  pr.state = "closed";
  assert.equal(eligible(pr), false);
});

test("missing bindings fail before minting without receiving the private key", () => {
  for (const configured of ["", "false", "true"]) {
    const result = spawnSync("bash", ["-c", bindingCheck], {
      env: { PATH: process.env.PATH, APP_CONFIGURED: configured }, encoding: "utf8",
    });
    assert.equal(result.status, configured === "true" ? 0 : 1);
    assert.equal(result.stdout, "");
  }
  assert.match(workflow, /APP_CONFIGURED: \$\{\{ vars\.PR_AUTOMATION_APP_CLIENT_ID != '' && secrets\.PR_AUTOMATION_APP_PRIVATE_KEY != '' \}\}/);
  assert.ok(workflow.indexOf("- name: Check App bindings") < workflow.indexOf("uses: actions/create-github-app-token@"));
});

test("publisher has immutable actions, current-repo PR-only scope and no PR execution", () => {
  assert.match(workflow, /permissions: \{\}/);
  assert.match(workflow, /pull_request_target:\n    types:\n      - opened\n      - reopened\n      - edited\n    branches:\n      - main/);
  assert.match(workflow, /runs-on: ubuntu-latest/);
  assert.match(workflow, /group: retarget-\$\{\{ github\.event\.pull_request\.number \}\}\n  cancel-in-progress: false/);
  assert.deepEqual([...workflow.matchAll(/uses: (\S+)/g)].map((match) => match[1]), [
    "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
    "actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b",
  ]);
  assert.match(workflow, /client-id: \$\{\{ vars\.PR_AUTOMATION_APP_CLIENT_ID \}\}/);
  assert.match(workflow, /private-key: \$\{\{ secrets\.PR_AUTOMATION_APP_PRIVATE_KEY \}\}/);
  assert.match(workflow, /github-token: \$\{\{ steps\.app-token\.outputs\.token \}\}/);
  assert.deepEqual([...workflow.matchAll(/permission-[\w-]+: \w+/g)].map((match) => match[0]), ["permission-pull-requests: write"]);
  assert.doesNotMatch(workflow, /^\s+(owner|repositories|enterprise|skip-token-revoke|outputs):/m);
  assert.doesNotMatch(workflow, /checkout|workflow_dispatch|repository_dispatch|persist-credentials|git push/);
  assert.doesNotMatch(script, /pulls\.create|createRef|updateRef|merge\(/);
  const guard = fs.readFileSync(path.join(root, ".github/workflows/agents-md-guard.yml"), "utf8");
  assert.doesNotMatch(guard, /PR_AUTOMATION_APP|create-github-app-token/);
});
