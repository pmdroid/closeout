# Closeout

Closeout is an open specification for declaring what must be verified before an agent's work can be accepted, and recording the evidence used to make that decision.

Commit the requirements in `.agents/closeout.yaml` on the remote `origin` branch `main`. The runner reads that commit. `closeout try` evaluates a draft at `~/.agents/closeout.yaml` and does not write a decision. The reference runner, a CI job, or an orchestrator can read the same policy and reach the same decision from the same evidence.

```bash
cargo test
cargo run --quiet -- validate
```

Draft 0.1 is in [spec/0.1.md](spec/0.1.md). JSON Schemas are in [schema/](schema/). The sample policy is in [examples/bun-project](examples/bun-project). A GitHub Actions workflow that verifies a sealed report and comments on the pull request is in [examples/github/verify-sealed.yml](examples/github/verify-sealed.yml).

Run a gate against a frozen candidate commit:

```bash
cargo run --quiet -- run --gate beforePR --base <base> --head <head> --json
```

Exit 0 means accepted. Exit 1 means a requirement failed. Exit 3 means acceptance is blocked. Exit 2 means the invocation is invalid.

Plugins for Claude Code, Codex, and OpenCode live in [plugins/](plugins/). They consult the runner. They do not contain a second copy of the policy, and they do not grant permission to open a pull request.

License: Apache-2.0.
