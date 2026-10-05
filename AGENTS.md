# Closeout

This repository is the Closeout specification, draft 0.1, and its reference runner.

Acceptance requirements are in `.agents/closeout.yaml` on the remote `origin` branch `main`. Read that commit for what has to pass. Do not copy the policy into this document.

The runner is the Rust binary `closeout`. From this repository, `cargo run --quiet -- validate` checks the policy. Tests are `cargo test`.

A skill under `.agents/skills/` explains a procedure. It becomes a requirement only when the policy names it.

The reference runner executes command requirements. It does not open pull requests. A session hook that consults Closeout does not accept the work.
