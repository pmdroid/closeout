---
name: closeout
description: Satisfy the repository acceptance policy in .agents/closeout.yaml before work is accepted. Use when preparing a pull request, finishing a task, or recording review evidence.
---

The acceptance policy is `.agents/closeout.yaml` on the remote `origin` branch `main`. The runner reads that commit. When that commit has no closeout file, `run` and `decision` read `~/.agents/closeout.yaml`. A file on `origin/main` wins. A local edit does not change the requirements. A skill that is installed but not named there is not a requirement. A named requirement stays required even when an agent never loads the skill. An item that lists `paths` is required only when the candidate changes a matching path.

To test a draft before it is on `origin/main`, write `~/.agents/closeout.yaml` and run:

    closeout try --gate beforePR --base <base-commit> --head <candidate-commit>

Command requirements are executed by the Closeout runner in one detached worktree at the candidate commit. Setup steps run in that worktree before the commands and may leave files. When a setup step fails, later commands do not run.

    closeout run --gate beforePR --base <base-commit> --head <candidate-commit> --candidate-session <your-session> --candidate-model <your-model> --json

A message that tests passed is not command evidence. The evidence file written by the runner is the record.

When the policy has `retry.scope: task`, use the same `--task <id>` on `run`, `decision`, `try`, and `evidence add` throughout the task. Set `CLOSEOUT_TASK` to that ID for the agent hooks. Preserve the evidence directory across commits and sessions. A requirement at its configured failed-attempt limit is `exhausted`. Stop retrying and ask the operator for help. An exhausted decision stays blocked; a stop hook lets the agent stop without accepting the task. Only the operator or orchestrator authorizes a new task ID after escalation.

For a review requirement, follow the skill named on that item. Use a different session when `differentSession` is true, and a different model when `differentModel` is true. An empty model id does not prove independence. Do not edit the candidate during the review.

Write findings to a JSON array. Each object has `severity`, `location`, `explanation`, and `evidence`. Then record them:

    closeout evidence add --gate beforePR --item <qualified-id> --base <base-commit> --head <candidate-commit> --session <reviewer-session> --model <reviewer-model> --findings findings.json

The runner computes the outcome from the findings. Do not put an outcome field in the file.

Read the decision:

    closeout decision --gate beforePR --base <base-commit> --head <candidate-commit> --candidate-session <implementer-session> --candidate-model <implementer-model> --json

`accepted` is exit 0. `rejected` is exit 1. `blocked` is exit 3.

A hook that lets the session stop does not accept the change. It does not permit opening or merging a pull request. The orchestrator checks the current decision at that boundary. Stopping after repeated hook feedback does not turn a blocked decision into an accepted one.
