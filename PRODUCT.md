# Product

<!-- impeccable:product-schema 1 -->

The questions about audience and build path were declined. Facts below that the repository or the original request did not state are marked inferred.

## Platform

web

## Stack

Astro. The request asked for an Astro landing page and schema docs.

## Users

Inferred. The primary user is someone who has to decide whether an agent's change can be accepted. They write the requirements once, in the repository, and they need an orchestrator, a CI job, or the reference runner to reach the same decision from the same evidence. A second audience is the person implementing that orchestrator.

## Product Purpose

Closeout declares what must be verified before an agent's work can be accepted, and records the evidence used to make that decision. Success is two evaluators, given the same policy, the same candidate, and the same evidence, returning the same acceptance decision.

## Positioning

Closeout is an open specification for declaring what must be verified before an agent's work can be accepted, and recording the evidence used to make that decision. ACPDash is one consumer of that file. The format does not belong to ACPDash.

## Operating Context

The policy lives at `.agents/closeout.yaml` on the remote `origin` branch `main`. When that commit has no closeout file, the runner reads `~/.agents/closeout.yaml`. The reference runner is the Rust binary `closeout`. Draft 0.1, the JSON Schemas, the conformance fixtures, and the contribution rules are in this repository. A session hook may consult the decision. It does not open or merge a pull request. The orchestrator checks the current decision at that boundary.

## Capabilities and Constraints

Draft 0.1. Public requirements are `command` and `review`, gate `beforePR`. Imports are local files. An absent policy is zero requirements and an accepted decision. A present file that does not load blocks acceptance. Command checks run in a detached git worktree at the candidate commit. The entry file may list setup steps. They run in that worktree before the commands and may leave files. A failed setup step rejects the decision, and later commands do not run. An item may name `paths`. The runner requires that item only when the candidate changes a matching path. A setup step may name `paths` the same way. License is Apache-2.0.

Inferred as still undecided: a public host name, a package registry, and any remote policy registry. This edition does not have those.

## Brand Commitments

The name is Closeout. The edition in public is Closeout Specification, Draft 0.1. Voice is plain and specific. Sentence case in headings.

## Evidence on Hand

`spec/0.1.md`, `schema/`, `conformance/`, `examples/bun-project`, and the `closeout` binary. There are no customer logos, testimonials, benchmarks, or pricing. Do not invent them.

## Product Principles

The policy file is the requirement. A skill becomes a requirement only when the policy names it.

The same inputs produce the same acceptance decision.

Chat is not command evidence.

Retry exhaustion is not acceptance.

A hook inside a session is not permission to open a pull request.
