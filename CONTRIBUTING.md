# Contributing

Draft 0.1 in `spec/0.1.md` is the behavior an evaluator implements. `schema/` and `conformance/` travel with that text. A change to required behavior updates the spec, the schema, and a fixture in the same change.

The reference runner in `src/` is one implementation. ACPDash can track this draft on its own releases. A format change is a spec change, not an ACPDash release note.

Issues and pull requests are the place to propose an edition. Say which fixture demonstrates the behavior you want. An outside implementation that passes `conformance/` without copying this runner is the check that the draft can be read on its own.

This project is licensed under Apache-2.0. By contributing, you agree that your contributions are licensed under Apache-2.0.
