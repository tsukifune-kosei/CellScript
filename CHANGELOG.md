# Changelog

## 2026-04-22

- Tightened backend CFG reachability analysis so unreachable-block metrics are rooted at the selected ELF entry label instead of treating every `.global` text symbol as reachable.
- Added a regression test proving unused global exports are still counted as unreachable from the entry root.
- Removed obsolete `global_text_labels` parser storage after entry-root reachability replaced global-root reachability.
- Rebased bundled-example unreachable-block budgets on the stricter entry-root metric while keeping call-edge and CFG shape budgets enforced.
