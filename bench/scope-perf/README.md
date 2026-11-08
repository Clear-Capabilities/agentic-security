# Scope performance

`node bench/scope-perf/runner.mjs [--files 10000] [--ignored 100000] [--runs 5] [--json]` times the scope inventory (the `--explain-scope` preview) on a generated Git repository, then again after adding generated files that a `.gitignore` rule excludes. The exit code is 0 only when the preview finishes under 10 seconds and the ignored files add no more than 10% to it.

It measures the inventory only. It does not time a full analysis, so the requirement that a scan adding 100,000 ignored files grows by at most 10% is covered only for the part that decides eligibility. The ignored subtree is reported as one entry and is never listed file by file.

The requirement names a fixed 8-vCPU, 16-GB runner. The runner prints the machine it ran on; a result from another machine is not a measurement of that target. One run on a developer laptop with 8 CPUs and 16 GB gave a preview of about 0.7 seconds for 10,000 files, with no measurable growth from 100,000 ignored files. Treat that as a smoke result, not the published figure: the published figure needs the fixed runner, five runs, and cold and warm cache results recorded together.
