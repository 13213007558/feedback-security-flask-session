# Feedback task starting environment

Upstream: https://github.com/pallets-eco/flask-session
Upstream commit: `bc2fe67958bff5e46023c4807b5e75ca350554eb`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_cachelib.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `1 passed in 0.64s`
Whole-command wall time: 1.408 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
