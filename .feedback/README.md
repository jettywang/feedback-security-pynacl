# Feedback task starting environment

Upstream: https://github.com/pyca/pynacl
Upstream commit: `ca15a18eeb4d1e954b1f08066ffa3b7ebe3b71a9`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC LIBSODIUM_MAKE_ARGS=-j4 LDFLAGS='' UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_secret.py tests/test_aead.py tests/test_sealed_box.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `117 passed in 1.58s`
Whole-command wall time: 1.910 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
