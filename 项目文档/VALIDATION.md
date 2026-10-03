# Current package verification — 2026-10-02

Version **0.1.2**: **20 installed unittest cases PASS**. The rebuilt package records `dhtfish98` as the new implementation author. Runtime files matched source and the separately installed wheel; retained third-party notices were checked.

Wheel: `cvp_network_policy_reachability_review-0.1.2-py3-none-any.whl`. SHA-256: `b4b47539f1cf131aa7ed3b281b3b67dff2944c40f46c2338a33433fb1911fc2b`. Current result: `ATTRIBUTION_UPDATE_20261002.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Local checks exercised macOS Python 3.14; exact-commit GitHub CI records Linux results separately. Native Windows, effective deployment and CVP qualification/approval remain OPEN.

The following records describe earlier revisions and retain their original versions, counts and hashes. They do not validate this new package.

---

# Current re-audit verification — 2026-10-02

Version **0.1.1**: **20 installed unittest cases PASS**. A new wheel was built and installed into a fresh, separate environment. Runtime bytes in source, wheel and installed package matched. Dependency checks and retained license bytes passed.

Wheel: `cvp_network_policy_reachability_review-0.1.1-py3-none-any.whl`. SHA-256: `08f75869a9780a3e026dc33b268751ed4efe0419f9f749e6754bdb1466b4ba98`. Current machine-readable result: `REAUDIT_20261002.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Python 3.14/macOS was exercised locally. Exact-commit GitHub checks provide separate Linux evidence; native Windows and effective deployment remain OPEN. Project scope and unsupported input behavior remain defined in README.md.

The records below are historical source/oracle/initial-installation evidence, retained for provenance. Earlier test counts, wheel hashes, versions and installation claims refer to the original release and do not validate this repaired release. Full upstream equivalence and CVP applicant qualification/approval remain OPEN.

---

# Validation

Recorded on 2026-10-02 for the final selected implementation. 9 unittest cases passed. Runtime dependencies: Python standard library only. Python 3.14 on macOS arm64 was exercised. Other operating systems and Python versions remain untested.

The suite covers valid declared inputs, malformed/unsupported input, duplicate and nonfinite JSON, lone-surrogate input rejected through both API and CLI, bounded local regular-file reads (symlink/FIFO rejection), and failing CLI exit status. Project-specific tests cover the cryptographic or static semantics listed below. Each project with a cryptographic input also rejects identity, torsion and noncanonical Ed25519 points through its concrete application API and CLI; CRL/OCSP additionally reject certificate/CRL inner-versus-outer AlgorithmIdentifier mismatches. Shared tests reject signature key-family/hash mismatches and noncanonical signature scalars. Normal tests use temporary files and never rewrite saved examples.

## Independent or standard comparison

```json
{
  "reference": "official Kubernetes NetworkPolicy API and concept semantic fixtures",
  "independent_expected_results": "namespace AND pod, union, ingress and egress intersection, named ports, ipBlock except, default empty egress; operation budget",
  "semantic_test_count": 5,
  "live_CNI_behavior": "OPEN"
}
```

This comparison is validation-only. Upstream application packages are not runtime dependencies.

## Packaging and isolation

A wheel was built and installed into a separate per-project virtual environment with source import paths removed. The imported module resided in that environment. The installed CLI accepted the saved valid request (exit 0), rejected an empty object (exit 1), and the installed audit completed with socket creation blocked. This proves the exercised offline input profile and installed artifact; it does not prove all code paths, real deployment, program eligibility or acceptance. Final wheel SHA-256 and installation details are recorded by the aggregate publication evidence.

## Review and limits

Every new production source file was reviewed, including file handling, parser bounds, trust binding, result semantics and unsupported branches. Fixed upstream source review boundaries are listed in ORIGIN.md and provenance/SOURCE_REVIEW.json. Model covers label selectors, namespace AND pod selectors, policy union, direction isolation, CIDR exclusions, numeric ranges, and named ports on declared destination pods. No cluster access, packets, DNS/service NAT, host-network exceptions, CNI-specific behavior, Calico/Istio policies or apply operations. Effective packet delivery remains OPEN.

Cryptographic PASS asserts only the explicit signed input contract where `verified=true`. Static audits retain `verified=false`. An authenticated revoked status can be FAIL with `complete=true`; an unsupported or invalid input is FAIL with `complete=false`. No repository count, package build, or synthetic test is used as evidence of CVP eligibility.

## Source re-audit on 2026-10-02

20 current source unittest cases passed after the independent re-audit. New regressions cover parsed floating-point overflow, missing/unusable safe local-file capabilities and privacy canaries, plus applicable context/URI, peer-null, legacy-switch and revocation-time counterexamples. This source evidence supersedes the earlier source test count. Rebuilt wheel installation and exact-commit CI for this revision are recorded separately by the publication owner; the previous installation record alone does not validate these edits.

Official label-key/value and namespace/Pod/NetworkPolicy name grammar boundaries were exercised at every supported field and selector location, with legitimate empty/caseful labels and the distinct 63/253/317 character boundaries.
