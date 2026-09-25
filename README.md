# Aegis PQC — ECDAT

**Enterprise Cryptographic Discovery & Analysis Tool**

Smart India Hackathon 2026 · Problem Statement **26164** · NTRO
Theme: Blockchain & Cybersecurity · Team: **Quantum Shield**

> Discovers where cryptography actually lives across an organisation, determines
> which of it a quantum computer would break, explains the technically correct
> replacement, and turns that into an evidence-aware migration roadmap — with
> every conclusion traceable to the exact evidence that produced it.

---

## The problem

Cryptography is scattered across an enterprise — in certificates, dependency
manifests, source code, compiled binaries and container images — and is almost
never documented in one place. Two facts make this urgent:

**Shor's algorithm** breaks RSA and elliptic-curve cryptography once a
cryptographically relevant quantum computer (CRQC) exists. These algorithms
protect most of the internet today.

**Harvest Now, Decrypt Later (HNDL)** means the threat is already live. An
adversary records encrypted traffic today and stores it, waiting to decrypt it
when a CRQC arrives. Data that must stay confidential for a decade is therefore
at risk *now*, not when quantum computers ship.

Before an organisation can migrate, it has to answer a question most cannot:
*where is our vulnerable cryptography?* ECDAT answers it.

---

## Pipeline

```
DISCOVER → INVENTORY → CBOM → QUANTUM RISK → RECOMMEND → PRIORITISE → REPORT
```

| Stage | What happens |
|---|---|
| **Discover** | Five independent scanners find real cryptographic usage |
| **Inventory** | Findings unified into one canonical model; declared organisational context attached with visible provenance |
| **CBOM** | Schema-validated CycloneDX 1.6 Cryptography Bill of Materials |
| **Quantum Risk** | Algorithm classification + Mosca time-horizon analysis |
| **Recommend** | Role-aware remediation (a signature and an encryption use of RSA get different answers) |
| **Prioritise** | Technical risk combined with *declared* business context → action buckets |
| **Report** | CBOM, inventory, risk, recommendations, roadmap and full assessment exports |

---

## Discovery surfaces

| Surface | Reads | Establishes |
|---|---|---|
| **Certificates** | PEM / DER | Algorithm via ASN.1 OID extracted from the certificate's own structure — this is how ML-DSA and other new post-quantum certificates are recognised |
| **Dependencies** | `requirements.txt`, `package.json`, `pom.xml`, `go.mod` | A library *capable* of cryptography — recorded with an empty algorithm field, never reported as usage |
| **Source** | Python (AST), JavaScript/TypeScript, Java, Go | Actual call sites, with import / call-site / configuration evidence levels distinguished |
| **Binary** | ELF, via LIEF | Linked libraries and imported symbols read from the import table — nothing is executed |
| **Container** | Docker / OCI archives | Layers safely extracted, then the four surfaces above run across them |

---

## Quantum risk and the Mosca inequality

Each algorithm is classified against an auditable YAML knowledge base:

- **Quantum-vulnerable** — RSA, ECC, DSA, Diffie-Hellman (broken by Shor's algorithm)
- **Symmetric, reduced margin** — AES, SHA-2 (Grover's algorithm weakens these; it does **not** break them — the distinction is preserved throughout)
- **Post-quantum** — ML-KEM, ML-DSA, SLH-DSA
- **Capability only** — a library with no confirmed usage; no algorithm-level verdict is assigned
- **Unknown** — never guessed

For quantum-vulnerable findings, Mosca's inequality decides whether timing
matters yet:

```
data_lifetime + migration_time > CRQC_horizon   →   exposed
```

**The CRQC horizon is never hardcoded.** It is supplied as policy. If it — or
either other input — is missing, the result is `INSUFFICIENT_INFORMATION` and no
calculation is performed. The system does not substitute a guess for an
assumption it was not given.

---

## Recommendations

Role-aware, because RSA does two different jobs:

| Finding | Recommendation | Standard |
|---|---|---|
| RSA used for key establishment | ML-KEM-based hybrid key establishment | NIST FIPS 203 |
| RSA used for signatures | ML-DSA | NIST FIPS 204 |
| AES-128 | AES-256 (classical strengthening — *not* a post-quantum issue) | — |
| MD5 / SHA-1 | A modern hash — a classical weakness unrelated to quantum computing | — |

If the role cannot be established, no specific target is recommended and the
missing evidence is named instead.

---

## Migration roadmap

Priority is **organisational context applied to technical risk**, not risk
restated. A CRITICAL-risk finding reaches `IMMEDIATE` only if the owning
component is *declared* business-critical; where nobody declared it, the same
finding sits lower, because the system will not assume importance it was never
told.

Buckets: `IMMEDIATE` · `HIGH` · `PLANNED` · `EVIDENCE_REQUIRED` · `MONITOR` ·
`NO_ACTION`.

No dates, costs, effort estimates or performance benchmarks are invented.

---

## Tech stack

| Layer | Technology |
|---|---|
| Language | Python (backend, frontend and tests) |
| Dashboard | Streamlit, with a custom CSS design system |
| API | FastAPI (optional layer; auto-generated docs at `/docs`) |
| Storage | SQLite (single file, no server) |
| Cryptography | `cryptography` ≥ 49 — provides RSA, AES, X25519 **and ML-KEM** without a C toolchain |
| Binary analysis | LIEF |
| CBOM | `cyclonedx-python-lib` (CycloneDX 1.6, schema-validated) |
| Visualisation | Plotly, pandas |
| Tests | pytest |

There is no machine-learning model. Every classification is deterministic and
rule-based, which is what makes each conclusion explainable and reproducible.

---

## Setup and run

```bash
pip install -r requirements.txt
```

```bash
# ECDAT — the SIH 2026 application
streamlit run frontend/ecdat_app.py        # or: ./run_ecdat.sh  /  .\run_ecdat.ps1

# Security Lab — the retained HNDL / Q-Day demonstration (separate app)
streamlit run frontend/app.py              # or: ./run_demo.sh   /  .\run_demo.ps1
```

```bash
python -m pytest tests -q                  # full test suite
```

In the ECDAT sidebar, click **LOAD DEMO ESTATE** to run the whole pipeline.

The application is fully offline — no CDN, no web fonts, no outbound network
calls. This is enforced by an automated test.

---

## Demo estate

Five synthetic applications are generated on disk — `payments-api`,
`legacy-auth`, `mobile-gateway`, `pqc-pilot` and `content-portal` — containing
real certificates, real manifests, real source files and a genuinely compiled
binary.

The fixtures are synthetic because a hackathon has no real client codebase to
scan. **The analysis is not.** The scanners read those files exactly as they
would read a production repository, and every finding, classification and
recommendation is computed live.

`content-portal` deliberately contains cryptographic *words* in comments,
identifiers and documentation but no cryptographic *usage*. It returns zero
findings — the project's own built-in control against false positives.

---

## Repository layout

```
backend/
  model.py              canonical data model (observed facts / context / conclusions)
  discovery/            the five scanners
  knowledge/            YAML classification and mapping rules (auditable without reading code)
  inventory.py          unification and context resolution
  cbom.py               CycloneDX 1.6 export
  quantum_risk.py       classification and Mosca analysis
  recommendations.py    role-aware remediation engine
  migration_priority.py priority decision tree and roadmap
  ecdat_service.py      the single orchestrator the dashboard calls
frontend/
  ecdat_app.py          ECDAT dashboard
  ecdat_style.py        design system
  ecdat_view.py         pure formatting helpers
  app.py, ui.py         Security Lab (unmodified)
docs/
  CODEBASE.md           full technical reference
  security-lab/         presentation pack for the Security Lab capability
tests/                  828 tests
```

---

## Honest limitations

- **The CRQC horizon is an assumption, not a prediction.** No one knows when a
  cryptographically relevant quantum computer will exist. Every Mosca result is
  conditional on the horizon supplied, and that assumption is shown alongside
  the result.
- **Binary analysis is structural.** Imported symbols and linked libraries are
  read from the file's own tables. Whether a referenced function is reached at
  runtime would require disassembly, which is not performed — so no binary
  finding is rated HIGH confidence.
- **Dependency findings prove capability, not usage**, and are reported that way.
- **PE and Mach-O binaries** are parsed by the same library but are not exercised
  by the bundled demonstration estate.
- **Source scanning** uses a real AST for Python; JavaScript, Java and Go use
  tuned pattern matching, which is more conservative.
- **Container scanning** models the merged filesystem and the layer that last
  wrote each path, not full per-file layer history.
- **Business criticality is never inferred.** Where an organisation has not
  declared it, priority is deliberately capped.
- **No performance benchmarks** are attached to recommendations, because none
  have been measured for the discovered assets.

---

## Security Lab

The repository also retains the earlier **Harvest Now, Decrypt Later /
Q-Day** demonstration, which runs as a separate application and performs a
genuine classical factorisation of a deliberately undersized RSA modulus to
make the threat model tangible. It shares a visual language with ECDAT but no
pipeline logic, and is unmodified. Its presentation material lives in
`docs/security-lab/`.
