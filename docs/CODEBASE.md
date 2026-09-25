# Aegis PQC / ECDAT — Complete Technical Reference

Enterprise Cryptographic Discovery & Analysis Tool. This document explains
the entire codebase from first principles to the exact decision logic —
every concept a non-programmer needs, every piece of code a programmer needs.

---

## TABLE OF CONTENTS

1. Glossary — every unfamiliar term, defined once
2. What the product does, mechanically
3. Tech stack — every tool, what it is, why it's here
4. Folder structure
5. The data model — the vocabulary every other file shares
6. Discovery — the five scanners, in full
7. Inventory — merging and context
8. The Quantum Risk Engine — the Mosca calculation, in full
9. The Recommendation Engine — role-aware remediation, in full
10. Migration Priority — the decision tree, in full
11. CBOM — the standards-compliant export
12. The orchestrator — how one function runs everything
13. The frontend — Streamlit, the dashboard, the design system
14. Testing — what 828 tests actually check
15. The Security Lab — the separate frozen demo
16. One finding, traced start to finish — a worked example
17. Full file index

---

## 1. GLOSSARY

Read this first if any term below is unfamiliar. Everything else in this
document assumes you know these.

| Term | Plain meaning |
|---|---|
| **Python** | The programming language used for 100% of this project (backend and frontend) |
| **Library / package** | Pre-written code someone else published that you can `pip install` and use — e.g. the `cryptography` library gives you working RSA/AES code so you don't write encryption math yourself |
| **Function** | A named, reusable block of code that takes inputs and returns an output. `def add(a, b): return a + b` is a function |
| **Class** | A blueprint for a data structure that bundles related values together, e.g. a `CryptoFinding` class bundles "algorithm," "confidence," "file location" into one object |
| **Enum** (Enumeration) | A fixed, typo-proof list of allowed values. Instead of a plain text field where someone could type `"critikal"` by mistake, an Enum only allows `CRITICAL`, `HIGH`, `MEDIUM`, etc. — anything else is a code error caught immediately |
| **Dataclass** | A Python shorthand for defining a class that's mostly just a bundle of fields, with less boilerplate code |
| **Type hint** | Text like `-> int` or `: str` next to a variable/function, telling you (and tooling) what kind of value is expected. Doesn't change how the code runs — it's documentation the computer can also check |
| **AST (Abstract Syntax Tree)** | The structural representation of code that the Python interpreter itself builds before running a `.py` file. Parsing code into an AST means understanding it structurally (this is a function call, this is its second argument) rather than just reading it as text |
| **Regex (Regular Expression)** | A pattern-matching language for text, e.g. the pattern `RSA_\w+` matches `RSA_new`, `RSA_generate_key`, etc. Used where AST isn't available (JS, Java, Go) |
| **OID (Object Identifier)** | A globally standardized numeric code that unambiguously names something. `1.2.840.113549.1.1.1` always means "RSA encryption," everywhere, in every tool, forever — defined by international standards bodies, not by us |
| **YAML** | A plain-text data format (not code) for writing structured information humans can read and edit directly — used here for "which algorithms are quantum-vulnerable," so that list is auditable by someone who doesn't write Python |
| **REST API** | A way for one program to ask another program for data over HTTP (the same protocol web pages use), following a standard request/response pattern |
| **ASGI server** | The program that actually listens for incoming web requests and hands them to your Python code (Uvicorn, in this project) |
| **SQLite** | A database that lives entirely in one file on disk — no separate database server process to install or configure |
| **ELF** | The file format Linux uses for compiled executables and shared libraries (`.so` files) — analogous to `.exe`/`.dll` on Windows |
| **Session state** (Streamlit) | A dictionary that survives between reruns of a Streamlit script, used to remember "we already loaded the demo data" across button clicks |
| **CVE / CWE** | Not used here, but often confused with OID — irrelevant to this project, mentioned only to avoid confusion |
| **Shor's algorithm** | A quantum algorithm (proven mathematically in 1994) that factors large numbers efficiently — this is what breaks RSA, and solves the discrete-logarithm problem that breaks ECC/Diffie-Hellman, once a sufficiently large quantum computer exists |
| **Grover's algorithm** | A quantum algorithm that speeds up brute-force search quadratically — it *weakens* symmetric crypto like AES (roughly halving the effective key length) but does not break it the way Shor's algorithm breaks RSA |
| **CRQC** | Cryptographically Relevant Quantum Computer — a quantum computer powerful enough to actually run Shor's algorithm against real-world key sizes. Doesn't exist yet; *when* it will is an open research question, which is why this project always treats it as an assumption |
| **HNDL (Harvest Now, Decrypt Later)** | An attack strategy: record encrypted traffic today, store it, decrypt it once a CRQC exists later |
| **Mosca's inequality** | A real, published risk-planning framework (Michele Mosca, a post-quantum cryptography researcher) for deciding if you need to worry yet: compare how long your data must stay secret plus how long migration will take, against your best guess for when a CRQC will exist |
| **ML-KEM** | Module-Lattice Key Encapsulation Mechanism — the NIST-standardized (FIPS 203) post-quantum replacement for RSA/ECC *key exchange* |
| **ML-DSA** | Module-Lattice Digital Signature Algorithm — the NIST-standardized (FIPS 204) post-quantum replacement for RSA/ECC *signatures* |
| **CBOM** | Cryptography Bill of Materials — a standardized, machine-readable inventory of the cryptography inside a system, in the CycloneDX format |
| **CycloneDX** | An open, published standard (originally for software bill-of-materials, extended to cover crypto) — a file in this format can be read by any tool that supports the standard, not just this one |
| **LIEF** | "Library to Instrument Executable Formats" — a library for reading the internal structure of compiled binaries without running them |

---

## 2. WHAT THE PRODUCT DOES, MECHANICALLY

Given a folder of code (a "target"), the system:

1. **Reads** every certificate, dependency manifest, source file, and compiled
   binary it finds, and records every place cryptography appears — as a
   plain, unopinionated fact ("line 12 of `keys.py` calls
   `rsa.generate_private_key(key_size=2048)`")
2. **Looks up** each algorithm found against a small, editable YAML file that
   says whether it's broken by quantum computers, weakened, or already safe
3. **Calculates**, only for the vulnerable ones, whether the *timing* actually
   matters yet, using Mosca's inequality
4. **Recommends** a specific, role-correct replacement, or says "not enough
   evidence to recommend anything yet" if that's the honest answer
5. **Prioritizes** the recommendations into action buckets, using both the
   technical risk *and* whatever business context a human has actually
   declared — never inventing the business context
6. **Displays** all of this in a dashboard, and **exports** it as a
   standards-compliant CBOM file

Nothing in step 6 computes anything — it only shows what steps 1–5 already
produced.

---

## 3. TECH STACK — EVERY TOOL, IN DEPTH

### 3.1 Python — the only language

Every `.py` file in this project — backend logic, the web dashboard, the
tests — is Python. This isn't a limitation; it's a deliberate simplification:
one language means one person can read the entire codebase without switching
mental models between a backend language and a frontend language.

### 3.2 Streamlit — how the dashboard exists without writing HTML/CSS/JS by hand

Streamlit is a Python library that converts a plain Python script into a web
application. You write:

```python
import streamlit as st
st.title("Hello")
if st.button("Click me"):
    st.write("You clicked it")
```

...and Streamlit runs a local web server, opens a browser tab, and renders
that as an actual webpage with a working button. **The critical mental model:
every time the user interacts with anything (clicks a button, picks a
dropdown option), Streamlit reruns the *entire Python script from the top*.**
This is different from how a typical JavaScript web app works (where only
the part that changed re-renders). To remember something *across* those
reruns (like "the user already clicked Load Demo Estate, don't reload it"),
Streamlit gives you `st.session_state` — a dictionary that survives reruns.

You'll see this pattern throughout `ecdat_app.py`:

```python
if not st.session_state.get("_booted"):
    sx.boot_overlay()
    st.session_state["_booted"] = True
```

This says: "only show the animated boot sequence once — after it's shown
once, remember that in session state so it doesn't replay on every rerun."

### 3.3 FastAPI — the optional API layer

FastAPI is a Python framework for building REST APIs. In this project it
exposes the same backend logic over HTTP, so in principle another program
(not just the Streamlit dashboard) could call it. It's not what judges will
interact with directly — the dashboard is — but it exists because the
original project was built API-first, and running it gives you
auto-generated documentation at the `/docs` URL (FastAPI's built-in
"Swagger UI," which reads your function signatures and builds an interactive
API reference automatically — you don't write that documentation by hand).

### 3.4 Uvicorn — what actually runs FastAPI

FastAPI describes *what* your API does; Uvicorn is the actual running
program that listens on a network port and hands incoming requests to
FastAPI. This is a real separation in Python web development: the
"framework" (FastAPI) and the "server" (Uvicorn) are different libraries
that work together.

### 3.5 SQLite — the database

Every other database you've likely heard of (PostgreSQL, MySQL) requires
running a separate server process. SQLite doesn't — the entire database is
one `.db` file, and Python's standard library already knows how to read and
write it (`import sqlite3` works with zero installation). This project
stores scan results here. Simpler to run, no configuration, and completely
sufficient for this scale.

### 3.6 The `cryptography` library — the actual crypto implementations

This one library (version 49+) provides working, correct implementations of
RSA, AES, X25519, HKDF — **and ML-KEM (the post-quantum algorithm)** — all
from a single `pip install`, with no C compiler required on the installing
machine (older post-quantum libraries needed you to compile C code locally,
which regularly fails on Windows). This is why the whole project installs
in under a minute on a plain laptop.

### 3.7 LIEF — reading compiled binaries without running them

When the source code isn't available (a vendor's compiled `.dll`, a shipped
binary), LIEF lets Python open that file and read its *internal structure* —
specifically, the table of external functions it imports. If a binary
imports `EVP_aes_256_gcm`, LIEF can tell you that without ever executing a
single instruction of that binary. This is genuinely safe static analysis.

### 3.8 cyclonedx-python-lib — generating the standards-compliant report

CycloneDX is a real, published standard (used by real enterprise security
tools) for describing what's inside a piece of software. This library
generates a file in that exact format and validates it against the official
schema — meaning an external tool that only knows the CycloneDX standard,
and has never heard of this project, could still open and correctly parse
the file we produce.

### 3.9 Plotly and pandas — charts and tables

Pure presentation. `pandas` organizes data into table shape; `plotly` draws
charts from it. Neither one computes a risk level or a recommendation —
they only visualize numbers that arrived already computed.

### 3.10 pytest — the testing framework

Runs every test function in the `tests/` folder and reports pass/fail. A
"test" here is just a Python function starting with `test_` that calls part
of the real code and checks the result with `assert`:

```python
def test_rsa_is_quantum_vulnerable():
    result = classify("RSA")
    assert result.category == "quantum_vulnerable"
```

If the `assert` is false, pytest reports that test as failed.

---

## 4. FOLDER STRUCTURE

```
backend/
├── model.py                  the shared data vocabulary (read this first)
├── discovery/
│   ├── certificates.py       scanner 1
│   ├── dependencies.py       scanner 2
│   ├── source.py             scanner 3
│   ├── binary.py             scanner 4
│   ├── container.py          scanner 5
│   ├── attribution.py        maps a file path to "which company/component"
│   └── __init__.py           shared safety limits used by all 5 scanners
├── knowledge/                 YAML data files — the classification/mapping rules
│   ├── quantum_risk.yaml      which algorithms are quantum-vulnerable
│   ├── recommendations.yaml   role-aware replacement mappings
│   ├── crypto_apis.yaml       source-code API signatures the scanner looks for
│   ├── crypto_binary.yaml     binary symbol names the scanner looks for
│   └── crypto_libraries.yaml  known crypto packages, by ecosystem
├── inventory.py               merges scanner output + resolves org context
├── cbom.py                    CycloneDX export
├── quantum_risk.py            classification + Mosca calculation
├── recommendations.py         role-aware remediation engine
├── migration_priority.py      risk + context → action buckets
├── ecdat_service.py           the single entry point the frontend calls
├── demo_enterprise.py         generates fake certificates for the demo
├── demo_manifests.py          generates fake requirements.txt/package.json/etc.
├── demo_source.py             generates fake source files with real crypto calls
├── demo_binaries.py           generates one genuinely-compiled fake binary
├── demo_containers.py         generates fake Docker/OCI archives
│
│  (below this line: the ORIGINAL/legacy project — see Part 15)
├── crypto_engine.py, scanner.py, database.py, simulator.py,
│   procedure.py, service.py, main.py, reporting.py, migration.py,
│   config.py, preflight.py

frontend/
├── ecdat_app.py               the ECDAT dashboard — 10 tabs
├── ecdat_view.py               pure formatting functions (backend data → display strings)
├── ecdat_style.py               the CSS design system + animations
└── app.py, ui.py                the Security Lab — separate, frozen (Part 15)

tests/
├── test_suite.py, test_scanner.py, test_phase2.py,
│   test_phase4.py, test_release.py         legacy-project + honesty-audit tests
└── ecdat/
    └── test_phase1.py .. test_phase11_ui.py   one file per ECDAT build phase
```

---

## 5. THE DATA MODEL — `backend/model.py` (1,273 lines, no logic, only shapes)

Every other file imports from here. It defines the vocabulary the entire
system agrees on. Understanding this file means understanding the whole
project's design.

### 5.1 The central idea: three layers, never blended

**Layer 1 — Observed facts.** The `CryptoFinding` class. A record of what a
scanner literally saw, nothing inferred:

```python
class CryptoFinding:
    finding_id: str            # unique identifier for this exact finding
    algorithm: str             # e.g. "RSA" — empty string if not established
    key_size: int | None       # only set if a literal number was found in code
    confidence: Confidence     # HIGH / MEDIUM / LOW
    location: str              # file path
    line: int | None
    evidence: str              # the actual text snippet that justifies this finding
    component: str             # which application this belongs to
    source_type: SourceType    # certificate_file / dependency / source_code / binary / container
    detection_method: DetectionMethod
    raw_detail: dict           # extra structured detail (e.g. "role": "signature")
```

**Layer 2 — Declared context.** The `ApplicationContext` class. Information
a *human* supplied about a component — never inferred by the system:

```python
class ApplicationContext:
    component: str
    data_lifetime_years: int          # how long must this data stay secret
    data_sensitivity: Sensitivity
    business_criticality: BusinessCriticality
    context_source: ContextSource     # WHERE this value came from
    is_declared: bool                 # False = nobody actually said this
```

If `is_declared` is `False`, every downstream calculation treats this
component's business importance as **unknown** — not "low," not a default
guess. This single boolean is what prevents the system from ever quietly
assuming something a human didn't actually tell it.

**Layer 3 — Computed conclusions.** `QuantumRiskResult`,
`RecommendationResult`, `MigrationPriorityResult`. These are the *only*
classes allowed to state a risk level, a recommendation, or a priority — and
every one of them carries the `finding_id` that produced it, so any
conclusion can always be traced back to layer 1.

### 5.2 Confidence — how sure is the scanner, really

```python
class Confidence(str, Enum):
    HIGH   = "high"    # parsed structurally, unambiguous (a DER-parsed OID;
                        # an AST call node with a literal argument)
    MEDIUM = "medium"   # structurally located, but inference is involved
                        # (a crypto library import; a symbol in an import table)
    LOW    = "low"      # textual indicator only
```

Confidence is set once, when the finding is created, and **never upgraded**
by any later phase. If a finding started at LOW confidence, the risk
assessment, the recommendation, and the priority all still show LOW
confidence — the system never lets a weak signal look stronger just because
it passed through more processing steps.

### 5.3 RiskLevel — the output of the quantum risk engine

```python
class RiskLevel(str, Enum):
    CRITICAL     = "CRITICAL"
    HIGH         = "HIGH"
    MEDIUM       = "MEDIUM"
    LOW_BASELINE = "LOW BASELINE"
    PQC_READY    = "PQC READY"
    UNKNOWN      = "UNKNOWN"
```

Notice there is **no `SAFE`**. The code comment explaining this is explicit:
`PQC_READY` states only what was actually established (post-quantum material
was found and verified) and `LOW_BASELINE` states the *absence* of quantum
exposure without claiming the asset is beyond criticism in every other
respect. This is a deliberate wording choice to avoid overclaiming.

### 5.4 QuantumCategory — the algorithm-level classification

```python
class QuantumCategory(str, Enum):
    QUANTUM_VULNERABLE = "quantum_vulnerable"   # broken by Shor's algorithm
    SYMMETRIC_REDUCED  = "symmetric_reduced"    # only weakened by Grover's
    POST_QUANTUM       = "post_quantum"         # already believed quantum-safe
    CAPABILITY_ONLY    = "capability_only"       # a library, not confirmed usage
    UNKNOWN            = "unknown"
```

### 5.5 RemediationClass — what kind of fix, not just "migrate"

```python
class RemediationClass(str, Enum):
    PQC_NATIVE               = "pqc_native"                 # replace with a PQC algorithm
    HYBRID                   = "hybrid"                     # combine classical + PQC during transition
    CLASSICAL_STRENGTHENING  = "classical_strengthening"     # e.g. AES-128 → AES-256 (not a PQC issue!)
    NON_QUANTUM_ISSUE        = "non_quantum_issue"            # e.g. replace MD5 — nothing to do with quantum
    NONE_REQUIRED            = "none_required"
```

The code comment here is worth reading directly: *"Collapsing these into one
'PQC migration' bucket would misrepresent the threat model. Moving AES-128
to AES-256 addresses Grover's quadratic speedup, not Shor's algorithm.
Replacing MD5 addresses a break that has nothing to do with quantum
computing at all."* This single enum is what prevents the tool from telling
someone to "migrate to post-quantum crypto" when their actual problem is an
outdated hash function that was already broken by classical computers years
before quantum computing was ever relevant.

### 5.6 MigrationPriority — action buckets, separate from risk

```python
class MigrationPriority(str, Enum):
    IMMEDIATE          = "immediate"
    HIGH                = "high"
    PLANNED             = "planned"
    EVIDENCE_REQUIRED   = "evidence_required"
    MONITOR             = "monitor"
    NO_ACTION           = "no_action"
```

The docstring on this enum states the project's second most important
design decision directly: *"Priority is organisational context applied to
technical risk — not risk restated. A CRITICAL quantum-risk finding is not
automatically IMMEDIATE; that top bucket also requires the owning system to
be business-critical."*

---

## 6. DISCOVERY — THE FIVE SCANNERS, IN FULL

Every scanner has the same job shape: read some kind of input, produce a
list of `CryptoFinding` objects, and nothing else. None of the five scanners
know the others exist. `inventory.py` (Part 7) is the only file that calls
all five.

### 6.1 Certificates — `backend/discovery/certificates.py` (332 lines)

Reads `.pem` / `.der` certificate files. The key design choice: identify the
algorithm by extracting and looking up its **OID directly from the raw
certificate bytes**, not by guessing from the filename or trying to load it
with a high-level library that might fail on newer post-quantum certificate
types. From the code's own comment:

> "A DER-extracted OID is direct structural evidence; prefer it over the
> [library-based] fallback."

Every OID maps to an algorithm name via a lookup table (e.g.
`1.2.840.113549.1.1.1` → RSA). This is exactly how a certificate genuinely
declares its own algorithm — it's part of the certificate's own binary
structure, standardized since long before this project existed. **This is
why the scanner can even recognize ML-DSA and other very new post-quantum
certificate types**: their OIDs are looked up the same structural way,
rather than needing a crypto library that's been updated to understand that
specific algorithm.

Findings from a successfully parsed certificate get `HIGH` confidence
(`DetectionMethod.OID_EXTRACTION`). If only raw bytes could be read (parsing
failed), the finding is capped at lower confidence — the scanner never
claims more certainty than it actually has.

### 6.2 Dependencies — `backend/discovery/dependencies.py` (626 lines)

Reads `requirements.txt` (Python), `package.json` (JS/Node), `pom.xml`
(Java/Maven), `go.mod` (Go). Each of these is a *manifest file* — a
plain-text or XML/JSON list of "this project depends on library X, version
Y." The scanner checks each listed library name against
`crypto_libraries.yaml` (a curated list of packages known to provide
cryptographic functionality, per ecosystem).

**The critical design decision, repeated because it matters everywhere in
this system:** when a crypto-capable library is found in a manifest, the
resulting `CryptoFinding` is created with **`algorithm` left as an empty
string**. The library *can* do RSA — that doesn't mean this specific
application *does* RSA. This gap between "installed" and "used" is exactly
what the Source scanner (6.3) closes, by finding the actual function calls.

### 6.3 Source code — `backend/discovery/source.py` (1,045 lines — the largest scanner)

**For Python**, this scanner uses the real `ast` module from Python's own
standard library — the exact same parser Python itself uses before running
your code. `ast.parse(text)` builds a tree describing the code's structure
(this is a function call; this call has 2 arguments; the second argument is
the literal integer `2048`) — **it does not execute anything.** The code
comment says this explicitly: *"`ast.parse` performs no evaluation — it is a
parser, not an interpreter — so no application code executes at any point."*
This matters for safety: scanning an unknown codebase must never accidentally
run it.

Walking through the actual detection, simplified from the real code:

```python
def detect_python(text: str) -> tuple[list[SourceDetection], str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return [], f"unparseable Python ({type(exc).__name__})"
    # ...walk every node in the tree...
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # found an "import X" statement — check if X is a crypto module
            ...
```

A helper function reconstructs a dotted call name like
`rsa.generate_private_key` from the nested AST nodes Python actually
produces for it:

```python
def _dotted_name(node: ast.AST) -> str:
    """rsa.generate_private_key arrives as nested Attribute nodes;
    this flattens them back to a plain string."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))
```

And critically, key sizes are **only** extracted when they're a literal
number in the source:

```python
def _literal_int(node: ast.AST) -> int | None:
    """Only a literal counts. A variable, a call, or an unpacked
    mapping yields None, and the finding records an unknown key
    size rather than inventing one."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None
```

So `rsa.generate_private_key(key_size=2048)` → key size **2048**, recorded
with confidence. But `rsa.generate_private_key(key_size=config.RSA_BITS)` →
key size **unknown**, because `config.RSA_BITS` is a variable, not a
literal, and the scanner has no way to know its actual value without running
the program (which it deliberately never does).

**For JavaScript/TypeScript, Java, and Go**, real AST parsers aren't used
(no equivalent built into Python for those languages without adding heavy
external dependencies) — instead, carefully scoped regex patterns match
known crypto API call shapes from `crypto_apis.yaml`, tuned specifically to
avoid matching the word "RSA" inside a comment or a string literal.

**Evidence levels**, from strongest to weakest:
- `CALL_SITE` — an actual function call was found (e.g.
  `rsa.generate_private_key(...)`)
- `CONFIGURATION` — a crypto-related config value was set
- `IMPORT` — only an import statement was found, no call — weaker evidence,
  because importing a module doesn't prove it's actually invoked

### 6.4 Binary — `backend/discovery/binary.py` (596 lines)

Uses LIEF to parse a compiled file's **import table** — the list of external
function names a compiled program declares it needs from other libraries at
load time. This table is a real, standard part of the ELF/PE file formats
(Linux/Windows executable formats) — it's not something LIEF invents, it's
how the operating system itself knows what to link at runtime. If the table
lists `EVP_aes_256_gcm`, that's structural proof the binary links against
AES-256-GCM, obtained without loading or running a single instruction of the
binary. Symbol name → algorithm mapping comes from `crypto_binary.yaml`.

### 6.5 Container — `backend/discovery/container.py` (787 lines — the largest single file in discovery)

Given a Docker/OCI image archive, this scanner:
1. Safely unpacks the filesystem layers to a temporary directory, with
   protections against path traversal (a malicious archive trying to write
   outside the intended folder) and unbounded decompression (a
   "zip-bomb"-style attack where a tiny file expands to consume all disk
   space)
2. Calls scanners 6.1–6.4 **on the unpacked contents** — it does not
   reimplement any detection logic itself, it's a thin wrapper around the
   other four scanners

---

## 7. INVENTORY — `backend/inventory.py` (584 lines)

Three jobs:

1. **Merge.** Collects the `CryptoFinding` lists from all five scanners into
   one combined list.
2. **Attribute.** For each finding, resolves *which company/component* it
   belongs to — e.g. a file at `payments-api/src/keys.py` belongs to the
   `payments-api` component (`discovery/attribution.py` handles this
   path-based mapping).
3. **Attach declared context.** Looks up whether a human has supplied an
   `ApplicationContext` for that component (via a policy file). If yes, it's
   attached with `is_declared = True` and a record of *where* it came from
   (`ContextSource`). If no, the context stays absent — nothing is defaulted
   in silently.

---

## 8. THE QUANTUM RISK ENGINE — `backend/quantum_risk.py` (654 lines)

This is the intellectual core of the project. Full walkthrough.

### 8.1 Step one — classify the algorithm

Every finding's `algorithm` string is looked up in
`backend/knowledge/quantum_risk.yaml`, a plain-text data file — meaning
someone with zero programming knowledge can open it and verify the
classification rules themselves. A real excerpt:

```yaml
RSA:
  category: quantum_vulnerable
  note: RSA relies on integer factorisation, which Shor's algorithm solves
        in polynomial time on a CRQC.
DSA:
  category: quantum_vulnerable
  note: DSA relies on the finite-field discrete logarithm, which Shor's
        algorithm solves on a CRQC.
Diffie-Hellman:
  category: quantum_vulnerable
  note: Finite-field Diffie-Hellman relies on the discrete logarithm...
```

This lookup is what produces the `QuantumCategory` value described in 5.4.

### 8.2 Step two — Mosca's inequality (only runs for `quantum_vulnerable` findings)

The actual function, in full, from `quantum_risk.py`:

```python
def run_mosca(lifetime, migration, crqc):
    """Returns INSUFFICIENT_INFORMATION with no calculation when any of
    the three inputs is missing — the analysis is only as good as its
    assumptions, and a missing assumption must not be filled with a guess."""
    if not (lifetime.is_present and migration.is_present and crqc.is_present):
        return MoscaStatus.INSUFFICIENT_INFORMATION, None

    x = float(lifetime.value)     # years the data must stay confidential
    y = float(migration.value)    # years migration is expected to take
    z = float(crqc.value)         # assumed years until a CRQC exists
    combined = x + y
    within = combined > z         # THIS is Mosca's inequality

    verdict = MoscaVerdict.EXPOSED if within else MoscaVerdict.ACCEPTABLE
    result = MoscaResult(
        x_data_lifetime_years=x, y_migration_years=y,
        z_horizon_years=z, verdict=verdict,
        margin_years=round(combined - z, 4),
    )
    status = MoscaStatus.WITHIN_QUANTUM_WINDOW if within \
             else MoscaStatus.OUTSIDE_QUANTUM_WINDOW
    return status, result
```

In plain terms: if (how long your data must stay secret) + (how long you'll
take to migrate) is *more* than (how many years until a quantum computer
capable of breaking this exists), you are exposed — because by the time
you've migrated, the data you were protecting will already be readable by an
attacker who recorded it years ago.

**The `crqc` value — "years until a CRQC exists" — is never a number the
system invents.** It comes from a `RiskAssumption` object that must be
explicitly supplied via policy; if it's missing, `is_present` is `False` and
the function returns `INSUFFICIENT_INFORMATION` immediately, doing no
calculation at all rather than substituting a guess.

### 8.3 Step three — the full decision path

The actual function `assess_finding()` runs this exact sequence, one branch
at a time (the real code, slightly trimmed for length):

```python
def assess_finding(finding, context, policy) -> QuantumRiskResult:
    rationale = []
    crqc = _resolve_crqc(policy)

    # Branch 1 — is this just a library capability, not confirmed usage?
    if _is_capability_only(finding):
        rationale.append(
            f"{finding.library} is linked or declared as a dependency but "
            "no algorithm usage was established... This is a capability, "
            "not confirmed use."
        )
        return QuantumRiskResult(quantum_category=CAPABILITY_ONLY, ...)

    # Branch 2 — classify the algorithm via the YAML knowledge base
    category = classify_algorithm(finding.algorithm)

    # Branch 3 — not quantum-vulnerable? Assign LOW_BASELINE or PQC_READY,
    #            done. (No Mosca calculation needed — there's no exposure
    #            window to check for an algorithm that isn't quantum-broken.)

    # Branch 4 — IS quantum-vulnerable: run Mosca (8.2 above)
    mosca_status, mosca_result = run_mosca(lifetime, migration, crqc)

    # Branch 5 — combine Mosca result + confidence into a final RiskLevel,
    #            writing a plain-English rationale sentence for every branch
    #            taken, so the conclusion is always explainable afterward.
    ...
    return QuantumRiskResult(
        finding_id=finding.finding_id,
        quantum_category=category,
        risk_level=risk_level,
        mosca_status=mosca_status,
        mosca=mosca_result,
        confidence=finding.confidence,      # copied through, never upgraded
        rationale=rationale,                # every branch's reasoning, in plain English
    )
```

**Every single `QuantumRiskResult` carries a human-readable `rationale`
list** — literal sentences explaining exactly why that conclusion was
reached. This is what lets the dashboard (and a person defending this
project) always answer "why does it say that?" with an actual sentence the
code itself generated, not an after-the-fact justification.

---

## 9. THE RECOMMENDATION ENGINE — `backend/recommendations.py` (586 lines)

### 9.1 The role-aware idea, with real data

RSA is used for two structurally different cryptographic jobs, and the
scanner (Part 6.3) records *which role* a given call site performs — because
that's visible in the code itself (a call to a signing function looks
different from a call to a key-generation-for-encryption function). The
actual YAML entry:

```yaml
RSA:
  key_establishment:
    remediation_class: hybrid
    target: ML-KEM-based hybrid key establishment
    standard: NIST FIPS 203 (ML-KEM)
    note: RSA key transport is quantum-vulnerable; combining a classical
          key-establishment mechanism with ML-KEM in a hybrid provides
          post-quantum protection while retaining classical assurance
          during transition.
  signature:
    remediation_class: pqc_native
    target: ML-DSA
    standard: NIST FIPS 204 (ML-DSA)
    note: RSA signatures are quantum-vulnerable; ML-DSA is a NIST
          post-quantum signature scheme.
```

Same algorithm name (`RSA`), two completely different recommended
replacements, selected purely by which `role` the finding recorded. This is
looked up directly — the recommendation engine does not run any of its own
crypto-knowledge logic, it reads this table.

### 9.2 What happens when the role is unknown

If the scanner couldn't determine the role (e.g. from certificate metadata
alone, where the specific runtime use isn't always clear), the recommendation
engine does **not** guess. It returns a result explaining that the role
needs to be established before a specific replacement can be safely
recommended — recommending ML-KEM for something that turns out to be a
signature use would be actively wrong, so silence (with an honest
explanation) is the correct behavior, not a guess.

### 9.3 No invented numbers

The recommendation's `note` field never states a made-up benchmark ("ML-KEM
is 30% slower than RSA") unless that number genuinely exists somewhere
verified in the system. This is enforced by the same style of test that
checks for overclaiming elsewhere (Part 14).

---

## 10. MIGRATION PRIORITY — `backend/migration_priority.py` (523 lines)

### 10.1 The decision function, for real

```python
def prioritize(recommendation, context=None) -> MigrationPriorityResult:
    """Rules are applied in precedence order; the first match wins and
    records why. The Phase 7 risk level and Mosca status, and the Phase 8
    remediation class, are read from the recommendation and NEVER
    recomputed."""
    criticality = _resolve_criticality(context)
    remediation = recommendation.remediation_class

    # Rule 1 — nothing to migrate (already post-quantum, or a healthy
    #          classical primitive like AES-256): NO_ACTION.
    if remediation is RemediationClass.NONE_REQUIRED:
        return _result(priority=NO_ACTION, ...)

    # (further rules, each checked in order:)
    # Rule 2 — quantum-vulnerable AND within the Mosca exposure window
    #          AND the component is declared business-critical → IMMEDIATE
    # Rule 3 — quantum-vulnerable AND within the window, but criticality
    #          is NOT declared critical (or not declared at all) → HIGH,
    #          not IMMEDIATE. This is the rule that stops the system from
    #          assuming importance nobody actually told it.
    # Rule 4 — outside the Mosca window → PLANNED (not urgent, but real work)
    # Rule 5 — Mosca returned INSUFFICIENT_INFORMATION → EVIDENCE_REQUIRED
    # Rule 6 — a classical (non-quantum) issue, e.g. MD5 → its own bucket,
    #          reflecting real but non-quantum-related urgency
```

### 10.2 Why risk ≠ priority, worked with real numbers

Two findings, both classified `CRITICAL` risk by the quantum engine:

- Finding A: RSA-2048 in `payments-api`, and a human declared
  `payments-api` as `business_criticality: CRITICAL` in the policy file →
  **priority = IMMEDIATE**
- Finding B: the exact same RSA-2048 issue, but in a component where nobody
  ever filled in a policy file → `is_declared = False` →
  **priority = HIGH**, not IMMEDIATE, because the system has no actual
  evidence this component is business-critical

Same technical risk. Different priority. That difference is the entire
point of separating risk (Part 8) from priority (this part).

### 10.3 The roadmap — deterministic grouping, nothing new decided

```python
def build_roadmap(results, recommendations=None):
    """The grouping is a deterministic consequence of the priority —
    no new decision is made here. NO_ACTION items are excluded, because
    they are not work."""
```

`build_roadmap()` does not make any new judgment calls — it purely sorts
already-computed `MigrationPriorityResult` objects into the six buckets by
their existing `priority` field, and drops anything `NO_ACTION` (since
"no action needed" isn't a roadmap item). The function that runs everything
also guarantees deterministic ordering — same input always produces the same
output order, sorted by `(priority_rank, finding_id)` — which matters for
reproducible demos and reliable tests.

---

## 11. CBOM — `backend/cbom.py` (504 lines)

Takes the full list of findings and serializes them into a **CycloneDX
1.6** document using `cyclonedx-python-lib`. This isn't a custom JSON format
invented for this project — CycloneDX is a real, external, published
standard, meaning a security tool that has never heard of Aegis PQC could
still open this exact file and correctly understand what's in it. The
library also **validates** the output against the official schema before
it's considered done — so "the file looks plausible" is checked
automatically against "the file is actually valid," not just assumed.

---

## 12. THE ORCHESTRATOR — `backend/ecdat_service.py` (316 lines)

This file is the seam between backend and frontend. The frontend calls
exactly one function:

```python
def run_pipeline(target_path):
    findings = []
    findings += certificates.scan(target_path)
    findings += dependencies.scan(target_path)
    findings += source.scan(target_path)
    findings += binary.scan(target_path)
    # (container scanning happens separately, given an image archive)

    inventory_result = inventory.build(findings)
    risk_results = [quantum_risk.assess_finding(f, ctx, policy)
                     for f in inventory_result.findings]
    recommendations = [recommendations.recommend(r) for r in risk_results]
    priorities = migration_priority.prioritize_batch(recommendations)
    roadmap = migration_priority.build_roadmap(priorities, recommendations)

    return PipelineResult(findings=..., risk=..., recommendations=...,
                           priorities=..., roadmap=..., cbom=...)
```

(Simplified for readability — the real function handles error cases,
progress reporting for the UI, and per-surface toggles — but this is the
actual sequence.) **Everything above this function is "backend." Everything
that calls this function is "frontend."** That line is the one to point at
if anyone asks where the boundary is.

---

## 13. THE FRONTEND

### 13.1 `ecdat_app.py` (859 lines) — the dashboard itself

Ten tabs, created with one Streamlit call:

```python
tabs = st.tabs(["Overview", "Discovery", "Inventory", "CBOM",
                 "Quantum Risk", "Recommendations", "Migration",
                 "Reports", "Settings", "Security Lab"])
```

Every tab's code follows the same pattern: get the already-computed
`PipelineResult` from `st.session_state` (put there when "LOAD DEMO ESTATE"
was clicked and `run_pipeline()` ran), format it via `ecdat_view.py`, draw it
via components from `ecdat_style.py`. No tab computes a risk level, a
recommendation, or a priority — that already happened before any tab code
runs.

### 13.2 `ecdat_view.py` (353 lines) — formatting only

Small, pure functions — no side effects, no decisions, just translation.
Example shape:

```python
def format_risk_level(level: RiskLevel) -> tuple[str, str]:
    """Returns (display_text, color) for a RiskLevel enum value."""
    return {
        RiskLevel.CRITICAL: ("CRITICAL", "#ff6472"),
        RiskLevel.HIGH: ("HIGH", "#f3b85b"),
        ...
    }[level]
```

Because these functions take a plain value in and return a plain value out
— no Streamlit calls inside them — they're tested directly with ordinary
`assert` statements, without even starting a Streamlit server. That's what
`tests/ecdat/test_phase10.py` does.

### 13.3 `ecdat_style.py` (979 lines) — the visual design system

This file is CSS (the language browsers use to control appearance) written
as a big Python string and injected into the page with
`st.markdown(..., unsafe_allow_html=True)`. It defines:

- **Six shades of near-black** used as background layers, so panels read as
  physically layered instead of flat
- **A restrained color palette** — cyan for primary/active state, violet for
  the CBOM/analytical screens, green for verified/safe, amber for warning,
  red for critical — deliberately used sparingly (most of the interface
  stays neutral gray, color only appears where it's meaningful)
- **Custom animations** — a multi-second animated boot sequence on first
  load, an animated horizontal timeline for the Mosca inequality (showing
  the data-lifetime bar, migration-time bar, and the CRQC threshold line, all
  drawn to scale from real numbers), a flowing "pipeline" indicator
- Every animation is wrapped in `@media (prefers-reduced-motion: no-preference)`
  — a real, standard accessibility rule — meaning if the visitor's operating
  system says "reduce motion," none of this animates
- **Zero external dependencies** — no font downloaded from Google Fonts, no
  icon library loaded from a CDN, nothing that requires an internet
  connection to render correctly. This is checked by an automated test.

### 13.4 Session state, concretely

```python
if st.button("LOAD DEMO ESTATE"):
    result = svc.run_pipeline(demo_estate_path)
    st.session_state["pipeline_result"] = result

result = st.session_state.get("pipeline_result")
if result is None:
    st.info("Click Load Demo Estate to begin")
else:
    # render all ten tabs using `result`
```

This is the entire flow: click once, backend runs once, result is cached in
session state, every tab reads from that same cached object until the
button is clicked again.

---

## 14. TESTING — `tests/` (828 tests total)

### 14.1 What a test actually looks like

```python
def test_rsa_key_establishment_maps_to_hybrid():
    finding = _finding("RSA", role="key_establishment", key_size=2048)
    result = recommend(finding, risk=...)
    assert result.remediation_class == RemediationClass.HYBRID
    assert "ML-KEM" in result.target
```

This directly tests the exact behavior described in Part 9.1 — plugging in a
known input and asserting the real function produces the documented output.
There are hundreds of tests shaped exactly like this, one for nearly every
branch of every decision tree described in this document.

### 14.2 The "honesty audit" — `tests/test_release.py`

Not a functional test — a test that scans the *language* the code and UI
use. It fails the build if any file contains phrases like "unbreakable,"
"100% secure," or "guaranteed safe," and separately checks that no
production file imports networking libraries (`socket`, `requests` used for
outbound calls) or spawns a subprocess. This is what makes it defensible to
say "the tool cannot overclaim — there's a test for it, not just a promise."

### 14.3 Running everything

```bash
python -m pytest tests -q
```

828 tests, expected to pass every time, run twice from a clean state before
any handoff (to rule out a test that only passes by accident of leftover
state from a previous run).

---

## 15. THE SECURITY LAB — `frontend/app.py`, `frontend/ui.py`, and the legacy `backend/*.py` files

Before ECDAT, an earlier project ("AegisPQC") demonstrated the
Harvest-Now-Decrypt-Later attack live, including a "Q-Day" simulation that
genuinely factors a small, deliberately undersized RSA key on stage using
real classical mathematics (chosen small enough that factoring finishes in a
few seconds, purely to make the demonstration watchable — it is real math,
not a fake animation).

This project is **completely frozen** — unmodified since ECDAT development
began, verified by comparing file checksums (a cryptographic fingerprint of
the file's exact bytes) before and after every later change. It runs as a
**separate Streamlit application**:

```bash
streamlit run frontend/app.py        # Security Lab
streamlit run frontend/ecdat_app.py  # ECDAT — the main product
```

It shares only the visual design language (`frontend/ui.py`) with ECDAT, not
any pipeline logic. It's useful as a short, visceral opening ("here's why
this matters") but is architecturally separate from the ECDAT pipeline this
document describes.

---

## 16. ONE FINDING, TRACED START TO FINISH

To make the whole pipeline concrete, here is one real path through the
system, with realistic values at every step.

**1. On disk**, `payments-api/src/keys.py` line 12 contains:
```python
key = rsa.generate_private_key(key_size=2048, ...)
```

**2. Discovery (source scanner, 6.3):** `ast.parse()` builds a tree, walks
it, finds this `Call` node, reconstructs the dotted name `rsa.generate_
private_key` via `_dotted_name()`, matches it against the knowledge base,
extracts `2048` via `_literal_int()` because it's a literal, and produces:

```python
CryptoFinding(
    finding_id="fnd_a1b2c3",
    algorithm="RSA", key_size=2048,
    confidence=Confidence.HIGH,
    source_type=SourceType.SOURCE_CODE,
    location="payments-api/src/keys.py", line=12,
    component="payments-api",
    raw_detail={"role": "key_establishment"},
)
```

**3. Inventory:** attributes this to component `payments-api`; looks up
whether a human declared `ApplicationContext` for `payments-api` — say yes,
with `business_criticality: CRITICAL`, `data_lifetime_years: 10`.

**4. Quantum Risk:** looks up `"RSA"` in `quantum_risk.yaml` →
`quantum_vulnerable`. Runs `run_mosca()`: if `data_lifetime (10) +
migration_time (say 3) > crqc_horizon (say 8)`, that's `13 > 8` → `True` →
`WITHIN_QUANTUM_WINDOW`. Combined with the declared `CRITICAL` business
criticality → final `RiskLevel.CRITICAL`, with a written rationale sentence.

**5. Recommendations:** role is `"key_establishment"` → looks up
`RSA.key_establishment` in `recommendations.yaml` → `remediation_class:
hybrid`, `target: ML-KEM-based hybrid key establishment`.

**6. Migration Priority:** `remediation_class = HYBRID`, Mosca status =
`WITHIN_QUANTUM_WINDOW`, criticality = declared `CRITICAL` → matches Rule 2
→ **priority = IMMEDIATE**.

**7. Roadmap:** this finding lands in the `IMMEDIATE` bucket, shown at the
top of the Migration tab.

**8. Dashboard:** `ecdat_view.py` formats `RiskLevel.CRITICAL` as red text,
`ecdat_style.py` draws the Mosca timeline visual using the real `x=10,
y=3, z=8` values, and the finding appears in the Inventory tab, the
Quantum Risk tab, the Recommendations tab, and the Migration tab —
**the same `finding_id` linking every one of those four appearances back to
this single fact.**

That's the entire system, traced through one real value.

---

## 17. FULL FILE INDEX

| File | Lines | Role |
|---|---|---|
| `backend/model.py` | 1,273 | Shared data vocabulary — read first |
| `backend/discovery/source.py` | 1,045 | Source-code scanner (largest scanner) |
| `backend/scanner.py` | 1,020 | Legacy project's own scanner (not ECDAT) |
| `backend/service.py` | 895 | Legacy project's service layer (not ECDAT) |
| `backend/discovery/container.py` | 787 | Container scanner |
| `frontend/ecdat_style.py` | 979 | Design system / CSS / animations |
| `frontend/app.py` | 1,527 | Security Lab dashboard (frozen) |
| `frontend/ui.py` | 869 | Shared visual components (frozen) |
| `frontend/ecdat_app.py` | 859 | ECDAT dashboard — the 10 tabs |
| `backend/discovery/dependencies.py` | 626 | Dependency-manifest scanner |
| `backend/quantum_risk.py` | 654 | Risk classification + Mosca |
| `backend/discovery/binary.py` | 596 | Compiled-binary scanner |
| `backend/recommendations.py` | 586 | Role-aware remediation engine |
| `backend/inventory.py` | 584 | Merge + context resolution |
| `backend/discovery/certificates.py` | 332 | Certificate scanner |
| `backend/cbom.py` | 504 | CycloneDX export |
| `backend/migration_priority.py` | 523 | Priority decision tree + roadmap |
| `backend/ecdat_service.py` | 316 | The single orchestrator function |
| `frontend/ecdat_view.py` | 353 | Pure formatting functions |
| `backend/discovery/attribution.py` | 163 | File-path → component mapping |

Run `python -m pytest tests -q` for the 828-test verification described in
Part 14.
