# AegisPQC — Live Demo Runbook

**Print this. Hold it while you present.**

---

# T-minus 30 minutes — setup

Run these in order. Do not skip the pre-flight.

```powershell
cd path\to\aegis_pqc
.\.venv\Scripts\Activate.ps1
```

```powershell
.\preflight.ps1
```

Wait for **ALL SYSTEMS GO** and 14 green checks. This takes about a minute
because it runs the full test suite. If anything is red, fix it before doing
anything else — see Failure Recovery below.

```powershell
.\run_demo.ps1
```

The dashboard opens at `http://localhost:8501`.

### Then do these four things before you stand up

1. **Click LOAD PRESENTATION DEMO** in the sidebar. Wait for the green
   confirmation.
2. **Click LOAD DEMO ENTERPRISE** on the PQC Readiness tab. This warms the
   scanner cache — first run generates an RSA-3072 key and takes a second longer.
3. **Click RUN BENCHMARKS** once. Same reason.
4. **Run the Q-Day attack once, then click LOAD PRESENTATION DEMO again.** This
   confirms the factorisation works on this machine today and resets the archive
   to unbroken so the reveal is clean.

After step 4 every expensive path is warm and every tab renders instantly.

### Browser setup

- **Zoom to 80%** (Ctrl+Minus twice). At 100% the metric tiles wrap on a
  projector and the layout looks cramped.
- **F11 for fullscreen.** Hide the bookmarks bar.
- **Collapse the sidebar** (« button) once you have loaded the demo — it frees
  significant width for the tabs. Reopen it only if you need to reset.
- Close every other tab. A notification popping up mid-demo is avoidable.

---

# T-minus 2 minutes — final check

- [ ] Dashboard open, Overview tab showing, **25/100** visible
- [ ] Sidebar says "All stages are armed and ready to demonstrate"
- [ ] Archive shows **3 packets**, none marked BREACHED
- [ ] Laptop plugged in — power-saving throttles CPU and slows the factorisation
- [ ] Terminal window open behind the browser (for the fallback)
- [ ] Water within reach

---

# The click sequence

Follow `PITCH.md` for the words. This is the mechanical sequence only.

| # | Action | Watch for |
|---|---|---|
| 1 | **Overview** tab (already open) | Score 25/100, six tiles |
| 2 | **Quantum Vault** → select **Hybrid** | Security posture turns green |
| 3 | Click **ENCRYPT AND SEND** | Green success, four metric tiles, 7 pipeline steps |
| 4 | **HNDL Hoard** | Table shows all three algorithms |
| 5 | Scroll to **Forensic packet view** | "PRIVATE KEYS NOT CAPTURED" banner |
| 6 | **Q-Day Simulator** → select the **RSA-DEMO** packet | |
| 7 | Click **EXECUTE Q-DAY ATTACK** | **Stay silent while it runs.** Then 8 green steps, recovered merger brief |
| 8 | Select the **ML-KEM-768** packet → attack | Green RESISTS KNOWN ATTACKS |
| 9 | Scroll up to the **three honesty panels** | Deliver slowly |
| 10 | **Benchmarks** → **RUN BENCHMARKS** | Wait ~2s. Point at the speedup, then the wire overhead |
| 11 | **PQC Readiness** → **LOAD DEMO ENTERPRISE** | 9 assets, gauge at 25 |
| 12 | Expand any **CRITICAL** asset | OID, VERIFIED badge, reasoning list |
| 13 | **Migration Plan** | Queue, #1 = Records Archive, 50y |
| 14 | Expand **#1** | "Why this position" |
| 15 | **Overview** | Close on posture |

**Total clicks: 15.** Rehearse the sequence until your hands know it, so you can
look at the audience instead of the screen.

---

# Failure recovery

Every one of these has been thought through. Stay calm — the fallbacks are
genuinely good.

### The factorisation is taking longer than expected

Pollard's rho is randomised. It normally finishes under three seconds but can
take longer.

**Say:** *"This is randomised — Pollard's rho picks a random starting point, so
the runtime varies. That variance is itself the point: this is real search, not
a lookup."*

It aborts cleanly at 60 seconds; it cannot hang. If it does abort, click again —
a fresh random start.

### A tab throws an error

**Every tab works independently.** Skip it and continue; nothing downstream
depends on it.

If the Q-Day tab specifically fails, use the terminal fallback below — it is
arguably more impressive anyway.

### Streamlit disconnects or the page goes blank

Refresh the browser (F5). Session state is rebuilt from the database, so the
archive and the estate survive. You lose only the "last sent" panel.

If refresh does not help, in the terminal press Ctrl+C and:

```powershell
.\run_demo.ps1
```

The app self-seeds on load, so it comes back presentable.

### Total UI failure — the terminal fallback

This is your safety net. Switch to the terminal:

```powershell
python seed_demo.py
```

That runs the entire story in the console: key generation, three sends, the
harvest, the real Q-Day attack with full trace, the extrapolation, and the
scanner pre-flight. It is colourised and readable on a projector.

**Say:** *"The UI is a presentation layer over a service layer — let me show you
the same thing from the engine directly."*

Judges respect this more than a polished UI. It shows the demo was not the
product.

### A judge asks you to prove the attack is real, live

```powershell
python -m pytest tests/test_suite.py -k only_uses_public -v
```

That test deletes every private key from the database and runs the attack
anyway. It takes a few seconds and prints PASSED.

### The laptop is slow / running on battery

Plug in. If you cannot, drop the benchmark slider to **5 iterations** before
running it, and expect the factorisation toward the upper end of its range.

### PowerShell blocks the scripts

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Session-scoped, no admin rights, reverts when the window closes.

---

# Resetting between judges

If you present more than once:

1. Click **LOAD PRESENTATION DEMO** in the sidebar
2. Wait for the green confirmation

That rebuilds the database, regenerates keys, re-sends the three messages,
**clears the attack history**, and confirms the estate is ready. Takes under a
second warm.

The attack-history clear is the important part — without it the second judge
sees packets already marked BREACHED and the reveal is spoiled.

---

# If you have extra time in Q&A

Things worth showing that are not in the 10-minute script:

**The API.** `.\run_demo.ps1 -WithApi`, then `http://127.0.0.1:8000/docs`. A
typed OpenAPI contract. Thirty seconds, good architecture signal.

**The test suite.** `python -m pytest tests/ -q` → 244 passed. Then point at
`test_release.py` — the automated honesty audit.

**The honesty audit specifically.**
`python -m pytest tests/test_release.py -k overclaiming -v` — fourteen
parametrised tests, one per forbidden phrase.

**The OID proof.** If a judge is technical and sceptical about the scanner:

```powershell
openssl asn1parse -in data\demo_enterprise\quantum-safe-service\mlkem768_public.pem
```

The OID `2.16.840.1.101.3.4.4.2` appears in the output. Same value the scanner
reports.

**Export a report.** Migration Plan tab → Prepare Markdown report → Download.
Hand it over. It contains the full assessment and no key material.

---

# The mindset

You are not defending a student project. You built something with a defensible
position that most professional demos in this space do not have: **it refuses to
overclaim, and that refusal is automated.**

When a judge pushes, the honest answer is almost always the strong one. You have
a test for nearly every claim. Point at it.

And if you genuinely do not know something — say so, then say how you would find
out. On a panel of senior engineers that reads as competence, not weakness.

Good luck.
