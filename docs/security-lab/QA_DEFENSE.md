# AegisPQC — Q&A Defense Pack

**For Round 2 judging. Panel includes engineers from NVIDIA, US Bank, and
similar.**

---

## How to use this

Do not memorise answers. Memorise the **structure** of each answer:

1. Direct answer in one sentence
2. The evidence — a file, a test, or a number on screen
3. The limit — what it does *not* prove

That third step is the one that wins. A judge who asks a hard question is
testing whether you know your own boundaries. Volunteering the limit converts a
challenge into a demonstration of rigour.

**If you do not know, say so.** "I don't know — here's how I'd find out" beats a
confident wrong answer every single time, and these judges can tell the
difference instantly.

---

# TIER 1 — Near-certain questions

## "Did you actually break RSA, or is that faked?"

**This is the question. Have this one cold.**

> "It is real. Against the demo key we read only the public modulus off the
> wire, factor it with Brent's variant of Pollard's rho, reconstruct the private
> exponent from the recovered primes, and decrypt. The private key is never
> consulted.
>
> There's a test that proves it — `test_qday_attack_only_uses_public_data`
> deletes every private key from the database and then runs the attack. It still
> succeeds. I can run it right now if you'd like.
>
> The limit: that's an 88-bit modulus, not 2048. We did not break RSA-2048 and we
> don't claim to."

**If they want it run:** `python -m pytest tests/test_suite.py -k only_uses_public -v`

---

## "Why 88 bits? Isn't that just picking a number you can break?"

> "Yes — deliberately, and it's labelled demo-scale everywhere it appears.
>
> The alternative was to fake a 2048-bit break, which is what most PQC demos do
> and which falls apart under one question. We shrank the problem until it was
> honestly solvable on this hardware, solved it for real, then showed what
> changes at full scale.
>
> The mathematics is identical. What changes is the machine required.
>
> 88 specifically came from measurement, not taste. Pollard's rho is randomised,
> so what matters for a live demo is worst case, not median. At 96 bits the worst
> of six trials was 9.6 seconds — that would stall a pitch. At 88 the spread is
> 1.7 to 3.1. It's documented in `config.py` with the measurement table."

---

## "How is this different from any other Kyber demo?"

> "Three things.
>
> First, the break is real rather than animated — with a test that proves the
> private key is never touched.
>
> Second, we refuse to overclaim, and that's automated. There's an audit in
> `test_release.py` that fails the build if any of fourteen overclaiming phrases
> appear anywhere in the product. An earlier version of our code said 'QUANTUM
> IMMUNE' and printed 'Attempting BKZ reduction' — which was false, we attempt
> nothing. The audit caught both and we fixed them.
>
> Third, and this is the real difference: most demos stop at 'Kyber is safe.' The
> question an organisation actually has is 'where am I still exposed and what do
> I fix first?' That's the scanner and the migration plan."

---

## "Is the scanner really parsing those files, or is it a lookup table?"

> "Parsing. Two tiers.
>
> First it hands the file to the `cryptography` library — that gives exact key
> sizes, curve names, certificate subjects. If that fails, it walks the DER and
> extracts the algorithm identifier OID directly.
>
> Every finding carries the OID it was matched on. You can run `openssl
> asn1parse` on the same file and confirm — ML-KEM-768 is
> 2.16.840.1.101.3.4.4.2.
>
> The second tier matters because a real estate contains algorithms your library
> has never heard of. There's a test that synthesises an ML-DSA-65 key that pyca
> cannot load, and asserts the scanner still classifies it correctly from the
> DER."

---

## "What happens if I point it at a file it can't handle?"

> "It reports UNKNOWN and continues. The demo enterprise deliberately ships a
> truncated file to prove that.
>
> That's a design decision rather than error handling. An asset nobody can parse
> is exactly the asset a migration programme loses track of — so it gets its own
> phase in the plan, flagged for manual review. Silently skipping it would be
> worse than crashing.
>
> There's a parametrised test that throws empty files, binary garbage, malformed
> base64, and truncated PEM at it. None of them raise."

---

## "How do I know your report doesn't leak key material?"

> "Three layers.
>
> The report is assembled only from data that already passed the scanner's
> no-secret guarantee. Report generation then runs a defensive sweep and
> **raises** rather than returning if it finds a PEM header or a private-key
> field name. And there's a test that feeds the guard bad content to confirm it
> actually fires — a check that can never trigger proves nothing.
>
> Separately, there are tests that take the hex of every private key on disk and
> assert it appears in no API response, no UI element, no forensic view, and no
> export."

---

# TIER 2 — Likely from a banking or risk perspective

## "How did you decide the risk ratings? What's the model?"

> "Retention-driven, and deliberately simple enough to explain in one breath.
>
> A quantum-vulnerable algorithm protecting data with a 20-year-plus
> confidentiality requirement is CRITICAL. Seven to nineteen is HIGH. Under seven
> is MEDIUM. Critical data sensitivity escalates one level.
>
> The reasoning: harvest exposure is a function of how long the ciphertext has to
> stay secret, not the algorithm alone. Your 50-year records archive and your
> 2-year system can run identical RSA and have completely different exposure.
>
> That's also why the tool never has to predict a Q-Day date. The date is the
> thing nobody knows; the retention requirement is the thing you already know."

---

## "Where does the retention number come from in a real deployment?"

> "Here it's a sidecar `asset.json` file, which is the honest prototype answer. In
> a real deployment it would come from a CMDB or asset inventory — that's the
> integration point, and it's why the risk model reads it as declared business
> context rather than inferring it.
>
> Inferring retention from a certificate would be a guess dressed up as data."

---

## "Your readiness score is 25 out of 100. How is that calculated?"

> "Six numbers, all displayed in the UI. Each asset earns a share of 100 weighted
> by its rating — SAFE 100%, LOW 75%, MEDIUM 40%, HIGH 20%, UNKNOWN 10%, CRITICAL
> 0%.
>
> That's the whole formula. No hidden weights.
>
> It's deliberately simple because a score nobody can explain is a score nobody
> should act on. If a CISO can't reconstruct it on a whiteboard, they'll ignore
> it."

---

## "What would this cost us to actually migrate?"

> "I'd be careful here — the tool gives effort *bands*, not day estimates. A
> precise number derived from a file scan would be a fabrication.
>
> What it does give you is sequencing, which is the expensive decision. Getting
> the order wrong means spending a quarter on a 2-year system while a 50-year
> archive keeps accumulating harvestable traffic.
>
> The measured engineering cost we *can* state: ML-KEM adds roughly four times
> the wire bytes per handshake versus RSA-2048, and it's faster on CPU. For a
> bank the bandwidth number is the one that drives capacity planning."

---

## "Is ML-KEM approved for our use? What about compliance?"

> "ML-KEM is NIST FIPS 203, standardised in August 2024. ML-DSA is FIPS 204 for
> signatures. The hybrid we implement mirrors X25519MLKEM768, which browsers and
> CDNs have already deployed for TLS 1.3.
>
> I'd be careful about claiming anything on your specific regulatory position —
> I'm not going to guess at banking compliance requirements. What I can say is
> that the standards exist and the constructions are the deployed ones rather
> than something we invented.
>
> If you want current federal timelines, I'd check CNSA 2.0 and the OMB guidance
> directly rather than take my word on dates."

---

# TIER 3 — Likely from a hardware or performance perspective

## "You say ML-KEM is faster. Faster than what, measured how?"

> "Measured on whatever machine is running it, at the iteration count on the
> slider — it's not quoted from a paper. Right now it's showing [read the
> screen]× on key generation versus RSA-2048.
>
> Two caveats I'd flag. It varies between runs and between machines; I've seen
> 142× and 218× on different days, which is why I say 'two orders of magnitude'
> rather than a fixed figure. And RSA-2048 keygen is sampled over fewer
> iterations because each one takes tens of milliseconds — that's disclosed in
> the output.
>
> The comparison is apples-to-apples in that all three modes share an identical
> symmetric half. The only variable is key establishment."

---

## "What's the actual bottleneck? Where would this hurt at scale?"

> "Bandwidth, not compute. ML-KEM-768 is 1184 bytes of public key and 1088 bytes
> of ciphertext — both fixed by FIPS 203. That's about 1116 bytes of overhead per
> handshake against RSA's 284.
>
> At one connection that's irrelevant. At CDN scale that's the entire
> conversation, and it's why the hybrid deployments have been contentious — the
> hybrid is worse again, about 1150.
>
> The CPU side genuinely favours ML-KEM, so this is not a speed-versus-security
> trade. It's a bytes-versus-security trade."

---

## "Why doesn't Shor's algorithm work on lattices?"

> "Shor's solves the hidden subgroup problem over abelian groups — that's what
> factoring and discrete log reduce to. Module Learning With Errors isn't of that
> form, so the reduction doesn't exist.
>
> That's why the quantum speedup against lattices is so small: best known goes
> from roughly 2^181 classical to 2^165 quantum. Sixteen bits. Against RSA the
> same column goes from infeasible to hours.
>
> I'd stress those are estimates against *currently known* attacks, not proofs.
> Lattice cryptanalysis is active — if someone finds a better reduction those
> numbers move."

---

## "Could you run the real Shor's algorithm on simulated qubits?"

> "Not meaningfully, and I'd rather say that than fake it.
>
> Simulating enough qubits to factor anything non-trivial needs exponential
> classical memory. People have run Shor's on 15 and 21 with heavy
> pre-optimisation, and those demonstrations are mostly about the circuit, not the
> factoring.
>
> Gidney and Ekerå put RSA-2048 at around 20 million physical qubits and 8 hours.
> Nothing simulates that. Doing a classical break honestly says more than
> simulating a toy quantum one."

---

# TIER 4 — Architecture and engineering

## "Why Streamlit? Why not a real frontend?"

> "Time and reliability. The demo has to run on an unfamiliar laptop with no
> network.
>
> The architectural decision I'd actually defend is that the dashboard calls a
> shared service layer **in-process** rather than over HTTP to our own FastAPI.
> Two processes alive during a presentation is two ways to die — port collision,
> cold start, firewall prompt. The API is real and tested and available at
> `/docs`, but nothing in the demo depends on it running.
>
> The design system is extracted into `ui.py` so the presentation layer is
> swappable. If this became a product, the service layer and everything below it
> is unchanged."

---

## "How do I know adding all this UI didn't break your cryptography?"

> "The four verified modules — `crypto_engine`, `database`, `simulator`,
> `scanner` — have zero edits in the latest phase. That was a hard constraint.
>
> The procedural attack view is a good example. It's the most visually impressive
> addition, and it lives in a separate module that *parses the simulator's
> output* rather than changing how the attack runs. The presentation layer
> structurally cannot introduce a defect into the factorisation.
>
> And the test suite grew from 169 to 244 without weakening anything. Where an old
> expectation went stale — the tab count changed — I updated it to assert the new
> behaviour and made it stronger. It now checks tab *labels*, so it fails on a
> rename or reorder, not just a recount."

---

## "How long did this take, and how much is yours?"

Answer honestly about your process and your collaboration. Do not overstate
solo authorship — these judges have seen AI-assisted projects and respect
candour far more than a claim that doesn't survive a follow-up.

What you can defend without qualification: **every architectural decision, every
trade-off, and why each one was made.** That is what they are actually testing.
Know `config.py`, `simulator.py::_attack_rsa`, and `scanner.py::assess_risk`
line by line — those three carry the project.

---

## "What would you build next?"

> "Three things, in order.
>
> PKCS#12 and JKS support, because that's what's actually in an enterprise
> estate and we only read PEM and DER today.
>
> Real post-migration verification. Right now our VERIFY stage checks the plan's
> internal consistency — it does *not* re-scan a migrated estate, because we never
> modify anything. That's declared as partially implemented in the workflow
> metadata rather than hidden.
>
> And a CMDB integration so retention comes from the organisation's own asset
> inventory rather than a sidecar file."

---

# TIER 5 — Hostile or trap questions

## "Isn't this whole threat overblown? Q-Day might be decades away."

> "It might be. I deliberately don't predict a date, and I'd distrust anyone who
> does.
>
> But the date isn't the variable that matters. If you're holding data with a
> 25-year confidentiality requirement, you need it secret until 2051. The
> question isn't when Q-Day arrives — it's whether it arrives before your
> retention window closes. For long-lived data that's a bet, not a certainty.
>
> That's exactly why the risk model is retention-driven rather than
> date-driven. It's an argument you can make without a prophecy."

---

## "Your demo enterprise is fictional. Isn't that convenient?"

> "It's fictional, and it's generated locally so the demo works air-gapped. But
> the *cryptographic material is genuine* — you can open those PEM files in
> OpenSSL and get the same key sizes the scanner reports.
>
> The convenience I'd own is the retention metadata. Those numbers are chosen to
> make a clean story. In a real estate they'd come from a CMDB and they'd be
> messier.
>
> If you have real certificates you'd like scanned, the tool takes a directory
> path — it doesn't care that the demo enterprise exists."

---

## "You've got AES-256-GCM everywhere. Isn't symmetric crypto also at risk?"

> "Much less so, and this is a distinction I'd want to be precise about.
>
> Grover's algorithm gives a quadratic speedup against symmetric ciphers, so
> AES-256 retains roughly 128 bits of post-quantum security. That's why nobody's
> replacing AES and why our migration plan explicitly keeps it unchanged.
>
> There are caveats — Grover parallelises poorly, so the practical speedup is
> worse than the theoretical one. But the headline is right: the asymmetric layer
> is the urgent problem."

---

## "If I gave you a real RSA-2048 key right now, could you break it?"

> "No. Nobody could.
>
> And the tool will tell you that itself — if you feed it a real RSA-2048 packet,
> it explicitly refuses to fabricate a break and prints why. There's a test named
> `test_qday_refuses_to_fake_rsa2048` that fails the build if that path ever
> returns BREACHED.
>
> That refusal is deliberately in the product rather than in a disclaimer,
> because the temptation to fake it is exactly what makes most demos in this space
> untrustworthy."

---

## "What's the weakest part of this project?"

**Answer this honestly. Deflecting here costs you more than the weakness does.**

> "The gap between the demonstration and the assessment tool.
>
> The Q-Day break is a real cryptographic result. The scanner is a real parser.
> But the bridge between them — 'therefore migrate this asset first' — rests on
> retention metadata that a real deployment would have to source properly, and on
> a risk model I designed rather than one derived from a standard.
>
> The model is defensible and it's fully transparent, but it's a judgement. If I
> had more time that's where I'd want external validation."

---

# Quick reference — numbers to know

| Fact | Value |
|---|---|
| Demo modulus | 88-bit (2 × 44-bit primes) |
| Break time | 0.6 – 2.8 s, varies (**say "under three seconds"**) |
| ML-KEM-768 public key | 1184 B (fixed by FIPS 203) |
| ML-KEM-768 ciphertext | 1088 B (fixed by FIPS 203) |
| ML-KEM-768 OID | 2.16.840.1.101.3.4.4.2 |
| Wire overhead | RSA +284 B · ML-KEM +1116 B · Hybrid +1150 B |
| ML-KEM speed advantage | **"Two orders of magnitude"** — varies per run |
| Scanner result | 9 assets · 6 vulnerable · 2 ready · 1 unidentified |
| Readiness score | 25 / 100 — URGENT MIGRATION REQUIRED |
| Migration queue | 8 assets · 4 critical · 4 phases |
| ML-KEM attack cost | ~2^181 classical, ~2^165 quantum (estimates) |
| RSA-2048 via Shor's | ~20M physical qubits, ~8 h (Gidney & Ekerå 2019) |
| Tests | 244 |
| Standards | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) |

---

# The three sentences that carry the project

1. **"We did not break RSA-2048 — nobody has. We shrank the problem until it was
   honestly solvable today, broke it for real, and showed the only variable is
   time."**

2. **"Encryption doesn't stop you being recorded. It decides what the recording
   is worth later."**

3. **"Any scanner can list vulnerable assets. The hard question is which of forty
   systems you fix first — and the answer is driven by how long the data has to
   stay secret, not by the algorithm alone."**
