# AegisPQC — 10-Minute Pitch Script

**Round 2 Final · Track 02: Cybersecurity for the Future / Q-Day Zero**

---

## Before you read the script

Three rules that matter more than any sentence below.

**1. Never quote a number that moves.**
The Q-Day factorisation takes between 0.6 and 2.8 seconds depending on the run.
The ML-KEM speedup measured 142× one day and 218× the next — it is a live
measurement on whatever machine you are standing at. Say **"under three
seconds"** and **"two orders of magnitude"**, then point at the screen. The
screen shows the exact figure. If you state "1.3 seconds" and it takes 2.6, a
sharp judge notices, and now they are auditing everything else you said.

**2. The demo is the argument. Slides are not.**
Every claim in this script is something the audience watches happen. If you find
yourself explaining instead of showing, you have drifted.

**3. Say what you did not do, before you are asked.**
This is the single highest-value habit in this room. The judges include people
who have watched a hundred projects overstate their results. Pre-empting the
overclaim is what separates you from all of them, and it takes eight seconds.

---

## Timing map

| Time | Beat | Screen |
|---|---|---|
| 0:00 – 1:15 | The problem | Overview tab |
| 1:15 – 2:15 | PROTECT | Quantum Vault |
| 2:15 – 3:00 | HARVEST | HNDL Hoard |
| 3:00 – 5:15 | Q-DAY | Q-Day Simulator |
| 5:15 – 6:00 | The honesty boundary | Q-Day, three-panel |
| 6:00 – 6:45 | BENCHMARK | Benchmarks |
| 6:45 – 8:45 | DISCOVER → MIGRATE | PQC Readiness → Migration Plan |
| 8:45 – 10:00 | Close | Overview |

Rehearse with a timer. The two places you will overrun are the problem
statement and the migration tab. Both are cut-able; see the compression notes at
the end.

---

## 0:00 – 1:15 · The problem

> *[Overview tab is already on screen. Do not click anything yet.]*

"Encryption assumes an attacker who has to break it now.

There is a second option. Record it, store it, and wait. That is **Harvest Now,
Decrypt Later** — and it inverts the whole security calculation. The question
stops being *is this safe today* and becomes *will this still need to be secret
when the recording becomes readable*.

For a lot of data the answer is obviously yes. Payment settlement records with a
twenty-five year retention requirement. Genomic data. Regulatory archives held
for fifty years. Diplomatic traffic.

That data is already exposed. Not in the future — now. The ciphertext has
already left the building. Somebody may already have it.

AegisPQC does three things about that. It **demonstrates** the threat with a
real cryptographic break, not an animation. It **quantifies** the engineering
cost of the defence. And it **finds** where an organisation is still exposed and
tells them what to fix first."

> *[Gesture at the Overview metrics.]*

"This is the estate we scanned. Nine assets, six of them quantum vulnerable, a
readiness score of twenty-five out of a hundred. I will come back to how that is
calculated, because there is no black box in it."

**Why this opening works:** it names the threat model in the judges' own
language, anchors on retention periods a banking risk person recognises
immediately, and promises the honesty that the rest of the pitch delivers.

---

## 1:15 – 2:15 · PROTECT

> *[Click **Quantum Vault**.]*

"Alice sends a confidential file to Bob. Three key-establishment options: RSA at
demo scale, ML-KEM-768, or the hybrid.

One thing to notice before I send anything." *[Point at the subtitle.]* "The
symmetric layer is identical in all three. HKDF-SHA256 into AES-256-GCM. **We are
not replacing AES.** Grover's algorithm gives you a quadratic speedup against a
symmetric cipher, so AES-256 keeps about 128 bits of post-quantum security. Only
the asymmetric layer is in danger, and that is the only thing that changes here."

> *[Select **Hybrid**. Click **ENCRYPT AND SEND**.]*

"Here is the actual pipeline." *[Scroll to the procedure steps.]*

"Plaintext. Two key establishments in parallel — an ephemeral X25519 exchange
and an ML-KEM-768 encapsulation. Both shared secrets feed one HKDF, so an
attacker has to defeat **both** to derive the key. That is the X25519MLKEM768
construction browsers actually shipped in TLS 1.3.

Then AES-256-GCM. Then the envelope goes on the wire — and the last step is the
one that matters."

**Why the hybrid first:** it is the construction a bank would actually deploy,
and leading with it signals you understand production migration rather than a
textbook demo.

---

## 2:15 – 3:00 · HARVEST

> *[Click **HNDL Hoard**.]*

"The adversary captured it. Passive optical tap — injects nothing, modifies
nothing, triggers no alarm.

Look at the algorithm column." *[Point.]* "**All three** were harvested. RSA,
ML-KEM, and the hybrid. Choosing post-quantum cryptography does not make you
invisible. It makes the recording worthless later. There is no cryptographic
defence against being recorded — only against being understood."

> *[Expand the forensic view on any packet.]*

"This is what the tap actually holds. KEM ciphertext, nonce, authentication tag,
ciphertext body, and the recipient's public key. Every one of those is
observable on the wire by design.

And it says so right here — **private keys not captured**. A network tap sees
ciphertext and public parameters. Private keys never traverse the wire. That is
not a claim in a slide, it is enforced by a test that scans every field in that
table against every stored key."

**This beat is 45 seconds and cannot be cut.** It is the pivot that makes Q-Day
land.

---

## 3:00 – 5:15 · Q-DAY — the moment the pitch turns

> *[Click **Q-Day Simulator**. Select the RSA-DEMO packet.]*

"Now. Most post-quantum demos at this point claim to simulate Shor's algorithm
breaking RSA-2048. None of them do it. They read the private key out of their own
database and put a progress bar over the top.

We are going to do something different. Watch the modulus."

> *[Click **EXECUTE Q-DAY ATTACK**. Let it run. Do not talk over the first two
> seconds — let the audience watch real work happen.]*

"That was a real factorisation. Eighty-eight bit modulus, Brent's variant of
Pollard's rho, running on this laptop.

Here is the procedure it actually executed." *[Point at the steps.]*

"It read `n` and `e` off the wire — public data only. It factored the modulus and
recovered `p` and `q`. It computed the Carmichael totient and inverted `e` to
reconstruct `d` — that is the private key, derived from public data. It
decapsulated the harvested KEM ciphertext, ran HKDF to get the AES key, and
decrypted the payload."

> *[Point at the recovered plaintext.]*

"That is the merger brief. In the clear. From a recording.

And the private key was never consulted. There is a test called
`test_qday_attack_only_uses_public_data` that **deletes every private key from
the database** and then runs the attack. It still succeeds. If anyone wants, I
will run it."

> *[Now select the ML-KEM packet. Click attack.]*

"Same adversary, same archive, same procedure. ML-KEM-768.

No decapsulation key exists. Recovering the shared secret means solving Module
Learning With Errors. Shor's algorithm solves period-finding in abelian groups —
lattice problems are not of that form, so it does not apply.

Best known attack is BKZ lattice reduction: roughly 2^181 gates classically,
2^165 with a quantum computer. Notice how little the quantum column helps.
Sixteen bits. Against RSA, that same column goes from infeasible to hours.

**And we attempt nothing here.** The tool says so explicitly. Running a fake
reduction with a progress bar would be theatre. The published cost is the entire
argument."

**Delivery note:** the silence during the factorisation is the most powerful
three seconds in your pitch. Do not fill it.

---

## 5:15 – 6:00 · The honesty boundary

> *[Scroll to the three panels at the top of the Q-Day tab.]*

"I want to be precise about what you just watched, because the distinction
matters.

**One.** Today's demonstration. A deliberately undersized eighty-eight bit
modulus, factored genuinely, using classical factorisation. Not Shor's algorithm.
No quantum computer.

**Two.** The future quantum threat. Shor's algorithm is the real threat to RSA
and elliptic curves at production sizes. Gidney and Ekerå put RSA-2048 at roughly
twenty million physical qubits and eight hours. That machine does not exist.
**We have not broken RSA-2048 and we do not claim to.** If you select a real
RSA-2048 packet in this tool, it refuses to fabricate a break and tells you why.

**Three.** The defence. ML-KEM is *designed to resist* known classical and
quantum attacks. That is deliberately weaker than saying it cannot be broken —
lattice cryptanalysis is an active field and those estimates move.

The only thing that changes between panel one and panel two is **time**. The
mathematics is identical at eighty-eight bits and at two thousand forty-eight.
What differs is the machine. And the adversary already has the recording."

**This is the slide that wins you the room.** Deliver it slowly. It is the
moment a senior security person decides whether to trust everything else.

---

## 6:00 – 6:45 · BENCHMARK

> *[Click **Benchmarks**. Click **RUN BENCHMARKS**.]*

"Measured on this machine, right now.

Two things people get wrong about post-quantum. First — they expect it to be
slow. ML-KEM generates keys and decapsulates **two orders of magnitude faster**
than RSA-2048." *[Point at the actual number on screen.]* "It is on the screen;
it varies by machine.

Second — they think that means it is free. It is not. Look at wire overhead."
*[Point.]* "ML-KEM moves about four times the bytes RSA does per handshake. For a
file transfer that is noise. For TLS at internet scale that is the entire
engineering conversation.

**The honest cost of this migration is bandwidth, not speed.** A demo that shows
only the favourable half of a trade-off is marketing.

And notice these two sections are kept apart." *[Scroll to ESTIMATED.]* "Latency
and sizes are measured. Quantum attack costs are published estimates with
citations — nobody can measure those. Mixing them into one table would imply we
measured something we did not."

---

## 6:45 – 8:45 · DISCOVER → ASSESS → PRIORITIZE → MIGRATE

> *[Click **PQC Readiness**. Click **LOAD DEMO ENTERPRISE**.]*

"Everything so far demonstrates the threat. This is the part an organisation
actually deploys.

We scan a cryptographic estate. This is a fictional enterprise, generated
locally — but every file contains **genuine cryptographic material**. Real
RSA-2048 and 3072 keys, a real self-signed ECDSA certificate, a real ML-KEM-768
encapsulation key, and one deliberately corrupted file.

Nine assets. Six quantum vulnerable. Two post-quantum. One that could not be
parsed at all — and that one is reported, not dropped, because an asset nobody
can read is exactly the one a migration programme loses track of."

> *[Expand one CRITICAL asset.]*

"No black box. For every asset: the algorithm, the key size, **the OID it was
identified by** — you can run `openssl asn1parse` on that file and get the same
answer — the verification source, retention, sensitivity, and the exact reasoning
that produced the rating.

And note this distinction." *[Point at VERIFIED vs DECLARED.]* "**Verified** means
we parsed it out of real key material. **Declared** means we read it from a
deployment manifest — that is an operator's *claim*, not proof. An organisation's
migration status is frequently wrong on paper. A tool that treats a JSON file as
equivalent to a parsed key overstates progress, which is the exact failure it
exists to prevent. Declared assets cap at LOW. They never reach SAFE."

> *[Click **Migration Plan**.]*

"Any scanner can list vulnerable assets. The hard question a security programme
actually faces is which of forty systems to touch first.

Here is the answer, with a stated rule. Ordering is risk first, then **data
retention descending** — because harvest exposure is a function of how long the
ciphertext has to stay secret, not the algorithm alone.

Records Archive is number one. Fifty-year retention. Legacy Authentication,
thirty. Payment Processing, twenty-five. Same algorithm in several cases — the
retention is what moves them."

> *[Expand #1.]*

"Every entry has a **'why this position'** line a security lead could take
straight into a steering committee. Current state, recommended target from the
NIST standards, phase, effort band, and whether validation is required.

Four phases. And notice the target architecture keeps AES-256-GCM **unchanged** —
a migration plan that proposes replacing AES would show a misunderstanding of the
threat.

One thing this deliberately does not do: it does not touch anything. No file is
modified, no key is rotated. A tool that offers to auto-migrate an
organisation's cryptography and gets it wrong is worse than no tool at all. This
is decision support."

---

## 8:45 – 10:00 · Close

> *[Click back to **Overview**.]*

"So: discover the estate, assess what is vulnerable and why, prioritise by real
exposure, and produce a migration plan someone can execute.

Two hundred and forty-four tests back this. The ones I would point you at first
are the honesty tests — there is an automated audit that fails the build if
fourteen specific overclaiming phrases appear anywhere in the product. Those are
the words that assert absolute security. If any of them ever slipped into our
code or our documentation, the suite would reject it before it shipped.

I will be direct about the limits, because they matter more than the demo.

We broke eighty-eight bits, not two thousand forty-eight. Classically, not with
Shor's. The scanner reads PEM, DER, and JSON manifests — not PKCS#12, not JKS. It
does not validate certificate chains. It never predicts a Q-Day date, because
nobody credibly can.

What it does establish is the thing that is knowable and actionable: **which
assets use cryptography that the published quantum algorithms defeat, and how
long their data has to stay secret.** For a bank holding twenty-five year
settlement records, those two facts are enough to justify starting the migration
now — and that is the entire argument.

The recording is already made. The only open question is how long the adversary
has to wait."

---

## Compression — if you are running long

Cut in this order. Never cut the honesty boundary.

1. **Forensic packet expansion** (–25s) — describe it instead of expanding it.
2. **Benchmarks** (–30s) — state "ML-KEM is faster but costs four times the
   bytes; the honest cost is bandwidth" and move on.
3. **Migration phases** (–20s) — show the queue, skip the phase cards.
4. **The problem statement** (–25s) — cut straight to "Record it and wait. That
   is Harvest Now Decrypt Later."

If you are running **short**, expand the Migration Plan. It is the part that
distinguishes you from every other PQC project in the room.

---

## Delivery notes

**Pace.** You will speak faster than you rehearse. Deliberately slow the three
honesty panels and the moment the plaintext appears.

**Silence.** Two places: while the factorisation runs, and immediately after the
recovered merger brief appears. Let the room absorb both.

**Pointing.** When you quote a number, point at it on screen. It converts a claim
into an observation.

**If something breaks.** See `DEMO_RUNBOOK.md`. Short version: every tab works
independently, and the terminal fallback reproduces the whole story.

**The single sentence to land if you only land one:**

> "We did not break RSA-2048 — nobody has. We shrank the problem until it was
> honestly solvable today, broke it for real, and showed that the only variable
> between that and the real thing is time."
