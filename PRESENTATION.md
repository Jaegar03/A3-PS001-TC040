
# SENTIVRA: Funding Presentation

**One Security Layer. Every Threat.**

*Explainable, multi-layer threat detection that keeps your data where it belongs.*

Presented by: [presenter name] · [organisation] · [date]

---

## Slide 1: The problem

**Attacks come through many doors at once.**

- Phishing emails and chat messages.
- Malicious files.
- Unusual network traffic.
- Compromised computers.
- Password-guessing against logins.

**Defenders watch those doors with separate tools.** One product scans email, another watches computers, another reads logs. Each raises its own alerts, in its own format, with its own idea of what "high risk" means. Nobody sees the whole picture.

**The alerts rarely explain themselves.** "Threat detected: 87" doesn't tell an analyst what happened, why, or what to do. Much machine-learning security is a black box, so its mistakes can't be checked.

**Small and mid-sized organisations have no security team** to stitch this together. Schools, clinics, startups and local businesses face the same attackers as large enterprises, with a fraction of the people and budget.

**Checking a suspicious file often means sending it away.** Online scanning services analyze files on someone else's servers, so a confidential document can leave the organisation in the act of checking it.

> **Speaker note:** Pause here. Ask the panel how many separate security tools their own organisations run, and whether anyone reads all of their alerts.

---

## Slide 2: What SENTIVRA is

**SENTIVRA is one security layer that watches every door and gives one verdict you can understand.**

```
   files      network      endpoints      logins / logs      email & chat (next)
     │           │             │                │                   │
     └───────────┴──────┬──────┴────────────────┴───────────────────┘
                        ▼
        several independent detectors, each checking in its own way
        (signatures · rules · statistics · machine learning)
                        ▼
                 one risk engine
        (combines them; no single detector decides)
                        ▼
      one explainable alert:  what happened · why · the evidence ·
                              how confident · what to do
```

- **One platform** for files, network traffic, endpoint activity and login logs. Email, Telegram and WhatsApp Business come next.
- **Independent detectors** check the same data in different ways. When several agree, SENTIVRA is more certain; when only one fires, it says so.
- **Every alert explains itself** in plain language, with the evidence behind it, so a non-specialist can act on it and a specialist can verify it.
- **It runs where you run it.** Your files, traffic and logs are analyzed on your own infrastructure and are never sent to outside services.

---

## Slide 3: What it does today

**This is a working prototype, not a concept.** It runs today, with a full dashboard.

| Area | What SENTIVRA detects today |
|---|---|
| **Files** | Malicious and disguised files: an executable pretending to be a PDF, packed or encrypted content, files that are two formats at once, known malicious patterns (YARA signatures), and antivirus verdicts (ClamAV) where installed. Files are never opened or run |
| **Network** | Port scans, host sweeps, brute-force logins, floods, large data transfers out of the organisation, DNS tunnelling (hiding data in DNS traffic), malware "beaconing" home, and statistically anomalous connections, from packet captures or flow exports |
| **Endpoints** | Office documents launching command shells, unsigned programs running from user folders and calling out, new persistence (autostart entries, scheduled tasks, services), rogue listening ports, ransomware-like mass file changes, cleared security logs, and rare process chains. Uses osquery, a widely deployed open-source agent |
| **Logins** | Password guessing, password spraying, and a success right after many failures, from Linux, Windows and Wazuh logs |
| **Triage** | A 14-page dashboard to review alerts, see the evidence, and acknowledge or resolve each one, with a tamper-evident audit log of who did what |

**Built on open standards:**
- YARA and Sigma, the industry's shared rule formats;
- osquery for endpoints;
- MITRE ATT&CK, the global catalogue of attacker techniques, used for every technique mapping.

> **Speaker note:** Switch to the live demo here ([Appendix A](#appendix-a-three-minute-live-demo)). It takes three minutes and uses only safe, simulated data.

---

## Slide 4: How a verdict is reached

**Example: a real alert from the demo.** Three independent detectors examine a simulated fleet of computers.

| Detector | What it saw |
|---|---|
| **Sigma rules** | A Word document launched PowerShell; the Windows security log was cleared; a program started from a temporary folder |
| **Login analysis** | One address failed to log in to 22 different accounts (password spraying) |
| **Host behaviour** | A new autostart entry in a user folder; an unsigned program phoning out; 484 files modified in two minutes |

**SENTIVRA's verdict:**
- **CRITICAL, risk 100/100**;
- **"3 independent detectors raised findings"**;
- the full evidence, and the attacker techniques involved (MITRE ATT&CK);
- **recommended action: BLOCK**.

**The safety rule behind it: no single detector can raise a CRITICAL alert on its own.** Reaching CRITICAL needs either one detector that is very sure (score and confidence both at least 90%), or independent detectors that agree. One moderately confident signal stays at "worth a look". That keeps false alarms from burying real ones, and it means one fooled detector can't cause a panic.

---

## Slide 5: The machine learning inside

**Network anomaly detection uses four independent layers**, each trained to recognise normal traffic or known attacks:

| Layer | Model | What it catches |
|---|---|---|
| **Statistical baseline** | Robust z-scores against normal traffic | Connections far outside normal on any single measurement |
| **Isolation Forest** | Unsupervised anomaly detector (200 trees) | Connections that are easy to "isolate" from the crowd: unusual combinations |
| **Autoencoder** | A neural network (21 → 16 → 6 → 16 → 21) trained only on normal traffic | Connections it can't reconstruct well, because they don't look like anything normal |
| **Classifier** | LightGBM gradient-boosted trees, with calibrated probabilities | Patterns resembling labelled attacks it was trained on |

**How the layers combine.**
- Each flow is described by 21 measurements: duration, volume in each direction, rates, packet shape, TCP flags and service type.
- **A connection is flagged only when at least two independent layers agree.** No single model can flag anything alone.
- Each flag comes with a plain-English reason, for example "higher than 99.9% of normal traffic, driven by its SYN ratio", using TreeSHAP explanations for the classifier.
- **Beyond single connections**, a statistical significance test checks whether a whole upload has more anomalies than chance would produce. Normal traffic doesn't raise alarms just by being large.
- **Seven behaviour rules** catch what single connections can't show: scans, sweeps, brute force, floods, exfiltration, DNS tunnelling and beaconing.

**For endpoints:**
- a **learned fleet baseline** of what's normal: which programs start which, what runs at startup, which ports listen;
- **Sigma rules** and **host behaviour rules** evaluated against that baseline.

**Models are safe to load.** Every model is stored in a format that can't run hidden code (ONNX and LightGBM text), fingerprinted with SHA-256, and verified before it's used. A tampered model is refused.

**Next models (datasets already licensed and downloaded):**
- phishing-URL detection;
- prompt-injection detection for AI assistants;
- SQL-injection detection;
- a static malware model;
- an endpoint anomaly model.

---

## Slide 6: Results so far, stated honestly

**We report precision, recall and false-alarm rate, never "accuracy".** A detector that flags nothing can score 99% accuracy on security data, where attacks are rare.

**Network models, on a held-out test set of 27,881 connections:**

| | Precision | Recall | False-alarm rate |
|---|---|---|---|
| Models combined (two must agree) | **91.5%** | **84.9%** | **0.70%** |
| Models + behaviour rules | **92.7%** | **100%** | **0.70%** |

- **Precision:** when SENTIVRA flags something, how often it's really an attack.
- **Recall:** of the real attacks, how many it caught.
- The layers are fast: one connection through all four layers took about 11 ms on a laptop.

**Endpoint detection:**
- all **45 of 45** simulated attack episodes (9 scenarios × 5 test fleets) detected;
- **zero** false alarms across 10 benign simulated fleets.

The benign fleets include deliberately tricky normal behaviour: signed apps installed in user folders, installers run from Downloads, users opening shells, and mistyped passwords.

**What these numbers do and don't mean.** They were measured on **synthetic and simulated data**, generated to test the pipeline end to end. They show that the system, its leakage controls and its calibration work as designed. They are **not yet proof of performance on real-world traffic**.

Two things make them credible as a foundation:
- **Strict separation:** training, threshold-setting and testing each used separate data, and every change made after looking at test results is recorded rather than hidden.
- **Measurement on real data is the first milestone this funding pays for** (Slide 11).

> **Speaker note:** Say this before the panel asks. Honesty about synthetic data is a strength here: it's exactly the discipline a security product needs.

---

## Slide 7: What makes SENTIVRA different

| | SENTIVRA's approach |
|---|---|
| **One layer, many doors** | Files, network, endpoints, logins, and now email and messaging, all in one data model, one risk engine and one dashboard. The same phishing detector will work on an email, a Telegram message or a WhatsApp message without being rebuilt |
| **Explainable by design** | Every alert answers what happened, why, what the evidence is, how confident the system is, and what to do. The rule is built into the data model: an alert above "low" without evidence is rejected as invalid |
| **Consensus, not a black box** | No single model or detector decides. ML layers must agree, and independent detectors must corroborate before anything is called critical |
| **Honest by design** | A missing engine says "Not configured", never "clean". An unbuilt feature says "Not implemented", never a fake result. Simulated and demo data are labelled on every screen. Model results are shown only with their dataset and evaluation date |
| **Private by design** | Analysis runs on your infrastructure. Files, traffic and messages are never uploaded to outside services, and raw content isn't retained after analysis; only fingerprints, metadata and verdicts are kept |
| **Open standards, no lock-in** | YARA, Sigma, osquery and MITRE ATT&CK. Your rules and telemetry stay portable, and existing community rules work out of the box |
| **Secure foundation** | Least-privilege API access, signed short-lived tokens, rate limits, tamper-evident audit trail, pickle-free verified models, and files that are never executed |

**Where it fits.** Large enterprises assemble this capability from several specialised products and a security operations team to connect them. SENTIVRA's aim is to make the connected, explainable picture available to organisations that have neither the budget for many products nor the team to run them. It works alongside tools they already have, through open standards, rather than asking them to rip anything out.

---

## Slide 8: Privacy and trust

**Your data stays with you.**
- **SENTIVRA analyzes data where you run it.** It makes no outbound calls to cloud scanners or threat-intelligence services; if such lookups are ever added, they'll be explicit and opt-in.
- **Raw content is discarded after analysis.** Uploaded files, packet captures and logs are analyzed in memory and discarded. SENTIVRA keeps the fingerprint, the facts and the verdict: enough to act on, not a second copy of your data.
- **Messaging connectors will use official channels only:**
  - Gmail with **read-only** permission;
  - Telegram and WhatsApp Business through their official APIs, seeing only messages legitimately sent to the organisation's bot or business number.

  No scraping, and no attempt to read private conversations.

**The platform is hardened against attack itself:**
- **Least-privilege access.** A telemetry forwarder can submit data but can't read alerts. A reader can't change anything.
- **Accountability.** Every analysis and every alert decision is recorded, with who made it, in an append-only log.
- **A tested threat model.** SENTIVRA's own attack surface is documented, and every mitigation is backed by automated tests.

---

## Slide 9: The future: from detection to automated protection

**Today SENTIVRA detects and explains, and a person acts. Next, it will be able to act as well**, containing a threat from the same place it was detected, before data can leave the organisation.

```
  Detection  ──►  Policy engine  ──►  Human approval  ──►  Automated response
  (today)         proposes a           a person            carried out through
                  response             confirms            official APIs
      └──────────────── every step recorded in the audit log ─────────────────┘
```

**What automated response will do**, all reversible:
- quarantine a phishing email before anyone clicks it;
- block a malicious address at the firewall;
- isolate an infected file into encrypted quarantine;
- alert the right person on the right channel;
- open a ticket.

**Why this protects data.** The dangerous period in most incidents is the gap between an attacker getting in and someone noticing and responding. With detection, decision and response in one place, that gap shrinks from hours or days to minutes. Stolen data, leaked files and exposed records can be stopped before they leave, instead of being discovered afterwards.

**Why it will be trusted.** The safeguards are already designed ([docs/future-automation.md](docs/future-automation.md)):
- A human approves each action by default. Automatic approval is possible only for specific, reversible actions an organisation switches on.
- It never acts on a single detector's opinion, and never on simulated or test data.
- A fixed list of allowed actions: nothing an attacker writes in an email can become a command.
- Permanent deletion is never automated.
- A kill switch, off by default.
- **"Shadow mode" first:** SENTIVRA records what it *would* have done, and we measure that against what analysts actually did, before anything is switched on.

> **Speaker note:** Be clear that this is the roadmap, not the current build. The interfaces and safeguards are designed; the automation isn't built. Promising "no breach ever" would not be credible to a security audience. Promising faster, safer containment is, and it's what this design delivers.

---

## Slide 10: Who it's for

**Primary:** organisations that need real protection but have no dedicated security team:
- small and mid-sized businesses;
- schools and universities;
- clinics and healthcare practices;
- NGOs;
- startups.

**Secondary:** managed security service providers (MSSPs) and IT service companies that protect many such organisations and need one explainable console across all of them.

**How it can be delivered** (to be validated in pilots):
- **Self-hosted:** runs on the organisation's own server, so data never leaves.
- **Managed:** a service provider operates it for several clients.
- **Open core:** the detection engine and rule formats stay open; commercial support, connectors and automation come on top.

---

## Slide 11: Roadmap

| Milestone | What it delivers | Evidence you'll see |
|---|---|---|
| **1. Real-data validation** | Network models retrained and measured on a public real-traffic benchmark (CIC-IDS2017); endpoint baselines learned on real test machines | Published model card with real-traffic precision, recall and false-alarm rate |
| **2. Text and web threats** | Phishing-URL, prompt-injection and SQL-injection detectors — shipped in this build as bounded rule/heuristic analysis; training and published measurement on the licensed datasets already downloaded is the remaining work | Detectors live in the dashboard, with benign false-alarm testing |
| **3. Email and messaging** | Gmail (read-only), Telegram and WhatsApp Business connectors through official APIs, and the privacy documentation for each — shipped in this build; they analyse live messages end to end once credentials are configured | Provider-verified webhook ingestion end to end |
| **4. Pilot deployments** | Packaged deployment (designed in [docs/future-deployment.md](docs/future-deployment.md)) at [n] pilot organisations | Pilot feedback, alert quality on live data |
| **5. Automation in shadow mode** | Policy engine proposing responses, measured against analyst decisions | Measured agreement rate, before anything acts |
| **6. Approved automated response** | Reversible actions with human approval | Time from detection to containment |

---

## Slide 12: The ask

**We are seeking [amount] to take SENTIVRA from working prototype to piloted product over [period].**

| Use of funds | Share | Milestones |
|---|---|---|
| Engineering: detectors, connectors, automation | [x]% | 2, 3, 5, 6 |
| Data and evaluation: real-data validation, benign test corpora, independent testing | [x]% | 1, 2 |
| Security: external penetration test of SENTIVRA itself, deployment hardening | [x]% | 4 |
| Pilots and support | [x]% | 4 |

**What the panel gets in return:** measurable checkpoints. Each milestone produces evidence you can inspect (published metrics, working connectors, pilot results), not just progress reports.

---

## Slide 13: Why back SENTIVRA now

- **It already works.** A running platform with seven detectors, a 14-page dashboard and a secured API, not slides alone.
- **It's built like a security product should be:**
  - **204 automated tests**, security scanning with no open findings, and known-vulnerability audits with no known issues;
  - a documented threat model of SENTIVRA itself, a model card for every model, and an audit trail for every action.
- **It's honest.** It shows what's done and what isn't, labels simulated data, and reports its limitations next to its numbers. That's the property that makes a security tool trustworthy, and it's rare.
- **It's positioned for the gap.** The organisations most exposed to attack are the least able to afford today's multi-product security stacks.
- **It has a clear path to protection, not just detection.** Automated, human-approved response from the same platform is fully designed, with its safeguards.

**SENTIVRA: one security layer, every threat, and your data stays yours.**

---

## Appendix A: Three-minute live demo

Everything in the demo is safe:
- the EICAR test file, a harmless industry-standard antivirus test;
- synthetic network traffic that refers to no real host;
- a simulated fleet whose commands are placeholders.

The dashboard labels all of it *Demo data* or *Simulated*.

1. **Sign in** at `http://localhost:3000`. Every API call is authenticated.
2. **Demo mode → Run all scenarios.** A file scan, a network capture and a simulated fleet run through the real pipeline.
3. **Overview.** Point out:
   - the security score, with its formula shown;
   - alerts by severity and by detector;
   - the *Live / Simulated / Demo data* breakdown;
   - that every chart has a table view.
4. **Threats → open the CRITICAL alert.** Read the Explanation card aloud: what happened, why ("3 independent detectors"), the evidence, the confidence and the recommended action. Scroll to the per-detector findings and the ATT&CK techniques.
5. **Click Acknowledge**, then open the **Audit Log** to show the action recorded with who did it.
6. **Network page.** Show a flagged connection's explanation ("higher than 99.9% of normal traffic, driven by…") and the behaviour rules that fired.
7. **Models page.** Show that every model lists its data, test date and limitations, and that untrained models say "Not trained" rather than showing a made-up score.
8. **Integrations page.** Show that email and messaging honestly say "Not configured" — built and tested, waiting on credentials — while Suricata and Zeek say "Not implemented". That's the roadmap you're funding.

---

## Appendix B: Questions the panel is likely to ask

**"Have the models been proven on real traffic?"**
Not yet, and we say so on the Models page itself. Today's numbers come from synthetic and simulated data and prove the pipeline, calibration and safeguards work. Real-traffic validation on a public benchmark is milestone 1, and its results will be published the same way, good or bad.

**"How is this different from a SIEM or an EDR product?"**
Those are powerful, and typically aimed at organisations with a security team to operate them. SENTIVRA combines detection across several surfaces into one explainable verdict, runs where the customer runs it, and is built on open standards. It can work alongside existing tools rather than replacing them.

**"What happens when it's wrong?"**
- False alarms are contained by design: models must agree, detectors must corroborate for a CRITICAL alert, and batch-level statistics stop large normal uploads from raising alarms.
- Missed attacks are why there are several independent layers. On the test data, behaviour rules caught what the models missed.
- Every alert shows its evidence, so a person can check it quickly.

**"Does any of our data leave our network?"**
No. SENTIVRA analyzes data where it runs and makes no outbound calls to scanning or intelligence services. Raw files, captures and logs are discarded after analysis. Only fingerprints, facts and verdicts are kept.

**"Why not automate responses right away?"**
Because an automated response that's wrong can do as much damage as an attack. The design adds automation in stages:
1. shadow mode, measured against analysts' decisions;
2. human-approved actions;
3. automatic approval only for reversible actions an organisation chooses.

The interfaces and safeguards are designed now, so adding automation doesn't mean rebuilding.

**"Can it guarantee our data will never be exposed?"**
No security product can honestly promise that, and a vendor who does should worry you. What SENTIVRA does is shrink the time between an attack starting and it being contained, and keep your data inside your organisation while it's being checked.

**"Is SENTIVRA itself secure?"**
- It has a documented threat model, and API access is least-privilege: every call needs a token with a specific permission.
- Tokens are signed and short-lived, and there are rate limits and request-size limits.
- Uploaded files are never executed, and models are verified and can't run hidden code.
- Every action goes into an append-only audit trail.
- All of this is covered by automated tests, and an external penetration test is part of the funding plan.

---

*Technical depth for reviewers:*
- [docs/architecture.md](docs/architecture.md): the whole system explained;
- [docs/CAPABILITY_MATRIX.md](docs/CAPABILITY_MATRIX.md): what works, what is experimental, what does not exist;
- [docs/model-card.md](docs/model-card.md): every model's data and results;
- [docs/threat-model.md](docs/threat-model.md): SENTIVRA's own security;
- [docs/future-automation.md](docs/future-automation.md): the automation design;
- [docs/future-deployment.md](docs/future-deployment.md): the deployment design.
