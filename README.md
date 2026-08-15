# 💧 Hydroficient IoT Water Defense System 
    (Extern IoT defense system projects)
### An 8-Week IoT Security Externship — Securing The Grand Marina Hotel's Water Infrastructure

![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)
![Duration](https://img.shields.io/badge/Duration-8%20Weeks-blue?style=flat-square)
![Role](https://img.shields.io/badge/Role-Junior%20Security%20Engineer-orange?style=flat-square)
![Stack](https://img.shields.io/badge/Stack-Python%20%7C%20MQTT%20%7C%20TLS%2FmTLS%20%7C%20AI-informational?style=flat-square)
![Outcome](https://img.shields.io/badge/Outcome-Passed%20Insurance%20Audit-success?style=flat-square)

> *"A sensor glitches. A valve shuts off. 2,000 hotel guests wake up with no water."*
> That's the scenario this project exists to prevent.

---

## 📖 Overview

This repository documents an 8-week hands-on cybersecurity externship at **Hydroficient**, a company that builds IoT water management systems for commercial properties. I was brought on as a **junior security engineer** reporting to **Maya Chen (Senior Security Engineer)**, with my first assignment being **The Grand Marina Hotel** — a 500-room luxury resort running three HYDROLOGIC flow-management devices across its entire water system.

The General Manager, Marcus Webb, had one question: *"Is our system secure?"*

Over eight weeks, I answered that question by building the entire IoT security stack from scratch — not studying it, **building it**: a real MQTT pipeline, breaking it open as an attacker would, then closing every gap one layer at a time — encryption, device identity, replay protection, live monitoring, and finally an AI anomaly detection layer that catches what rule-based defenses can't.

By the end, The Grand Marina's water system **passed its insurance audit on the first try**, and the security architecture built here became the **baseline spec** for Hydroficient's next hotel wing (42 additional rooms).

---

## 🏨 The Client: The Grand Marina Hotel

| | |
|---|---|
| **Property** | 500 guest rooms, 15 floors, 12 restaurants, Olympic pool & spa, conference center |
| **Guests on-site** | 2,000+ on any given night |
| **Water cost before Hydroficient** | ~$300,000/month |
| **Savings after Hydroficient** | 15–20% reduction in consumption |
| **Incoming water pressure** | 85 PSI (vs. 40 PSI code minimum) |

### The Three HYDROLOGIC Devices

| Device | Location | Serves |
|---|---|---|
| **Device 01** | Main Building Mechanical Room | Guest rooms, lobbies, restaurants |
| **Device 02** | Pool/Spa Wing | Pool, spa, fitness center |
| **Device 03** | Kitchen/Laundry Wing | Commercial kitchen, laundry facilities |

Each device continuously streams **upstream/downstream pressure, gate position, flow rate, and cumulative consumption** to the cloud, and exposes remote controls — including gate adjustment and an **emergency water shutoff** — through a central operator dashboard. That combination (real-time telemetry + remote physical control) is what makes this an IoT security problem rather than a traditional data-security problem: a compromised system doesn't just leak data, it can shut off water to 500 rooms.

---

## 🗺️ System Architecture — Trusted Sensor Data, End to End

Every reading has to prove its **identity, integrity, freshness, and order** before it's allowed to change what an operator sees on the dashboard. No single control is asked to catch every attack — each stage below closes a gap the previous stage doesn't cover.

```
 [1] COLLECT              [2] PROTECT               [3] IDENTITY              [4] VALIDATE              [5] ASSESS                [6] RESPOND
 Hotel Sensors     ──▶    Signed MQTT Payload  ──▶   MQTT Broker         ──▶   Subscriber Verifies  ──▶   AI Anomaly Review   ──▶   Live Dashboard
 (S)                      (P)                        (B)                      (V)                        (AI)                     (D)
```

| #     | Stage        | Component                                                      | What Happens                                                                                                                                                                                           |     |
| ----- | ------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --- |
| **1** | **Collect**  | Hotel Sensors — Main Building · Pool & Spa · Kitchen & Laundry | Each HYDROLOGIC device reads pressure, flow, and gate position                                                                                                                                         |     |
| **2** | **Protect**  | Signed MQTT Payload                                            | Message is stamped with the current timestamp, a sequence counter, and an **HMAC-SHA256** tag over the topic + reading                                                                                 |     |
| **3** | **Identity** | MQTT Broker (Mosquitto, mTLS)                                  | Broker performs an **mTLS handshake** and validates the client certificate — an unknown client is blocked before its message ever reaches a subscriber                                                 |     |
| **4** | **Validate** | Subscriber Verifies                                            | HMAC is recomputed and compared (unchanged?), timestamp is checked (≤30 seconds old), sequence number is checked (must be newer than the last one seen) — **all three checks must pass**               |     |
| **5** | **Assess**   | AI Anomaly Review (Isolation Forest)                           | Every reading that survives Steps 3–4 is scored against a learned "normal" pattern: 🟢 **normal**, 🟠 **AI-flagged anomaly** (unusual but not rule-breaking), 🔴 **rule-blocked** (failed Step 3 or 4) |     |
| **6** | **Respond**  | Live Dashboard                                                 | Trusted, scored reading is pushed over **WebSocket** and rendered — pressure gauge, security event log, operator alert                                                                                 |     |

**❌ REJECTED — dashboard is not updated** whenever a message fails identity, integrity, or freshness checks: invalid certificate · modified payload · stale timestamp · replayed sequence. Rejected messages never reach Step 5 or 6 — they're logged as a blocked event instead.

> **Defense-in-depth in one line:** mTLS = identity + encryption · HMAC = integrity · Timestamp + sequence = replay defense · Isolation Forest = the layer that catches what all the rules above it miss.

**Production mapping**: publisher → real sensor/gateway device · broker → AWS IoT Core / Azure IoT Hub · subscriber → backend validation service · AI layer → scikit-learn model served alongside the backend · dashboard → Grafana/Kibana/custom web app. The pattern built here is the same pattern used in real IoT deployments — just at the scale of 3 devices instead of 300.

---

## 🎥 Video Demos

### 1. The Simulator Reproduced Each Attack on Demand
Separate terminals reproduced eavesdropping, false-data injection, and replay attempts. Each run verified terminal rejection and dashboard logging.
🔗 [Watch the demo](https://drive.google.com/file/d/1M_1ju2n27jXrr6frrMz9XPyOaMPnGyvE/view?usp=sharing)

### 2. AI and Rules Operate Together in Real Time
Four coordinated services reproduce trusted traffic, known attacks, and unusual sensor patterns against the same secured pipeline.
🔗 [Watch the demo](https://drive.google.com/file/d/1M_1ju2n27jXrr6frrMz9XPyOaMPnGyvE/view?usp=sharing)

### 3. AI Live Dashboard Demo
Green confirms trusted telemetry, orange marks an unusual pattern for review, and red records a blocked security failure.

The video demonstrates a cybersecurity dashboard designed to monitor water pressure and message integrity, including:

- **Security and Integrity Monitoring** — each reading is verified by an HMAC signature; the system also scans for old timestamps and replay attacks
- **AI Anomaly Detection** — the system uses AI to detect abnormal patterns, such as water pressure or flow rates that fall outside average ranges; when an anomaly is detected, the system issues an alert and requires an operator to review or certify the situation
- **Device Tracking** — the dashboard monitors devices across the main building, the pool and spa, and the kitchen and laundry
- **Data Visualization and Reporting** — the bottom of the screen displays alerts (nature of the abnormal pattern, reason for the alert, and source); the right side shows a live data feed of timestamps, pressure readings, and messages; metrics include total messages received, messages certified, messages blocked, and AI-detected threats
- **Attack Simulation** — during a simulation, the dashboard displays alerts in red when an attack occurs, and messages identified as attacks are blocked immediately, so operators can see an attempted attack taking place in real time

🔗 [Watch the demo](https://drive.google.com/file/d/1YPtEs0quIAvScCp-mDrwSoJT4F693M23/view?usp=sharing)

---

## 📑 Presentation

🔗 [View the full capstone presentation](https://docs.google.com/presentation/d/1nYzl8mj8IIMGNrrNK9pNOZ5Fp8c1tRFyOircYHCg2HA/edit?usp=sharing)

---

## 🛡️ Defense-in-Depth: The Complete Security Stack

Each project added one independent layer. No single layer is sufficient alone — together, they close every gap:

| Layer | Project | Defends Against |
|---|---|---|
| **Threat Modeling (STRIDE + CIA)** | 1 | Unknown/unmapped risks |
| **TLS Encryption** | 4 | Eavesdropping on the network |
| **Mutual TLS (Device Identity)** | 5 | Rogue/unauthorized devices connecting |
| **Timestamp Validation** | 6 | Stale replayed messages |
| **Sequence Counters** | 6 | Duplicate/recent replayed messages |
| **HMAC Message Signing** | 6 | Tampered message content |
| **Live Dashboard Monitoring** | 7 | Slow human detection time |
| **AI Anomaly Detection (Isolation Forest)** | 8 | Gradual drift & abnormal patterns that pass every rule |

---

## 🧰 Tech Stack

- **Language**: Python (data structures, control flow, functions, classes, Pandas, JSON)
- **Messaging Protocol**: MQTT (topics, QoS, publish/subscribe)
- **Broker**: Eclipse Mosquitto
- **Client Library**: paho-mqtt
- **Security**: TLS 1.2/1.3, mutual TLS (mTLS), X.509 certificates, HMAC-SHA256
- **Real-Time Web**: WebSockets, custom HTTP server, vanilla HTML/CSS/JS (no frameworks)
- **AI/ML**: scikit-learn (Isolation Forest, Local Outlier Factor), Google Colab
- **Documentation**: Threat models, security assessment reports, device provisioning policy, final capstone presentation

---

## 📁 Folder Structure

```
Cybersecurity(Hydroficient )/
├── Explore What's In Store/                                          — Onboarding & company context
├── Project 1 Map Hydroficient's IoT system.../                       — Threat modeling (CIA + STRIDE)
├── Project 2 Learn Python basics.../                                 — Python fundamentals + mock sensor
├── Project 3 Build a fake sensor.../                                 — MQTT pipeline (insecure baseline)
├── Project 4 Add encryption.../                                      — TLS + performance testing
├── Project 5 Control which devices.../                               — mTLS device identity
├── Project 6 Simulate an attack that replays old commands/           — Replay attack defenses
├── Project 7 Build a dashboard.../                                   — Live WebSocket security dashboard
├── Project 8 (Bonus) Use AI.../                                      — Isolation Forest anomaly detection
└── README.md                                                          — This file
```

---

## 🧩 Project-by-Project Breakdown

### Project 1 — Map Hydroficient's IoT System & Identify What Could Go Wrong
**Threat modeling, before any code was written.**
- Learned the IoT device → cloud data flow and applied the **CIA Triad** (Confidentiality, Integrity, Availability) to identify what's actually vulnerable: the HYDROLOGIC device itself, remote controls, the cloud API, and the dashboard
- Practiced the **attacker's mindset framework**: What's valuable? What's exposed? What's weak? What's the path?
- Built a full **STRIDE threat model** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) for The Grand Marina
- **Deliverable**: a professional threat model document — the same kind of deliverable security consultants charge thousands of dollars to produce

### Project 2 — Learn Python Basics to Work With Sensor Data
**Building the language skills needed to simulate a real IoT device.**
- Python fundamentals: data structures, control flow, functions
- Working with **JSON** and **nested JSON** using Pandas
- Data cleaning and preparation concepts
- Built a `WaterSensor` class — a **mock sensor log generator** that simulates realistic pressure/flow readings, including timestamps and sequence counters (laying the groundwork for replay-attack defenses two months later)

### Project 3 — Build a Fake Sensor & Send Data in an Insecure Way
**Standing up the real pipeline — then attacking it.**
- Installed and configured **Mosquitto** (MQTT broker) and the **paho-mqtt** Python library
- Learned MQTT fundamentals: topics, QoS levels, publish/subscribe message flow
- Designed the full MQTT topic hierarchy for The Grand Marina (`hydroficient/grandmarina/sensors|commands|alerts|status/...`)
- Built `sensor_publisher.py` and `dashboard_subscriber.py` — a working three-terminal pipeline: sensor → broker → live dashboard
- **The uncomfortable experiment**: opened a fourth terminal, subscribed with zero authentication, and watched every device ID, pressure reading, and timestamp scroll past in plain text — proving the exact vulnerability an attacker would exploit

### Project 4 — Add Encryption & Test How It Affects Performance
**Closing the confidentiality gap with TLS.**
- Learned how TLS and digital certificates work (why HTTPS matters, what a Certificate Authority does)
- Wrote `generate_certs.py` to build a private **Certificate Authority** and issue a server certificate for the Mosquitto broker
- Configured Mosquitto for TLS and updated the Python client code accordingly
- Ran four controlled experiments — **Speed Test, Stress Test, Eavesdropper Test, Certificate Test** — comparing TLS vs. no-TLS under normal, moderate-load, and emergency-mode conditions
- **Deliverable**: a professional **Security Assessment Report** quantifying encryption overhead with real experimental evidence

### Project 5 — Control Which Devices Are Allowed to Connect
**Closing the identity gap with mutual TLS (mTLS).**
- Learned the difference between **one-way TLS** (server proves identity) and **mutual TLS** (both server and client prove identity)
- Simulated the exact attack this defends against: a rogue device with only the public CA certificate connecting, subscribing to every topic, and publishing fake pressure data — undetected, because TLS alone doesn't check *who* is connecting
- Generated a unique client certificate for each of the three HYDROLOGIC devices and reconfigured Mosquitto to require client certs
- **Benchmarked the cost of identity**: proved mTLS added negligible latency
- Ran **Identity Attack Simulations** — correct certificate, no client certificate, expired certificate, wrong certificate — and documented pass/fail results
- **Deliverable**: a formal **Device Provisioning Policy** covering onboarding, retirement, and compromised-device response

### Project 6 — Simulate an Attack That Replays Old Commands
**Closing the integrity/freshness gap with layered replay defenses.**
- Proved the gap first: captured legitimate encrypted MQTT traffic and successfully replayed it — the subscriber accepted every replayed message without complaint
- Implemented and compared **three independent defenses**, each catching what the others miss:

| Defense | Catches | Misses |
|---|---|---|
| **Timestamp validation** (30s window) | Stale replays | Immediate replays within the window |
| **Sequence counter** | Any exact or delayed replay | Modified replays with an incremented sequence number |
| **HMAC-SHA256 signing** | Any tampered/modified message | Byte-for-byte unmodified replays |

- Built `publisher_defended.py` and `subscriber_defended.py`, combining all three defenses
- Ran a **Defense Comparison** experiment proving that only the combination of all three closes every gap — no single control is sufficient on its own

### Project 7 — Build a Dashboard That Monitors Threats in Real Time
**Making the defense visible to a non-technical operator.**
- Learned why real-time visibility matters (a terminal log is useless to a GM checking his phone at 3 AM)
- Built a **4-component live architecture**: `dashboard.html` (the screen), `dashboard_server.py` (HTTP + WebSocket bridge), `subscriber_dashboard.py` (the validation logic from Project 6, now pushing events live), and the unchanged `publisher_defended.py`
- Used **WebSockets** (not polling) so the dashboard updates the instant an event happens — publish-to-browser latency under 1 second
- Ran `attack_simulator.py` for a **live attack demo**: the dashboard shows green zone cards for valid traffic and flips to a red "ATTACK DETECTED" panel the moment a forged/replayed/stale message is rejected
- Customized the dashboard's styling and built a **capstone presentation** summarizing Weeks 1–7

### Project 8 (Bonus) — Use AI to Spot Unusual Patterns in Sensor Data
**Closing the blind spot that rule-based defenses can't see.**
- The scenario that motivated this project: a sensor's pressure readings drift slowly from 59 → 61 → 63 → 66 PSI over six hours. Every single message has a **valid HMAC, a fresh timestamp, and a correct sequence number** — every rule-based check from Project 6 passes it. But 66 PSI at 4 AM, when nobody should be using water, is a leak in progress.
- Learned why deterministic rules (HMAC/timestamp/sequence) are binary pass/fail and structurally blind to *gradual drift* and *abnormal combinations* of otherwise-valid data
- Learned **Isolation Forest**: an unsupervised anomaly detection algorithm that isolates outliers with random data splits — points that are easy to isolate (few splits needed) are flagged as anomalies
- Ran experiments in Google Colab: trained a baseline model, compared **Isolation Forest vs. Local Outlier Factor (LOF)**, and ran hyperparameter experiments
- Moved the trained model from Colab into the live dashboard, adding a fourth, probabilistic layer on top of the three deterministic ones
- Updated the final presentation to include the AI layer

---

## 📊 Outcome

- **The Grand Marina passed its insurance audit on the first attempt in three years** — the auditor specifically called the live dashboard "the clearest security posture view she's reviewed at a property this size"
- The security architecture built in this externship became the **baseline spec for Hydroficient's next expansion** — a new 42-room wing at the same property
- Invited to help scope the threat model for that next phase

---

## 🎓 Skills Demonstrated

`Threat Modeling` `STRIDE` `CIA Triad` `Python` `MQTT` `TLS/mTLS` `PKI & Certificate Management` `HMAC` `Replay Attack Defense` `WebSockets` `Real-Time Dashboards` `Anomaly Detection` `Isolation Forest` `Security Assessment Reporting` `Technical Documentation` `Incident Simulation`

---

*This project was completed as part of the Extern Cybersecurity Externship (Hydroficient), under the mentorship of Maya Chen, Senior Security Engineer. All company names, client names, and scenarios are part of the externship's simulated training environment.*
