# AIRA: Autonomous Incident Reasoning Agent

> **Capstone-I Project | Department of Computer Science & Engineering**  
> *(IoT & Cyber Security including Blockchain Technology)*  
> **Academic Year 2025 – 26 (Even Semester)**

---

## 👥 Team & Project Details
- **Project Title:** AIRA: Autonomous Incident Reasoning Agent
- **Team Members:**
  - S. Sai Puneeth (`2451-23-749-061`)
  - Syed Abrar Ahmed (`2451-23-749-042`)
  - C V Rahul Rao (`2451-23-749-029`)
- **Faculty Guide:** [ Faculty Guide Name ], *Designation, Dept. of CSE*

---

## 🛡️ Executive Summary & Motivation
Modern enterprise Security Operations Centers (SOCs) generate massive volumes of alerts across heterogeneous telemetry sources (Windows Event Logs, Sysmon, Zeek, EDR). Tier-1 and Tier-2 analysts suffer severe alert overload and fragmented context, requiring arduous manual pivot investigations to piece together timelines and attack chains.

**AIRA** solves this operational bottleneck by serving as an **agentic AI-assisted investigation framework**:
1. Ingests and normalizes multi-source endpoint & network logs.
2. Constructs an in-memory **Temporal Causal Provenance Graph** (Attack Graph).
3. Executes an autonomous **Hypothesis-Driven Reasoning Loop** to correlate activities and identify missing evidence / telemetry gaps.
4. Maps observed behaviors to standardized **MITRE ATT&CK** techniques.
5. Produces an evidence-grounded **Incident Dossier**, chronological attack timeline, and prioritized response recommendations while strictly keeping the human analyst in the loop.

---

## 🏗️ Architecture Pipeline

```
Security Telemetry (Sysmon / EVTX / Network)
                   │
                   ▼
       Canonical Event Normalization
                   │
                   ▼
     Temporal Causal Attack Graph Builder
   (Processes, Sockets, Files, Registry Keys)
                   │
                   ▼
       AIRA Agentic Reasoning Core
  ┌────────────────────────────────────────┐
  │ • Root-Cause Backward Provenance       │
  │ • Forward Blast-Radius Reachability    │
  │ • Evidence-Based Hypothesis Generation │
  │ • Missing Evidence Gap Audit           │
  │ • MITRE ATT&CK Heuristic Engine        │
  └───────────────────┬────────────────────┘
                      │
                      ▼
     Reconstructed Chronological Timeline
                      │
                      ▼
  Incident Dossier & Actionable Recommendations
                      │
                      ▼
    Human SOC Analyst (Approval / Response)
```

---

## 📁 Repository Structure
```
aira/
├── aira/
│   ├── core/
│   │   ├── models.py            # Canonical Event, Entity, Hypothesis, Dossier models
│   │   ├── normalizer.py        # Sysmon / EVTX to Canonical schema parser
│   │   ├── graph_builder.py     # NetworkX temporal causal provenance graph engine
│   │   ├── mitre_mapper.py      # MITRE ATT&CK technique mapping engine
│   │   ├── reasoning_agent.py   # Autonomous hypothesis & investigation agent
│   │   └── report_generator.py  # Incident dossier & Markdown report generator
│   ├── data/
│   │   └── samples/             # Multi-stage attack datasets (e.g. sample_attack_chain.json)
│   └── ui/                      # Analyst Workbench UI modules
├── tests/                       # Unit and integration test suites
├── requirements.txt             # Project dependencies
├── run_demo.py                  # One-click end-to-end investigation demonstration
└── README.md                    # Project documentation
```

---

## 🚀 Quick Start & Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the End-to-End Investigation Demo
```bash
python run_demo.py
```

This will:
- Load the multi-stage attack telemetry from `sample_attack_chain.json`.
- Normalize all events into canonical representations.
- Build the directed causal provenance graph.
- Execute backward root-cause tracing and forward blast-radius analysis.
- Correlate events with MITRE ATT&CK techniques (T1204, T1059, T1071, T1547, T1003, T1021).
- Formulate evidence hypotheses and detect missing evidence.
- Render the rich interactive terminal dashboard.
- Export `incident_report_INC-001.md`.

---

## 🎯 Capstone Deliverables Tracker
- [x] Multi-Source Event Correlation Engine
- [x] Attack Graph Representation & Subgraph Extractor
- [x] Attack Timeline Builder
- [x] Evidence-Grounded AI Investigation Report Generator
- [x] Functional AIRA Prototype Pipeline
