# 🛡️ CyberSentinel AI — Agentic Cybersecurity System

> An event-driven, context-aware, multi-agent AI system for real-time
> cybersecurity monitoring, anomaly detection, malware analysis, and
> automated response.

---

## 📖 Project Overview

CyberSentinel AI is a fully agentic cybersecurity pipeline built in pure
Python.  It processes a continuous stream of security log events, scores
them with three complementary anomaly-detection models, routes suspicious
events through a decision layer, deep-dives into file threats using a
Computer Vision model (inspired by the original **bytes-cv.ipynb** notebook),
and executes automated responses — all visible in a real-time Streamlit
dashboard.

This is **not** a simple ML pipeline.  Each stage is encapsulated in an
autonomous agent that has a single, well-defined responsibility.  Agents
communicate by passing structured Python dictionaries — no message queues,
no external services, everything runs locally.

---

## 🏗️ Architecture

```
┌─────────────┐   raw events    ┌──────────────────┐
│  Simulator  │ ─────────────► │ MonitoringAgent  │  validate / enrich
└─────────────┘                 └────────┬─────────┘
                                         │ cleaned events
                                         ▼
                                ┌──────────────────┐
                                │ DetectionAgent   │  IF + Z-Score + UBA
                                └────────┬─────────┘
                                         │ anomaly_score + is_anomaly
                                         ▼
                                ┌──────────────────┐
                                │  DecisionAgent   │  severity + routing
                                └──┬─────────┬─────┘
                       file threat │         │ other threats
                                   ▼         ▼
                        ┌──────────────┐   ┌──────────────────┐
                        │ MalwareAgent │   │  ResponseAgent   │
                        │ (CV model)   │──►│  block / isolate │
                        └──────────────┘   └────────┬─────────┘
                                                     │ finalised events
                                                     ▼
                                           ┌──────────────────┐
                                           │  Streamlit UI    │
                                           └──────────────────┘
```

### Agent Responsibilities

| Agent | File | Role |
|-------|------|------|
| **Monitoring** | `agents/monitoring_agent.py` | Type-check, validate, deduplicate, enrich with known-bad IP flags |
| **Detection** | `agents/detection_agent.py` | Run three models, fuse scores into one `anomaly_score` |
| **Decision** | `agents/decision_agent.py` | Assign severity, choose action, route file threats |
| **Malware** | `agents/malware_agent.py` | Parse .bytes → RGB image → texture features → class label |
| **Response** | `agents/response_agent.py` | Execute log / throttle / block / isolate actions |
| **Orchestrator** | `orchestrator/main_orchestrator.py` | Wire agents together, drive the tick loop |

---

## 📂 Folder Structure

```
seminar_project/
├── agents/
│   ├── monitoring_agent.py
│   ├── detection_agent.py
│   ├── decision_agent.py
│   ├── malware_agent.py
│   └── response_agent.py
├── models/
│   ├── isolation_forest.py
│   ├── zscore.py
│   ├── uba.py
│   └── malware_cv_model.py
├── orchestrator/
│   └── main_orchestrator.py
├── data/
│   ├── simulator.py
│   └── cybersecurity_logs.csv    ← place Kaggle dataset here
├── ui/
│   └── app.py
├── utils/
│   └── helpers.py
├── logs/                          ← auto-created
├── config.py
├── requirements.txt
└── README.md
```

---

## ⚙️ How the Models Work

### 1. Isolation Forest (`models/isolation_forest.py`)
Randomly partitions the feature space. Points that are isolated in fewer
splits are anomalies. Trained on the first 50 events (warm-up), then scores
every subsequent event. Weight in fusion: **40%**.

### 2. Z-Score Detector (`models/zscore.py`)
Maintains a rolling window (default 50 events) of each numeric feature.
Any event where at least one feature is more than 3 standard deviations
from the rolling mean is flagged. Adapts to drifting behaviour. Weight: **35%**.

### 3. UBA — User Behaviour Analytics (`models/uba.py`)
Profiles each user's historical behaviour: failed login count, number of
distinct source IPs, and frequency of each event type. Flags deviations
from the user's own past baseline. Weight: **25%**.

### 4. Malware CV Model (`models/malware_cv_model.py`)
Directly from the notebook (`bytes-cv.ipynb`):

```
.bytes hexdump file
      │
      ▼ parse_hexdump()        — offset + hex bytes → uint8 array
      │
      ▼ bytes_to_image()       — pad/truncate → reshape to (64, 64, 3)
      │
      ▼ _texture_features()    — entropy, zero_frac, edge_density, …
      │
      ▼ _heuristic_classify()  — rule-based → label + confidence
```

The heuristic classifier runs with no GPU and no pre-trained weights:

| Condition | Predicted label |
|-----------|----------------|
| entropy > 0.85 | ransomware (encrypted payload) |
| zero_frac > 0.40 | benign (padded binary) |
| edge_density > 0.15 | worm (dense code) |
| high_frac > 0.35 | trojan |
| entropy < 0.40 | adware (string-heavy) |
| otherwise | spyware |

Drop a real sklearn or ONNX checkpoint at `models/malware_cnn.pkl` to
replace the heuristic with a trained model.

---

## 🚀 Setup Instructions

### 1. Clone / download the project

```bash
git clone <your-repo-url>
cd seminar_project
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. (Optional) Download the Kaggle dataset

Dataset: **Synthetic Cybersecurity Logs for Anomaly Detection**
URL: https://www.kaggle.com/datasets/fcwebdev/synthetic-cybersecurity-logs-for-anomaly-detection

Place the downloaded CSV at:

```
seminar_project/data/cybersecurity_logs.csv
```

**Without the dataset** the system automatically switches to *synthetic
mode*, generating realistic random events — all features still work.

### 5. (Optional) Add malware byte samples

Place `.bytes` hexdump files (Kaggle Microsoft Malware Classification
dataset format) inside:

```
seminar_project/data/malware_bytes/
```

Without them, the Malware Agent uses deterministic synthetic byte images.

---

## ▶️ How to Run

### Streamlit Dashboard (recommended)

```bash
# From the seminar_project/ directory:
streamlit run ui/app.py
```

Open your browser at **http://localhost:8501**, then press **▶ Start** in
the sidebar.

### Command-line batch mode

```bash
# From the seminar_project/ directory:
python -c "
from orchestrator.main_orchestrator import MainOrchestrator
orc = MainOrchestrator()
orc.run(max_batches=10)
print(orc.stats)
"
```

---

## 🔄 Data Flow Walkthrough

```
1. EventSimulator.next_batch()
   → list of raw event dicts with source_ip, dest_ip, user, event_type,
     raw_features {bytes_sent, bytes_received, duration_sec, …}

2. MonitoringAgent.process()
   → validates fields, coerces types, flags known-bad IPs, deduplicates
   → output: same list, cleaned

3. DetectionAgent.process()
   → IF model scores each event (0–1)
   → Z-Score model scores each event (0–1)
   → UBA model scores each event (0–1)
   → fusion: 0.40*IF + 0.35*Z + 0.25*UBA → anomaly_score
   → adds: anomaly_score, is_anomaly, model_scores{}

4. DecisionAgent.process()
   → maps score to severity (low/medium/high/critical)
   → maps severity to action (log/alert/block/isolate)
   → flags file-related high-severity events as is_file_threat=True
   → returns (file_threats, other_threats)

5. MalwareAgent.process()   [file_threats only]
   → loads or synthesises a .bytes sample
   → converts bytes → 64×64 RGB image
   → extracts texture features (entropy, edge density, …)
   → classifies → malware_label, malware_confidence, malware_is_threat
   → escalates severity to "critical" if malware confirmed

6. ResponseAgent.process()  [all events]
   → executes action: add to block-list, throttle list, isolation list
   → annotates: response_action, response_message, is_blocked, is_isolated

7. Streamlit UI
   → reads finalised events from orchestrator.history
   → renders KPI cards, trend charts, severity bar, pie chart, live table
```

---

## 📊 Dashboard Charts Explained

| Chart | What it shows |
|-------|---------------|
| **Anomaly Score Trend** | Average anomaly score per batch over time. The red dashed line marks the detection threshold. Spikes indicate attack bursts. |
| **Alerts per Batch** | Number of anomalous events detected per simulation tick. Colour-coded: green (low) → orange → red (high). |
| **Normal vs Anomalous Pie** | Cumulative distribution of all events since start. Ideally mostly green. |
| **Events by Severity** | Bar chart of low / medium / high / critical event counts. Indicates overall threat level. |
| **Malware Type Distribution** | When malware events exist, shows the mix of ransomware / trojan / worm etc. detected by the CV model. |
| **Live Event Table** | Most recent 200 events. Rows are colour-coded: red = critical, orange = high, yellow = medium. |

---

## 🗃️ Dataset Notes

### Primary dataset (required for CSV mode)
**Synthetic Cybersecurity Logs for Anomaly Detection**
https://www.kaggle.com/datasets/fcwebdev/synthetic-cybersecurity-logs-for-anomaly-detection

Contains labelled network log events with fields like source/destination IP,
bytes transferred, duration, and anomaly labels.

### Additional datasets (if you want to extend)

| Need | Kaggle dataset |
|------|----------------|
| Real malware byte samples | [Microsoft Malware Classification Challenge](https://www.kaggle.com/c/malware-classification) — `.bytes` hexdump files in exactly the format the notebook/MalwareAgent expects |
| Network intrusion | [KDD Cup 1999](https://www.kaggle.com/datasets/galaxyh/kdd-cup-1999-data) — adds 41 feature columns for richer detection |
| User login behaviour | [User Behaviour Anomaly Detection](https://www.kaggle.com/datasets/taha7ussein007/userauthenticationdataset) — improves UBA model |

---

## 🔧 Configuration Reference (`config.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `SIMULATION_BATCH_SIZE` | 20 | Events per tick |
| `SIMULATION_INTERVAL_SEC` | 2.0 | Seconds between UI refreshes |
| `IF_N_ESTIMATORS` | 100 | Isolation Forest trees |
| `IF_CONTAMINATION` | 0.05 | Expected anomaly fraction |
| `ZSCORE_THRESHOLD` | 3.0 | Standard deviations for flagging |
| `ZSCORE_ROLLING_WINDOW` | 50 | Window size for Z-Score |
| `UBA_MAX_FAILED_LOGINS` | 5 | Trigger threshold |
| `UBA_MAX_DISTINCT_IPS` | 3 | Trigger threshold |
| `ANOMALY_SCORE_THRESHOLD` | 0.50 | Combined score → anomaly |
| `HIGH_SEVERITY_THRESHOLD` | 0.75 | → high severity |
| `CRITICAL_SEVERITY_THRESHOLD` | 0.90 | → critical severity |
| `MALWARE_IMAGE_SIZE` | (64, 64) | Width × height for byte→image |
| `LOG_TO_FILE` | True | Enable file logging |

---

## 💡 Example Output (CLI)

```
Batch   1/10 | events= 18 | anomalies=  1 | blocked=0
Batch   2/10 | events= 19 | anomalies=  2 | blocked=1
Batch   3/10 | events= 20 | anomalies=  0 | blocked=1
Batch   4/10 | events= 18 | anomalies=  3 | blocked=2
...
```

Log file (`logs/system.log`):

```
[2024-07-15 10:23:01] INFO     agents.monitoring_agent — MonitoringAgent: 20 in → 19 forwarded
[2024-07-15 10:23:01] INFO     agents.detection_agent  — DetectionAgent: 19 events, 2 anomalies
[2024-07-15 10:23:01] WARNING  agents.response_agent   — BLOCK: 10.0.0.99 | user=user_007 | severity=high
```

---

## 🛠️ Troubleshooting

**`ModuleNotFoundError: No module named 'streamlit'`**
→ Run `pip install -r requirements.txt` inside your virtual environment.

**`streamlit run ui/app.py` — "command not found"**
→ Make sure your virtual environment is activated:
  `source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows).

**Charts are empty / no events appear**
→ Press the **▶ Start** button in the sidebar.  Charts only populate after
  the first batch is processed.

**`FileNotFoundError` for dataset CSV**
→ The system automatically falls back to synthetic mode.  No action needed
  unless you specifically want to test with the real dataset.

**Isolation Forest shows `cold-start` warning in logs**
→ Normal behaviour.  The IF model needs 50 events before it's fully fitted.
  Scores for the first few batches are preliminary.

**All events show `malware_label = —`**
→ Only `file_access` / `data_exfiltration` events with a high anomaly score
  are routed to the Malware Agent.  Run more batches and some will appear.

---

## 👤 Authors

Seminar project — Agentic AI Systems in Cybersecurity.
