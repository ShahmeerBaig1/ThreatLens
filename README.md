# ThreatLens

### Log Analysis & Threat Intelligence Dashboard

---

## Overview

ThreatLens is a web-based application for analyzing system and application logs to identify potentially suspicious or high-risk activity. It is designed as a compact, self-contained platform that demonstrates how raw log data can be transformed into structured, actionable insights.

While developed as an academic project, the system follows patterns commonly seen in modern security tooling: ingestion, analysis, visualization, and reporting.

---

## Key Capabilities

### Log Analysis

* Upload and process standard `.log` files
* Identify suspicious patterns such as authentication failures, unauthorized access attempts, and malformed requests
* Apply rule-based detection to highlight anomalous entries

---

### Visualization & Reporting

* Aggregate view of total and suspicious events
* Severity classification (low, medium, high)
* Timeline and distribution charts for observed activity
* Dashboard-style presentation for quick interpretation

---

### Synthetic Log Generation

* Generate realistic log datasets for testing and demonstration
* Adjustable parameters:

  * Number of entries
  * Ratio of suspicious activity
* Eliminates dependency on live systems or external datasets

---

### AI-Assisted Analysis (Optional)

* Generates structured threat intelligence summaries using a language model
* Includes:

  * Executive overview
  * Pattern identification
  * Risk assessment
  * Suggested mitigation steps
* Designed as an augmentation layer, not a replacement for rule-based analysis

---

## Technology Stack

**Backend**

* Python (Flask)
* Procedural design for simplicity and clarity

**Frontend**

* HTML with Tailwind CSS
* Flowbite UI components
* Chart.js for data visualization

**AI Integration (Optional)**

* Gemini API

---

## Project Structure

```
threatlens/
│
├── app.py
├── logs/              # Generated log files
├── uploads/           # User-uploaded logs
│
├── templates/
│   ├── landing.html
│   ├── upload.html
│   ├── results_nuclear.html
│   └── generator.html
│
└── static/
```

---

## Setup

### Install dependencies

```bash
pip install flask google-generativeai
```

### Configure environment (optional)

```bash
export ENABLE_AI=true
export GEMINI_API_KEY=your_api_key_here
```

### Run the application

```bash
python app.py
```

Access the application at:

```
http://127.0.0.1:5000
```

---

## Usage Flow

1. Generate or obtain a log file
2. Upload the file through the analysis interface
3. Review detected anomalies and summary metrics
4. (Optional) Generate an AI-assisted report

---

## Scope and Limitations

ThreatLens is intended for demonstration and educational purposes. The detection logic is rule-based and does not provide the depth or accuracy of production-grade intrusion detection systems.

It is best understood as a prototype illustrating core concepts rather than a comprehensive security solution.

---

## Closing Note

The goal of ThreatLens is to show how relatively simple components—log parsing, pattern matching, and visualization—can be combined into a coherent system that supports security analysis.

It emphasizes clarity, usability, and extensibility over complexity.
