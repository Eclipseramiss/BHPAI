# BHPAI

**BHPAI** is a modular malware analysis framework for Windows Portable Executable (PE) files.
It combines **static analysis**, **automatic unpacking**, **machine-learning inference**, and a **user-mode dynamic behavioural sandbox** into a single research-oriented pipeline.

Unlike traditional signature-based antivirus engines, BHPAI does not primarily rely on hash databases. Instead, it extracts a rich set of structural, statistical and behavioural indicators and uses a pre-trained **LightGBM** classifier to estimate the probability that a sample is malicious. When the static score is ambiguous, a controlled sandbox execution is performed for verification.

---

## Table of Contents

- [Key Features](#key-features)
- [Hybrid Verdict Architecture](#hybrid-verdict-architecture)
- [Static Analysis](#static-analysis)
- [Dynamic Behavioural Sandbox](#dynamic-behavioural-sandbox)
- [AI-Powered Detection](#ai-powered-detection)
- [Dataset & Training Results](#dataset--training-results)
- [Usage](#usage)
- [Building from Source](#building-from-source)
- [Limitations](#limitations)
- [Disclaimer](#disclaimer)

---

## Key Features

| Category              | Capabilities |
|------------------------|--------------|
| **Static Analysis**    | PE headers, sections, imports, resources, overlay, certificates, Rich header, version info, entropy statistics, string analysis, API/opcode n-grams, CFG features |
| **Unpacking**            | Automatic detection & unpacking of **UPX** (NRV2B / NRV2D / NRV2E) and **WWPack** |
| **Machine Learning**       | LightGBM classifier, feature contribution explanations, hard-negative mining |
| **Dynamic Sandbox**          | Full user-mode isolation with API hooking, filesystem & registry virtualization, behavioural correlation, memory dumping |
| **Reporting**                   | Threat score, risk label, SHAP-style explanations, heuristic YARA rules, detailed sandbox JSON report |
| **GUI**                            | Modern PyQt6 / PySide6 interface (Dashboard, Scan, Sandbox, Benchmark, About) |

---

## Hybrid Verdict Architecture

BHPAI uses a two-stage hybrid decision pipeline:

1. **Static AI (LightGBM)** produces a malware probability (0–100%).
2. **Auto-conclude** when the score is highly confident:
   - < 30% → Clean / Low Risk
   - \> 95% → Critical Malware
3. When the score falls in the **ambiguous range (30–95%)**, the sample is executed inside **BHPAISandbox** for verification only (the sandbox does **not** make the final decision alone).
4. A rule-based **BehaviourRiskScorer** analyses the sandbox events and produces a behaviour risk score.
5. Optional SHAP-style verification compares static feature contributions with observed runtime behaviour.
6. Final threat score is computed as:

```
Final = 0.7 × Static + 0.3 × Behaviour + confidence_delta
```

---

## Static Analysis

### PE Structure
- DOS / NT headers, section table, import & delay-import tables
- Export table, resource directory, TLS callbacks
- Overlay detection and size analysis
- Digital signature presence & validity
- Rich header (compiler / tool identification)
- Version information extraction

### Entropy & Statistical Features
- Code-section entropy, maximum / mean / std section entropy
- Resource entropy statistics
- Overlay ratio, code-to-image ratio
- Packing indicators (high entropy, unusual section names)

### String Analysis
- ASCII & Unicode string extraction
- Interesting / suspicious string ratios
- Base64 / Hex / Caesar detection and decoding attempts

### API & Code Analysis
- Imported API statistics and suspicious API flags
- API call sequence extraction and n-gram generation
- Opcode n-gram extraction (Capstone)
- Control-flow graph (CFG) features: cyclomatic complexity, basic-block statistics, indirect call ratio, loop detection

### Automatic Unpacking
Supported packers:
- **UPX** – NRV2B, NRV2D, NRV2E decompressors + PE reconstruction
- **WWPack**

Unpacking is performed before feature extraction whenever a supported packer is detected.

---

## Dynamic Behavioural Sandbox

The sandbox consists of two main components:

### 1. Launcher (`BHPAISandbox.exe`)
- Creates the target process in a suspended state
- Injects the monitor DLL (architecture-aware: x86 / x64)
- Attaches a Job Object with resource limits (CPU, memory, process count, UI restrictions)
- Resumes execution and waits for termination or timeout
- Performs pre-exit memory dumping (RWX regions, private memory, embedded PEs, heaps)
- Runs post-execution behavioural analysis and writes a detailed JSON report

### 2. Monitor DLL (`sysnethelper.dll` / `sysnethelper32.dll`)
Injected into the target process. Responsibilities:

#### API Hooking (MinHook)
- **File** – CreateFile, NtCreateFile, WriteFile, DeleteFile, MoveFileEx, SetFileAttributes, FindFirst/NextFile…
- **Registry** – RegCreateKeyEx, NtCreateKey, NtSetValueKey, NtDeleteKey…
- **Process / Injection** – CreateProcess, CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, NtMapViewOfSection, NtQueueApcThread…
- **Network** – connect, send/recv, DNS queries, getaddrinfo, WinHttp, WinINet…
- **COM** – CoCreateInstance, CoGetClassObject
- **Named objects** – Mutex, Event, Semaphore, Section
- **Named pipes**
- **GDI / UI** – BitBlt family, MessageBox, SetWindowsHookEx, SystemParametersInfo, CreateWindowEx…

#### Virtualization
- **Filesystem** – Overlay redirection with whiteout support for delete semantics
- **Registry** – Complete virtual store under `Overlay\RegistryOverlay` (Win32 + Native NT APIs)

#### Anti-Detection & Mitigation
- Cloaking of common sandbox-detection named objects
- Rate-limiting of desktop GDI operations (visual-payload mitigation)
- MessageBox spam suppression
- Blocking of global / low-level input hooks
- Fake success for certain system-parameter changes

#### Event Pipeline

```
Raw API events → Asynchronous JSONL log → Semantic normalisation
→ Multi-event correlation (Drop-and-Execute, Reflective loading,
   Manual mapping, PE unpacking, Persistence, Self-deletion…)
→ Rule-based behaviour risk score (0–100)
→ Detailed sandbox JSON report
```

---

## AI-Powered Detection

- **Model**: LightGBM gradient boosting classifier
- **Features**: 165 selected features combining PE structural, entropy, import/API, string, resource, packing, CFG, API n-grams and sandbox behavioural features
- **Training pipeline**:
  - Data leakage analysis
  - API n-gram vocabulary construction
  - Information-gain / gain-based feature selection
  - Early stopping
  - Decision threshold evaluation
  - Hard-negative mining for false-positive reduction
  - Feature contribution explanations

---

## Dataset & Training Results

### Dataset Overview

| Metric                      | Value    |
|-------------------------------|----------|
| Total samples                   | 8,370    |
| Malware                          | 4,210    |
| Benign                             | 4,160    |
| Train / Test split                  | 80 / 20  |
| Selected feature count                | 165      |
| Unique API n-grams scanned              | 348,092  |
| API n-gram vocabulary                     | 1,000    |

### Main Performance (held-out evaluation)

| Metric                | Score    |
|-------------------------|----------|
| Accuracy                  | 98.63%   |
| Precision                   | 99.16%   |
| Recall (TPR)                  | 98.10%   |
| F1-score                         | 98.63%   |
| ROC-AUC                            | 99.78%   |
| PR-AUC                                | 99.81%   |
| MCC                                      | 97.26%   |
| Cohen's Kappa                              | 97.25%   |
| Balanced Accuracy                             | 98.63%   |
| Specificity (TNR)                                | 99.16%   |
| False Positive Rate                                 | 0.84%    |
| False Negative Rate                                    | 1.90%    |

### Confusion Matrix

|                     | Predicted Benign | Predicted Malware |
|----------------------|-------------------|---------------------|
| **Actual Benign**      | 825 (TN)            | 7 (FP)                |
| **Actual Malware**       | 16 (FN)               | 827 (TP)                |

### Top Influential Features
1. `max_section_entropy`
2. `code_section_entropy`
3. `overlay_size_bytes`
4. `import_size`
5. `manifest_size_log`
6. `is_console`
7. `api_repeat_ratio`
8. `is_gui`
9. `total_strings`
10. `aslr_enabled`

---

## Usage

### Static Analysis (CLI)
```bash
python bhpai.py <path_to_pe>
# or
pe_analyzer.exe sample.exe [--safe-run]
```

### Dynamic Sandbox
```bash
BHPAISandbox.exe <path_to_pe>
```

### Graphical Interface
```bash
python gui.py
```

The GUI provides:

- **Dashboard** – System telemetry
- **Scan** – Hybrid static + dynamic analysis with threat gauge and explanations
- **Sandbox** – Standalone sandbox execution and event visualisation
- **Benchmark** – Model evaluation metrics
- **About** – Version and architecture information

---

## Building from Source

### Requirements
- Windows 10 / 11 (x64)
- Visual Studio 2019 or later (C++17)
- Python 3.9+
- Capstone, MinHook, nlohmann/json, OpenSSL
- PyQt6 or PySide6, LightGBM, scikit-learn, pandas, numpy, joblib

### Build Steps (high-level)
1. Build the static analyser (`pe_analyzer.exe`) and unpackers.
2. Build the sandbox launcher (`BHPAISandbox.exe`) and monitor DLLs (`sysnethelper.dll` / `sysnethelper32.dll`).
3. Place the trained model (`malware_detector_lgb.pkl`) and feature list (`selected_features.txt`) in the expected resource paths.
4. Run the GUI or CLI tools.

Detailed build instructions and CMake / MSBuild project files are provided in the respective source directories.

---


## Limitations

BHPAI is primarily a static + user-mode dynamic research framework and therefore has inherent limitations:

- Advanced custom packers / protectors
- Runtime decryption and fileless techniques
- Direct syscalls that bypass user-mode hooks
- Kernel-mode rootkits
- Samples requiring prolonged interactive behaviour
- Legitimate packed or highly optimised software can still produce false positives (mitigated by hard-negative analysis)

The sandbox provides useful behavioural signals but does not offer the same isolation guarantees as a hypervisor-based or kernel-assisted sandbox.

---

## Disclaimer

BHPAI is a research-oriented malware analysis framework.

The model is trained on a specific dataset; performance may vary significantly on samples from different distributions, malware families, compiler toolchains or packers. Benchmark results should not be interpreted as a guarantee of real-world detection performance.

The dynamic sandbox is a user-mode isolation environment and should not be considered a complete security boundary.

BHPAI is intended to complement, not replace:

- Traditional antivirus engines
- Full-system / hypervisor sandboxes
- Manual reverse engineering
- Threat-intelligence platforms

Use responsibly and only on samples you are authorised to analyse.

---

**BHPAI — Behavioural Heuristic PE AI**
Research tool for malware analysis, reverse engineering and security education.
