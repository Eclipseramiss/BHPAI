# BHPAI

## Introduction

**BHPAI** is a modular static malware analysis framework for Windows Portable Executable (PE) files.

The framework combines:

* Native PE analysis
* Automatic executable unpacking
* Handcrafted feature engineering
* Machine learning inference
* Explainable Artificial Intelligence
* Heuristic YARA rule generation

into a unified offline analysis pipeline.

Unlike traditional signature-based antivirus engines, BHPAI does not primarily rely on signature databases or hash matching. Instead, it extracts a comprehensive set of structural, statistical, and behavioral indicators from PE files and uses a pre-trained **LightGBM classifier** to estimate the probability that a file is malicious.

To improve analysis accuracy, BHPAI automatically detects supported executable packers and attempts to restore packed executables before feature extraction. This allows the classifier to analyze the underlying program structure rather than relying solely on compressed or obfuscated data.

The feature extraction engine is implemented entirely in **C++** for high-performance offline analysis.

---

## Core Analysis Capabilities

BHPAI currently supports the following static analysis components:

### PE Structure Analysis

* PE header analysis
* Section table analysis
* Import table analysis
* API statistics
* Import address table analysis
* Resource directory analysis
* Overlay detection and analysis
* File size and section ratio analysis

### Entropy and Statistical Analysis

* Code section entropy
* Maximum section entropy
* Mean section entropy
* Standard deviation of section entropy
* Overlay entropy characteristics
* Code-to-file ratios
* Entropy-based packing indicators

### String Analysis

* ASCII and Unicode string extraction
* Total string statistics
* Interesting and suspicious string detection
* Suspicious string ratios
* Version information analysis

### API and Code Analysis

* Imported API statistics
* API sequence extraction
* API repeat-ratio analysis
* API n-gram extraction
* Opcode n-gram extraction using **Capstone**
* Control-flow-related PE characteristics
* CFG-related feature extraction

### Automatic Unpacking

BHPAI supports automatic detection and unpacking of selected executable packers:

* UPX

  * NRV2B
  * NRV2D
  * NRV2E
* WWPack

The unpacking stage is performed before feature extraction whenever a supported packer is detected.

---

## AI-Powered Malware Detection

BHPAI uses a pre-trained **LightGBM gradient boosting classifier** to classify PE files based on a large set of engineered static features.

The model combines:

* PE structural features
* Entropy features
* Import and API features
* String statistics
* Resource characteristics
* Control-flow indicators
* API and opcode n-grams
* Executable packing indicators

The training pipeline includes:

* Data leakage analysis and removal
* Feature engineering
* API n-gram vocabulary construction
* Information-based feature selection
* Gain-based API n-gram selection
* LightGBM training
* Early stopping
* Decision threshold evaluation
* SHAP-based explainability
* Hard-negative analysis for false-positive reduction

The model is designed to learn combinations of features rather than relying on a single signature or hash.

---

## Explainable AI

BHPAI integrates **SHAP (SHapley Additive exPlanations)** to explain individual predictions.

For each analyzed PE file, SHAP can identify:

* Which features increased the malware probability
* Which features decreased the malware probability
* The relative contribution of each feature
* The primary reasons behind a prediction

This is particularly useful for analyzing false positives.

For example, a legitimate executable may be classified as suspicious due to a combination of:

* High code entropy
* High maximum section entropy
* Small import tables
* Missing manifests
* No overlay
* Unusual control-flow characteristics

Rather than treating the prediction as a black box, BHPAI exposes the feature-level reasoning behind it.

---

## Heuristic YARA Rule Generation

BHPAI can automatically generate heuristic YARA rules based on extracted characteristics, including:

* PE metadata
* Imported APIs
* Extracted strings
* Entropy characteristics
* Section properties
* Suspicious indicators
* Structural PE characteristics

The generated rules are intended to provide an additional detection and triage layer for malware research and threat analysis.

---

## Threat Scoring and Reporting

BHPAI produces a malware probability score and human-readable analysis output.

The analysis pipeline can provide:

* Malware probability
* Threat classification
* Confidence estimation
* Suspicious feature explanations
* PE structural information
* Entropy analysis
* Import/API analysis
* Packing information
* SHAP-based prediction explanations
* Heuristic YARA rules

---

# Dataset

## Dataset Overview

| Metric                    |                      Value |
| ------------------------- | -------------------------: |
| Total samples             |                  **8,370** |
| Malware                   |                  **4,210** |
| Benign                    |                  **4,160** |
| Train/Test Split          |                  **80/20** |
| Selected Feature Count    |                    **165** |
| API n-grams scanned       | **348,092 unique n-grams** |
| API n-gram vocabulary     |                  **1,000** |
| Positive-gain API n-grams |                     **32** |

The dataset is designed to include both malicious samples and increasingly difficult benign samples.

Particular attention is given to hard benign samples that share characteristics commonly associated with malware, including:

* High entropy
* Packed or compressed code
* No overlay
* Small import tables
* Missing manifests
* Unusual executable structures

This helps reduce false positives caused by legitimate software that superficially resembles packed or obfuscated malware.

---

# Training Summary

| Metric             |         Value |
| ------------------ | ------------: |
| Model              |  **LightGBM** |
| Best Iteration     |      **1000** |
| Train ROC-AUC      |   **1.00000** |
| Validation ROC-AUC |   **0.99814** |
| Early Stopping     | **50 rounds** |
| Decision Threshold |      **0.50** |

The model achieved a very high validation ROC-AUC while maintaining strong classification performance on the held-out evaluation set.

---

# Main Performance

| Metric              |      Score |
| ------------------- | ---------: |
| Accuracy            | **98.63%** |
| Precision           | **99.16%** |
| Recall / TPR        | **98.10%** |
| F1-score            | **98.63%** |
| ROC-AUC             | **99.78%** |
| PR-AUC              | **99.81%** |
| MCC                 | **97.26%** |
| Cohen's Kappa       | **97.25%** |
| Balanced Accuracy   | **98.63%** |
| G-Mean              | **98.63%** |
| Specificity / TNR   | **99.16%** |
| False Positive Rate |  **0.84%** |
| False Negative Rate |  **1.90%** |

---

# Confusion Matrix

|                    | Predicted Benign | Predicted Malware |
| ------------------ | ---------------: | ----------------: |
| **Actual Benign**  |     **825 (TN)** |        **7 (FP)** |
| **Actual Malware** |      **16 (FN)** |      **827 (TP)** |

### Summary

* **TP:** 827
* **TN:** 825
* **FP:** 7
* **FN:** 16

The model correctly classified **1,652 out of 1,675 evaluation samples**.

---

## Confusion Matrix

<img width="1109" height="944" alt="ez" src="https://github.com/user-attachments/assets/c3f05620-f277-450f-b73f-51014d9a7c4f" />

---

# Error Analysis

## False Positive Analysis

The latest benchmark produced only **7 false positives**.

The main patterns observed in false-positive analysis include:

* Extremely high code-section entropy
* Extremely high maximum section entropy
* No overlay data
* Small or unusual import tables
* Missing manifests
* Compressed or packed legitimate software
* Unusual control-flow characteristics

Example false positives include legitimate software such as:

| File                               | Predicted Malware Probability | Main Contributing Features             |
| ---------------------------------- | ----------------------------: | -------------------------------------- |
| `xpicleanup.exe`                   |                    **96.37%** | Small imports, no overlay, no manifest |
| `DOSBox0.74-3-win32-installer.exe` |                    **61.99%** | Extremely high code entropy            |
| `isotoxin.exe`                     |                    **73.71%** | High maximum entropy, no overlay       |
| `SecureAssessmentBrowser.exe`      |                    **81.57%** | No overlay, small import table         |
| `AkelUpdater.exe`                  |                    **76.30%** | High code entropy, no manifest         |

These cases demonstrate an important challenge in static malware detection:

> Legitimate packed, compressed, optimized, or unusually structured software can exhibit many of the same low-level characteristics as malware.

BHPAI therefore uses iterative hard-negative analysis to identify these cases and improve future model versions.

---

# False Positive Reduction

The training dataset has been progressively expanded with difficult benign samples.

A previous evaluation produced:

* **15 FP**
* **1.93% FPR**

After adding approximately **280 additional benign samples**, the latest evaluation produced:

* **7 FP**
* **0.84% FPR**

This represents approximately a **53% reduction in false positives** while maintaining approximately **98% malware recall**.

The iterative process is:

```text
Train Model
     ↓
Analyze False Positives
     ↓
Verify Legitimate Files
     ↓
Add Hard Benign Samples
     ↓
Retrain
     ↓
Evaluate Again
```

This process helps BHPAI learn that characteristics such as high entropy, missing manifests, or absent overlays are not independently sufficient to classify a file as malicious.

---

# Feature Importance

The most influential features in the current model include:

| Rank | Feature                |
| ---: | ---------------------- |
|    1 | `max_section_entropy`  |
|    2 | `code_section_entropy` |
|    3 | `overlay_size_bytes`   |
|    4 | `import_size`          |
|    5 | `manifest_size_log`    |
|    6 | `is_console`           |
|    7 | `api_repeat_ratio`     |
|    8 | `is_gui`               |
|    9 | `total_strings`        |
|   10 | `aslr_enabled`         |

Entropy-related features are particularly influential because packed, compressed, and obfuscated executables frequently exhibit high entropy.

However, BHPAI does not rely on entropy alone. The classifier combines multiple feature groups to reduce the risk of incorrectly classifying legitimate compressed or optimized software.

---

## Feature Importance

<img width="1329" height="784" alt="v" src="https://github.com/user-attachments/assets/d3a1a93f-934d-4625-8704-df96c8573b11" />

---

# ROC Curve

**ROC-AUC = 0.9978**

The Receiver Operating Characteristic (ROC) curve illustrates the model's ability to distinguish between malware and benign PE files across different classification thresholds.

A high ROC-AUC indicates strong overall class separation.

---

# Precision-Recall Curve

**PR-AUC = 0.9981**

The Precision-Recall curve is particularly important for malware detection because real-world malware datasets can be highly imbalanced.

PR-AUC evaluates the trade-off between:

* Precision
* Recall

and is especially useful when false positives and false negatives have different operational costs.

---

# Current Limitations

BHPAI is a static analysis framework and therefore has inherent limitations.

It may be affected by:

* Advanced packing
* Custom executable protectors
* Runtime decryption
* Fileless malware
* Dynamic API resolution
* Heavy obfuscation
* Polymorphic and metamorphic malware
* Samples requiring runtime behavior for detection

Static features can also produce false positives for legitimate software that is:

* Packed
* Compressed
* Highly optimized
* Generated by unusual compilers
* Distributed as a self-extracting executable

For this reason, BHPAI should complement, rather than replace:

* Traditional antivirus engines
* Sandbox analysis
* Dynamic behavioral analysis
* Reverse engineering
* Threat intelligence

---

# Use Cases

BHPAI is intended for:

* Malware research
* Reverse engineering
* Digital forensics
* Security education
* PE file analysis
* Offline malware triage
* Machine learning research in cybersecurity
* Explainable malware detection research

---

# Usage

```bash
python bhpai.py <filepath.exe>
```

Example:

```bash
python bhpai.py suspicious.exe
```

---

# Architecture

```text
                    PE File
                       │
                       ▼
              ┌─────────────────┐
              │  PE Detection    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Packer Detection │
              └────────┬────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
   Packed Executable          Normal Executable
          │                         │
          ▼                         │
    Automatic Unpacking             │
          │                         │
          └────────────┬────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ C++ PE Analyzer  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Feature Extraction│
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ LightGBM Model   │
              └────────┬────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      Prediction      SHAP       YARA
       Score       Explanation   Rules
          │            │            │
          └────────────┴────────────┘
                       │
                       ▼
                 Final Report
```

---

# Disclaimer

BHPAI is a research-oriented malware analysis framework.

The model is trained on a specific dataset and its performance may vary significantly on samples from different distributions, malware families, compiler toolchains, packers, and software ecosystems.

Benchmark results should not be interpreted as a guarantee of real-world detection performance.

BHPAI should be used as an additional analysis and research tool alongside established security solutions and professional malware analysis techniques.
