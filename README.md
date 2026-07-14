# BHPAI

## Introduction

**BHPAI (Behavioral & Heuristic PE Artificial Intelligence)** is a modular static malware analysis framework for Windows Portable Executable (PE) files. The framework combines native PE analysis, automatic executable unpacking, handcrafted feature engineering, machine learning inference, explainable artificial intelligence, and heuristic YARA rule generation into a unified analysis pipeline.

Unlike traditional signature-based antivirus engines, BHPAI does not rely on signature databases or hash matching. Instead, it extracts a comprehensive set of static characteristics from PE files and uses a pre-trained LightGBM classifier to estimate the probability that a file is malicious.

To improve analysis accuracy, BHPAI automatically detects supported executable packers and restores packed executables before feature extraction, allowing the classifier to analyze the original program structure rather than compressed or obfuscated data.

The feature extraction engine is implemented entirely in **C++** for high-performance offline analysis and currently supports:

* PE header and section analysis
* Import table and API statistics
* Resource directory analysis
* Overlay detection
* Entropy analysis
* String extraction and analysis
* Opcode/API n-gram extraction using Capstone
* Control-flow related PE characteristics
* Automatic UPX unpacking (NRV2B/NRV2D/NRV2E)
* Automatic WWPack unpacking

BHPAI also provides:

* **AI-powered malware classification** using a pre-trained LightGBM model
* **Explainable AI (SHAP)** to identify the most influential features behind each prediction
* **Automatic heuristic YARA rule generation** based on PE metadata, imported APIs, extracted strings, entropy characteristics, and behavioral indicators
* **Threat scoring** with confidence estimation and human-readable analysis reports

The training pipeline is designed to improve model generalization by removing known data leakage features, performing feature selection, optimizing the decision threshold, and evaluating the classifier using multiple metrics, including:

* Accuracy
* Precision
* Recall
* F1-score
* ROC-AUC
* PR-AUC
* MCC
* Cohen's Kappa
* Balanced Accuracy
* G-Mean

BHPAI is intended for malware research, reverse engineering, digital forensics, security education, and offline static malware analysis. It is designed as a research-oriented analysis framework and should complement, rather than replace, traditional antivirus solutions and dynamic malware analysis.

## Dataset

**Dataset Overview**

| Metric                | Value     |
|-----------------------|-----------|
| Total samples         | 8,066     |
| Malware               | 4,191     |
| Benign                | 3,875     |
| Train/Test Split      | 80/20     |
| Feature Count         | 149       |
| API n-grams scanned   | 349,986   |
| Selected API n-grams  | 51        |

## Training Summary

| Metric                  | Value          |
|-------------------------|----------------|
| Model                   | LightGBM       |
| Best Iteration          | 988            |
| Train ROC-AUC           | 0.99997        |
| Validation ROC-AUC      | 0.99749        |
| Early Stopping          | 50 rounds      |
| Decision Threshold      | 0.50           |

## Main Performance Table

| Metric              | Score    |
|---------------------|----------|
| Accuracy            | 98.39%   |
| Precision           | 98.80%   |
| Recall              | 98.09%   |
| F1-score            | 98.44%   |
| ROC-AUC             | 99.65%   |
| PR-AUC              | 99.74%   |
| MCC                 | 96.78%   |
| Cohen's Kappa       | 96.77%   |
| Balanced Accuracy   | 98.40%   |

## Confusion Matrix
<img width="1600" height="1333" alt="Code_Generated_Image" src="https://github.com/user-attachments/assets/cc46a204-ad6a-4c1d-b823-79588e794f72" />

## Error Analysis

### Top False Positives

| File              | Probability | Main Reasons                     |
|-------------------|-------------|----------------------------------|
| MouseClickTool    | 99.43%      | High code entropy, high max entropy |
| neroAacEnc        | 73.92%      | Packed code, high entropy        |
| wmaencode         | 59.25%      | Packed executable                |
| FontForge         | 65.13%      | Overlay + entropy                |
| AutoWorkplace     | 86.15%      | Small import table               |

## Feature Importance
<img width="1600" height="960" alt="Code_Generated_Image (1)" src="https://github.com/user-attachments/assets/e048a5e8-2f69-4f94-a9f2-7b881d9bc705" />

## ROC Curve
**ROC AUC = 0.9965**

Receiver Operating Characteristic (ROC) curve – illustrates the model's ability to distinguish between malware and benign files

## Precision-Recall Curve
**PR AUC = 0.9974**

This is particularly important in malware detection, where datasets are often imbalanced

# 10 False Positives

* 4 packed applications
* 2 multimedia encoders
* 2 automation software
* 2 uncommon installers

**Most false positives are caused by high code entropy and compressed commercial software**
