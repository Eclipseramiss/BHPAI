# BHPAI

# Introduction

**BHPAI** is a static malware detection framework designed for Windows Portable Executable (PE) files. The project combines low-level PE analysis with machine learning to identify malicious executables based on structural characteristics, entropy statistics, import behavior, opcode patterns, and other static features.

Unlike traditional signature-based antivirus engines, BHPAI does not rely on hash matching or predefined malware signatures. Instead, it extracts a comprehensive set of handcrafted features from PE files and uses a pre-trained LightGBM classifier to estimate the probability that a file is malicious.

The feature extraction engine is implemented in C++ for high performance and includes support for:

* PE header and section analysis
* Import and API statistics
* Resource inspection
* Overlay detection
* Entropy analysis
* String analysis
* Opcode/API n-gram extraction using Capstone
* Control-flow related PE characteristics

To improve generalization, the training pipeline removes known leakage features, performs feature selection, optimizes the decision threshold, and evaluates the model using multiple performance metrics including Accuracy, Precision, Recall, F1-score, ROC-AUC, PR-AUC, and MCC.

BHPAI also provides explainable predictions through SHAP analysis, allowing users to understand which static characteristics contribute most to each classification result.

The project is intended for malware research, educational purposes, and offline static analysis. It is not designed to replace traditional antivirus software or dynamic malware analysis.

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
