# PE Analyzer + Malware Detector

A complete static analysis framework for Windows PE files with rule-based detection and machine learning classification.

---

## Overview

This project combines a powerful **C++ PE analyzer** with a **LightGBM machine learning model** to detect malware in Windows executables.

---

## Components

1. **pe_analyzer.exe** – Static PE analysis engine (C++)
2. **Training Pipeline** – Feature extraction + LightGBM model (Python)

---

## Features

### Core Analyzer (C++)
- Detailed PE header parsing (DOS, NT, Optional, Sections)
- Import table analysis with suspicious API detection
- Disassembly using Capstone engine
- Opcode n-gram analysis & TF-IDF vectorization
- String analysis (Base64, Hex, XOR, Caesar)
- Packer detection (UPX, FSG)
- Entropy analysis across sections and overlay
- TLS callbacks detection
- Digital signature verification
- Automatic YARA rule generation
- Structured JSON output

---

### Machine Learning Detector (Python)
- Feature engineering from analyzer JSON output
- LightGBM binary classifier
- High-precision threshold optimization
- Model saving and feature selection

---

## Project Structure
/
├── pe_analyzer.exe # Main analyzer (built from C++)
├── main.py / train.py # Training scripts
├── dataset/
│ ├── malware/ # JSON reports from malware samples
│ └── benign/ # JSON reports from clean files
├── malware_detector_lgb.pkl # Trained model
├── selected_features.txt # List of used features
├── Makefile
└── README.md

---

## Requirements

### For Analyzer (C++)

- Windows + MinGW-w64 / MSYS2
- Capstone
- OpenSSL

### For Training (Python)

```bash
pip install pandas numpy scikit-learn lightgbm tqdm joblib

---

If you want, I can also:
- convert this into a **GitHub-ready README with badges + CI**
- or refactor it into a **professional malware research paper format**
- or add **architecture diagram (C++ → JSON → ML pipeline)**
