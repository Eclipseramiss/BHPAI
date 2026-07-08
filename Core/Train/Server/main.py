import os
import sys
import shutil
import subprocess
import json
import time
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import magic
import numpy as np
import joblib
import uvicorn

app = FastAPI(title="Malware Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS 
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

UPLOAD_DIR = Path("uploads")
MODEL_PATH = get_resource_path("malware_detector_lgb.pkl")
FEATURES_PATH = get_resource_path("selected_features.txt")
PE_TOOL = get_resource_path("./pe.exe")

UPLOAD_DIR.mkdir(exist_ok=True)

scan_results = {}

def verify_pe_integrity(exe_path: str) -> bool:
    try:
        mime = magic.from_file(str(exe_path), mime=True)
        is_valid = mime == 'application/x-dosexec'
        if not is_valid:
            print(f"MIME type validation failed: {mime} (expected: application/x-dosexec)")
        return is_valid
    except Exception as e:
        print(f"Error checking MIME type: {e}")
        return False

print("Loading model and selected features...")
try:
    model = joblib.load(MODEL_PATH)
    with open(FEATURES_PATH, 'r', encoding='utf-8') as f:
        selected_features = [line.strip() for line in f.readlines() if line.strip()]
    print(f"Model loaded successfully! Number of features: {len(selected_features)}")
except Exception as e:
    print(f"Error loading model/features: {e}")
    raise

def extract_features_from_json(data: dict) -> dict:
    features = {}
    
    features['code_section_entropy'] = data.get('code_section_entropy', 0.0)
    features['relocation_entropy'] = data.get('relocation_entropy', 0.0)
    features['code_ratio'] = data.get('code_ratio', 0.0)
    
    sections = data.get('sections', [])
    features['num_sections'] = data.get('num_sections', len(sections))
    if sections:
        entropies = [s.get('entropy', 0) for s in sections]
        features['max_section_entropy'] = max(entropies) if entropies else 0.0
        features['min_section_entropy'] = min(entropies) if entropies else 0.0
        features['mean_section_entropy'] = float(np.mean(entropies))
        features['std_section_entropy'] = float(np.std(entropies)) if len(entropies) > 1 else 0.0
    else:
        features['max_section_entropy'] = 0.0
        features['min_section_entropy'] = 0.0
        features['mean_section_entropy'] = 0.0
        features['std_section_entropy'] = 0.0
    
    features['overlay_size_bytes'] = data.get('overlay_size_bytes', 0)
    features['resource_size'] = data.get('resource_size', 0)
    size_bytes = data.get('size_bytes', 1)
    features['overlay_ratio'] = features['overlay_size_bytes'] / max(1, size_bytes)

    features['import_function_count'] = data.get('import_function_count', 0)
    features['import_rva'] = data.get('import_rva', 0)
    features['import_size'] = data.get('import_size', 0)
    features['suspicious_api_count'] = data.get('suspicious_api_count', 0)
    features['suspicious_api_ratio'] = data.get('suspicious_api_ratio', 0.0)

    features['e_lfanew'] = data.get('e_lfanew', 0)
    features['entry_point_rva'] = data.get('entry_point_rva', 0)
    features['file_alignment'] = data.get('file_alignment', 0)
    features['image_base'] = data.get('image_base', 0)
    features['machine'] = data.get('machine', 0)
    features['magic'] = data.get('magic', 0)

    bool_flags = [
        'alignment_weird', 'aslr_enabled', 'cfg_enabled', 'checksum_zero', 
        'digital_signature_valid', 'e_lfanew_not_aligned', 'e_lfanew_too_large',
        'has_debug', 'has_http_post_exfil', 'has_luhn_or_cc_validation', 
        'has_mutex_persistence', 'has_signature', 'has_tls', 'has_track_pattern_strings',
        'is_console', 'is_dll', 'is_fsg', 'is_gui', 'is_invalid_dos', 'is_upx', 
        'is_wwpack', 'likely_pos_scraper', 'no_imports', 'nx_enabled', 
        'has_memory_scraping_apis'
    ]
    for flag in bool_flags:
        features[flag] = int(bool(data.get(flag, False)))

    ngrams = data.get('top_suspicious_ngrams', [])
    features['top_suspicious_ngrams_count'] = len(ngrams)
    if ngrams:
        features['suspicious_ngrams_high_count'] = sum(1 for n in ngrams if n.get('count', 0) > 100)
        features['suspicious_ngrams_total_weight'] = sum(n.get('weight', 0) for n in ngrams)
    else:
        features['suspicious_ngrams_high_count'] = 0
        features['suspicious_ngrams_total_weight'] = 0.0
    
    opcode_info = data.get('opcode_ngrams', {})
    features['opcode_ngrams_total'] = opcode_info.get('total_ngrams_found', len(opcode_info.get('opcode_ngrams', [])))
    features['approx_instructions_analyzed'] = opcode_info.get('approx_instructions_analyzed', 0)

    str_info = data.get('string_analysis', {})
    features['total_strings'] = str_info.get('total_strings_found', 0)
    interesting = str_info.get('interesting_strings', [])
    features['interesting_strings_count'] = len(interesting)
    features['interesting_strings_ratio'] = len(interesting) / max(1, features['total_strings'])

    return features

def run_pe_analyzer(exe_path: str) -> dict:
    try:
        print(f"Running pe.exe analyzer: {os.path.basename(exe_path)}")
        
        result = subprocess.run(
            [PE_TOOL, exe_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False
        )
        
        if result.returncode != 0:
            print(f"pe.exe warning: {result.stderr.decode(errors='ignore')[:500]}")

        json_files = list(UPLOAD_DIR.glob("*.json"))
        if not json_files:
            raise Exception("No JSON output file found from pe.exe")

        target_json = max(json_files, key=lambda x: x.stat().st_mtime)
        
        if target_json.stat().st_size < 300:
            raise Exception(f"JSON output file is too small ({target_json.stat().st_size} bytes)")

        with open(target_json, 'r', encoding='utf-8') as f:
            data = json.load(f)

        try:
            target_json.unlink()
        except:
            pass

        return data

    except subprocess.TimeoutExpired:
        raise Exception("pe.exe timeout (quá 3 phút)")
    except Exception as e:
        raise Exception(f"Lỗi chạy pe.exe: {str(e)}")

async def process_scan_background(scan_id: str, temp_exe: Path, filename: str, threshold: float):
    try:
        scan_results[scan_id]["status"] = "scanning"
        scan_results[scan_id]["progress"] = "Running PE analyzer..."

        pe_data = run_pe_analyzer(str(temp_exe))

        scan_results[scan_id]["progress"] = "Extracting features..."
        feat_dict = extract_features_from_json(pe_data)

        df = pd.DataFrame([feat_dict])
        
        for col in selected_features:
            if col not in df.columns:
                df[col] = 0.0
                
        df = df[selected_features].fillna(0)

        prob = float(model.predict(df)[0])
        is_malware = prob > threshold

        scan_results[scan_id].update({
            "malware_probability": round(prob, 4),
            "is_malware": bool(is_malware),
            "status": "Malware" if is_malware else "Benign",
            "threshold_used": round(threshold, 4),
            "file_size_bytes": pe_data.get("size_bytes"),
            "num_sections": pe_data.get("num_sections"),
            "import_function_count": pe_data.get("import_function_count"),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        print(f"Completed | scan_id={scan_id} | Prob={prob:.4f} | {'MALWARE' if is_malware else 'BENIGN'}")

    except Exception as e:
        print(f"[ERROR] Scan {scan_id}: {str(e)}")
        scan_results[scan_id].update({
            "status": "error",
            "error_message": str(e),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    
    finally:
        if temp_exe.exists():
            try:
                temp_exe.unlink(missing_ok=True)
            except:
                pass

@app.post("/scan")
async def scan_file(file: UploadFile = File(...), threshold: float = Form(0.65), background_tasks: BackgroundTasks = BackgroundTasks()):
    if not file.filename.lower().endswith('.exe'):
        raise HTTPException(status_code=400, detail="Only .exe files are allowed")

    scan_id = f"scan_{os.urandom(8).hex()}"
    temp_exe = UPLOAD_DIR / f"{scan_id}_{file.filename}"

    try:
        with open(temp_exe, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        print(f"Received file: {file.filename} | scan_id: {scan_id}")

        if not verify_pe_integrity(str(temp_exe)):
            temp_exe.unlink(missing_ok=True)
            raise HTTPException(
                status_code=400, 
                detail="File is not a valid PE executable (MIME type check failed)"
            )

        scan_results[scan_id] = {
            "scan_id": scan_id,
            "filename": file.filename,
            "status": "queued",
            "progress": "Waiting in queue...",
            "created_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        background_tasks.add_task(
            process_scan_background, 
            scan_id, 
            temp_exe, 
            file.filename, 
            threshold
        )

        return JSONResponse({
            "scan_id": scan_id,
            "filename": file.filename,
            "status": "queued",
            "message": "Scan started in background. Use /scan/result/{scan_id} to check status",
            "created_time": scan_results[scan_id]["created_time"],
        }, status_code=202)

    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] Scan {file.filename}: {str(e)}")
        if temp_exe.exists():
            try:
                temp_exe.unlink(missing_ok=True)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Error uploading/validating file: {str(e)}")

@app.get("/scan/result/{scan_id}")
async def get_scan_result(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Not found scan result")
    
    result = scan_results[scan_id]
    if result["status"] in ["queued", "scanning"]:
        return JSONResponse(result, status_code=202)
    
    status_code = 200 if result["status"] not in ["error"] else 500
    return JSONResponse(result, status_code=status_code)

@app.get("/")
async def root():
    return {
        "message": "Malware Detector API (Async + Security Enhanced)",
        "model_features": len(selected_features),
        "security_notes": [
            "MIME type verification (magic library)",
            "PE executable integrity check",
            "Background task processing (non-blocking)",
        ],
        "endpoints": {
            "scan": "POST /scan (file + threshold optional) - Returns 202 Accepted, scan runs in background",
            "get_result": "GET /scan/result/{scan_id} - Returns 202 if still processing, 200 when ready",
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)