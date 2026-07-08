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

app = FastAPI(title="Malware Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====================== CONFIG ======================

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

# ====================== HELPER FUNCTIONS ======================
def verify_pe_integrity(exe_path: str) -> bool:

    try:
        mime = magic.from_file(str(exe_path), mime=True)
        is_valid = mime == 'application/x-dosexec'
        if not is_valid:
            print(f"⚠️ MIME type validation failed: {mime} (expected: application/x-dosexec)")
        return is_valid
    except Exception as e:
        print(f"❌ Error checking MIME type: {e}")
        return False

# ====================== LOAD MODEL & FEATURES ======================
print("Đang load model và selected features...")
try:
    model = joblib.load(MODEL_PATH)
    with open(FEATURES_PATH, 'r', encoding='utf-8') as f:
        selected_features = [line.strip() for line in f.readlines() if line.strip()]
    print(f"✅ Model loaded thành công! Số features: {len(selected_features)}")
except Exception as e:
    print(f"❌ Lỗi load model/features: {e}")
    raise

def extract_features_from_json(data: dict) -> dict:
    features = {}
    
    # 1. Entropy & structural features
    features['code_section_entropy'] = data.get('code_section_entropy', 0.0)
    features['relocation_entropy'] = data.get('relocation_entropy', 0.0)
    
    sections = data.get('sections', [])
    features['num_sections'] = len(sections)
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
    
    features['code_ratio'] = data.get('code_ratio', 0.0)
    features['overlay_size_bytes'] = data.get('overlay_size_bytes', 0)
    features['resource_size'] = data.get('resource_size', 0)
    features['overlay_ratio'] = features['overlay_size_bytes'] / max(1, data.get('size_bytes', 1))

    # 2. Import & API
    features['import_function_count'] = data.get('import_function_count', 0)
    features['suspicious_api_count'] = data.get('suspicious_api_count', 0)
    features['suspicious_api_ratio'] = data.get('suspicious_api_ratio', 0.0)

    # 3. Ngrams
    ngrams = data.get('top_suspicious_ngrams', [])
    features['top_suspicious_ngrams_count'] = len(ngrams)
    features['suspicious_ngrams_high_count'] = sum(1 for n in ngrams if n.get('count', 0) > 100)
    features['suspicious_ngrams_total_weight'] = sum(n.get('weight', 0) for n in ngrams)
    
    features['opcode_ngrams_total'] = data.get('opcode_ngrams', {}).get('total_ngrams_found', 0)

    # 4. Strings
    str_info = data.get('string_analysis', {})
    features['total_strings'] = str_info.get('total_strings_found', 0)
    interesting = str_info.get('interesting_strings', [])
    features['interesting_strings_count'] = len(interesting)
    features['interesting_strings_ratio'] = len(interesting) / max(1, features['total_strings'])

    # 5. Boolean flags
    features['has_memory_scraping_apis'] = int(data.get('has_memory_scraping_apis', False))
    features['has_tls'] = int(data.get('has_tls', False))
    features['is_gui'] = int(data.get('is_gui', False))
    features['is_dll'] = int(data.get('is_dll', False))

    return features

# ====================== RUN PE ANALYZER ======================
def run_pe_analyzer(exe_path: str) -> dict:
    try:
        print(f"🔍 Đang chạy pe.exe phân tích: {os.path.basename(exe_path)}")
        
        result = subprocess.run(
            [PE_TOOL, exe_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False
        )
        
        if result.returncode != 0:
            print(f"⚠️ pe.exe warning: {result.stderr.decode(errors='ignore')[:500]}")

        json_files = list(UPLOAD_DIR.glob("*.json"))
        if not json_files:
            raise Exception("Không tìm thấy file JSON output từ pe.exe")

        target_json = max(json_files, key=lambda x: x.stat().st_mtime)
        
        if target_json.stat().st_size < 300:
            raise Exception(f"File JSON output quá nhỏ ({target_json.stat().st_size} bytes)")

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

# ====================== BACKGROUND SCANNING TASK ======================
async def process_scan_background(scan_id: str, temp_exe: Path, filename: str, threshold: float):

    try:
        # Update status: scanning
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
        print(f"✅ Hoàn tất | scan_id={scan_id} | Prob={prob:.4f} | {'MALWARE' if is_malware else 'BENIGN'}")

    except Exception as e:
        print(f"❌ [ERROR] Scan {scan_id}: {str(e)}")
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

# ====================== SCAN ENDPOINT ======================
@app.post("/scan")
async def scan_file(file: UploadFile = File(...), threshold: float = Form(0.65), background_tasks: BackgroundTasks = BackgroundTasks()):
    # Quick extension check
    if not file.filename.lower().endswith('.exe'):
        raise HTTPException(status_code=400, detail="Chỉ hỗ trợ file .exe")

    scan_id = f"scan_{os.urandom(8).hex()}"
    temp_exe = UPLOAD_DIR / f"{scan_id}_{file.filename}"

    try:
        with open(temp_exe, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        print(f"📤 Nhận file: {file.filename} | scan_id: {scan_id}")

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
        }, status_code=202)  # 202 Accepted

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ [ERROR] Scan {file.filename}: {str(e)}")
        if temp_exe.exists():
            try:
                temp_exe.unlink(missing_ok=True)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Lỗi upload/validate file: {str(e)}")

# ====================== GET RESULT ======================
@app.get("/scan/result/{scan_id}")
async def get_scan_result(scan_id: str):

    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Không tìm thấy kết quả quét")
    
    result = scan_results[scan_id]
    
    # Return 202 Accepted if still processing
    if result["status"] in ["queued", "scanning"]:
        return JSONResponse(result, status_code=202)
    
    # Return 200 OK if completed or 500 if error
    status_code = 200 if result["status"] not in ["error"] else 500
    return JSONResponse(result, status_code=status_code)

@app.get("/")
async def root():
    return {
        "message": "Malware Detector API (Async + Security Enhanced)",
        "model_features": len(selected_features),
        "security_notes": [
            "✅ MIME type verification (magic library)",
            "✅ PE executable integrity check",
            "✅ Background task processing (non-blocking)",
        ],
        "endpoints": {
            "scan": "POST /scan (file + threshold optional) - Returns 202 Accepted, scan runs in background",
            "get_result": "GET /scan/result/{scan_id} - Returns 202 if still processing, 200 when ready",
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)