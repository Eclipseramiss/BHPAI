import os
import sys
import shutil
import subprocess
import json
import time
import argparse
from pathlib import Path
import pandas as pd
import magic
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfTransformer

def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS 
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

MODEL_PATH = get_resource_path("malware_detector_lgb.pkl")
FEATURES_PATH = get_resource_path("selected_features.txt")
PE_TOOL = get_resource_path("./pe.exe")
API_NGRAM_PREFIX = "api_ng__"

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

def extract_features_from_json(data: dict, selected_features, api_ngram_features) -> dict:
    features = {}

    features['code_section_entropy'] = data.get('code_section_entropy', 0.0)
    features['relocation_entropy']   = data.get('relocation_entropy', 0.0)
    features['code_ratio']           = data.get('code_ratio', 0.0)

    sections = data.get('sections', [])
    features['num_sections'] = data.get('num_sections', len(sections))
    if sections:
        entropies = [s.get('entropy', 0) for s in sections]
        features['max_section_entropy']  = max(entropies) if entropies else 0.0
        features['min_section_entropy']  = min(entropies) if entropies else 0.0
        features['mean_section_entropy'] = float(np.mean(entropies))
        features['std_section_entropy']  = float(np.std(entropies)) if len(entropies) > 1 else 0.0
    else:
        features['max_section_entropy']  = 0.0
        features['min_section_entropy']  = 0.0
        features['mean_section_entropy'] = 0.0
        features['std_section_entropy']  = 0.0

    features['overlay_size_bytes'] = data.get('overlay_size_bytes', 0)
    features['resource_size']      = data.get('resource_size', 0)
    features['num_resources']      = data.get('num_resources', 0)
    features['resource_entropy']   = data.get('resource_entropy', 0.0)
    size_bytes = data.get('size_bytes', 1)
    features['overlay_ratio'] = features['overlay_size_bytes'] / max(1, size_bytes)
    features['resource_ratio'] = features['resource_size'] / max(1, size_bytes)

    features['resource_total']              = data.get('resource_total', 0)
    features['resource_icon_count']         = data.get('resource_icon_count', 0)
    features['resource_cursor_count']       = data.get('resource_cursor_count', 0)
    features['resource_bitmap_count']       = data.get('resource_bitmap_count', 0)
    features['resource_dialog_count']       = data.get('resource_dialog_count', 0)
    features['resource_menu_count']         = data.get('resource_menu_count', 0)
    features['resource_stringtable_count']  = data.get('resource_stringtable_count', 0)
    features['resource_accelerator_count']  = data.get('resource_accelerator_count', 0)
    features['resource_manifest_count']     = data.get('resource_manifest_count', 0)
    features['resource_version_count']      = data.get('resource_version_count', 0)
    features['resource_rcdata_count']       = data.get('resource_rcdata_count', 0)
    features['resource_other_count']        = data.get('resource_other_count', 0)

    features['resource_entropy_mean'] = data.get('resource_entropy_mean', 0.0)
    features['resource_entropy_max']  = data.get('resource_entropy_max', 0.0)
    features['resource_entropy_std']  = data.get('resource_entropy_std', 0.0)

    manifest_present = int(bool(data.get("manifest_present", False)))
    manifest_size = data.get("manifest_size", 0)
    features["manifest_present"] = manifest_present
    features["manifest_size_log"] = np.log1p(manifest_size) if manifest_present else 0.0
    features['manifest_entropy'] = data.get('manifest_entropy', 0.0)

    if 'manifest_execution_level' in data:
        features['manifest_execution_level'] = data['manifest_execution_level']
    elif data.get('manifest_requested_admin'):
        features['manifest_execution_level'] = 3
    else:
        features['manifest_execution_level'] = 0

    features['manifest_uiaccess']            = int(bool(data.get('manifest_uiaccess', False)))
    features['manifest_auto_elevate']        = int(bool(data.get('manifest_auto_elevate', False)))
    features['manifest_requested_privilege'] = data.get('manifest_requested_privilege', 0)
    features['manifest_has_dpi']             = int(bool(data.get('manifest_has_dpi', False)))
    features['manifest_has_com']             = int(bool(data.get('manifest_has_com', False)))
    features['manifest_has_dependencies']    = int(bool(data.get('manifest_has_dependencies', False)))
    features['manifest_dependency_count']    = data.get('manifest_dependency_count', 0)

    features['certificate_present'] = int(bool(data.get('certificate_present', False)))
    if 'certificate_count' in data:
        features['certificate_count'] = data['certificate_count']
    elif features['certificate_present'] or data.get('certificate_size', 0) > 0:
        features['certificate_count'] = 1
    else:
        features['certificate_count'] = 0

    features['has_version_info']              = int(bool(data.get('has_version_info', False)))
    features['version_company_name_length']   = data.get('version_company_name_length', 0)
    features['version_product_name_length']   = data.get('version_product_name_length', 0)
    features['version_description_length']    = data.get('version_description_length', 0)
    features['version_original_filename_len'] = data.get('version_original_filename_len', 0)
    features['version_product_version_len']   = data.get('version_product_version_len', 0)

    features['rich_header_present'] = int(bool(data.get('rich_header_present', False)))
    features['rich_header_entries'] = data.get('rich_header_entries', 0)
    features['rich_has_vs2015']     = int(bool(data.get('rich_has_vs2015', False)))
    features['rich_has_vs2017']     = int(bool(data.get('rich_has_vs2017', False)))
    features['rich_has_vs2019']     = int(bool(data.get('rich_has_vs2019', False)))
    features['rich_has_vs2022']     = int(bool(data.get('rich_has_vs2022', False)))
    features['rich_has_masm']       = int(bool(data.get('rich_has_masm', False)))
    features['rich_has_cvtres']     = int(bool(data.get('rich_has_cvtres', False)))

    features['import_function_count'] = data.get('import_function_count', 0)
    features['import_rva']            = data.get('import_rva', 0)
    features['import_size']           = data.get('import_size', 0)
    features['suspicious_api_count']  = data.get('suspicious_api_count', 0)
    features['suspicious_api_ratio']  = data.get('suspicious_api_ratio', 0.0)

    api_flags = [
        'has_VirtualAlloc', 'has_VirtualProtect', 'has_WriteProcessMemory',
        'has_ReadProcessMemory', 'has_CreateRemoteThread', 'has_NtMapViewOfSection',
        'has_QueueUserAPC', 'has_WinExec', 'has_ShellExecute', 'has_LoadLibrary',
        'has_GetProcAddress', 'has_InternetOpen', 'has_WinHttpOpen',
        'has_CryptEncrypt', 'has_BCryptEncrypt'
    ]
    for flag in api_flags:
        features[flag] = int(bool(data.get(flag, False)))

    features['e_lfanew']        = data.get('e_lfanew', 0)
    features['entry_point_rva'] = data.get('entry_point_rva', 0)
    features['file_alignment']  = data.get('file_alignment', 0)
    features['image_base']      = data.get('image_base', 0)
    features['machine']         = data.get('machine', 0)
    features['magic']           = data.get('magic', 0)

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
    features['top_suspicious_ngrams_count']  = len(ngrams)
    features['suspicious_ngrams_high_count'] = sum(1 for n in ngrams if n.get('count', 0) > 100)
    features['suspicious_ngrams_total_weight'] = sum(n.get('weight', 0) for n in ngrams)

    opcode_info = data.get('opcode_ngrams', {})
    features['opcode_ngrams_total'] = opcode_info.get('total_ngrams_found',
                                                      len(opcode_info.get('opcode_ngrams', [])))
    features['approx_instructions_analyzed'] = opcode_info.get('approx_instructions_analyzed', 0)

    cfg_info = data.get('CFG', {})
    features['cfg_build_success']         = int(bool(cfg_info.get('build_success', False)))
    features['cfg_num_basic_blocks']      = cfg_info.get('num_basic_blocks', 0)
    features['cfg_num_edges']             = cfg_info.get('num_edges', 0)
    features['cfg_cyclomatic_complexity'] = cfg_info.get('cyclomatic_complexity', 0)
    features['cfg_average_out_degree']    = cfg_info.get('average_out_degree', 0.0)
    features['cfg_average_in_degree']     = cfg_info.get('average_in_degree', 0.0)
    features['cfg_max_out_degree']        = cfg_info.get('max_out_degree', 0)
    features['cfg_max_call_depth']        = cfg_info.get('max_call_depth', 0)
    features['cfg_recursive_function_count'] = cfg_info.get('recursive_function_count', 0)
    features['cfg_back_edge_ratio']       = cfg_info.get('back_edge_ratio', 0.0)
    features['cfg_jump_density']          = cfg_info.get('cfg_jump_density', 0.0)
    features['cfg_branch_density']        = cfg_info.get('cfg_branch_density', 0.0)
    features['cfg_indirect_control_flow'] = cfg_info.get('indirect_control_flow', 0)
    features['cfg_indirect_call_ratio']   = cfg_info.get('indirect_call_ratio', 0.0)
    features['cfg_call_count']            = cfg_info.get('call_count', 0)
    features['cfg_avg_block_size']        = cfg_info.get('avg_block_size', 0.0)
    features['cfg_has_loops']             = int(bool(cfg_info.get('has_loops', False)))
    features['cfg_unreachable_blocks']    = cfg_info.get('unreachable_blocks', 0)

    str_info = data.get('string_analysis', {})
    features['total_strings']             = str_info.get('total_strings_found', 0)
    interesting = str_info.get('interesting_strings', [])
    features['interesting_strings_count'] = len(interesting)
    features['interesting_strings_ratio'] = len(interesting) / max(1, features['total_strings'])

    api_ng: dict = data.get('api_ngrams', {})
    for ng in api_ngram_features:
        col = API_NGRAM_PREFIX + ng
        features[col] = api_ng.get(ng, 0)

    seq = data.get('api_sequence', [])
    seq_len = data.get('api_seq_length', len(seq))
    if seq_len is None or seq_len < 0:
        seq_len = len(seq)
    features['api_seq_length'] = int(seq_len)

    unique_calls = data.get('api_unique_calls', len(set(seq)) if seq else 0)
    if unique_calls is None or unique_calls < 0:
        unique_calls = len(set(seq)) if seq else 0
    features['api_unique_calls'] = int(unique_calls)

    if 'api_repeat_ratio' in data and data['api_repeat_ratio'] is not None:
        repeat_ratio = data['api_repeat_ratio']
        if not np.isfinite(repeat_ratio):
            repeat_ratio = 0.0
    else:
        repeat_ratio = (1.0 - unique_calls / max(1, seq_len) if seq_len > 0 else 0.0)
    features['api_repeat_ratio'] = float(repeat_ratio)
    features['api_sequence_present'] = int(bool(seq))
    counts = np.array(list(api_ng.values()))
    if counts.sum() > 0:
        probs = counts / counts.sum()
        features['api_entropy'] = -np.sum(probs * np.log2(probs + 1e-12))
    else:
        features['api_entropy'] = 0.0

    transitions = [(seq[i], seq[i+1]) for i in range(len(seq)-1)]
    features['api_total_transitions'] = len(transitions)
    features['api_unique_transitions'] = len(set(transitions))
    out_deg = {}
    loop_cnt = 0
    for src, dst in transitions:
        out_deg.setdefault(src, set()).add(dst)
        if src == dst:
            loop_cnt += 1
    features['api_avg_out_degree'] = np.mean([len(t) for t in out_deg.values()]) if out_deg else 0.0
    features['api_loop_ratio'] = loop_cnt / max(len(transitions), 1)
    features['api_repeated_transition_ratio'] = (len(transitions) - len(set(transitions))) / max(len(transitions), 1)

    return features


def run_pe_analyzer(exe_path: str, temp_dir: Path) -> dict:
    try:
        abs_exe_path = os.path.abspath(exe_path)
        abs_pe_tool = os.path.abspath(PE_TOOL)
        abs_temp_dir = os.path.abspath(temp_dir)
        if not os.path.exists(abs_pe_tool):
            raise Exception(f"PE analyzer tool not found at: {abs_pe_tool}")
        result = subprocess.run(
            [abs_pe_tool, abs_exe_path, "--safe-run"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=abs_temp_dir,
            timeout=180,
            check=False
        )
        if result.returncode != 0:
            err_msg = result.stderr.decode(errors='ignore')[:500]
            if err_msg.strip():
                print(f"pe.exe stderr: {err_msg}")
            stdout_msg = result.stdout.decode(errors='ignore')[:500]
            if stdout_msg.strip():
                print(f"pe.exe stdout: {stdout_msg}")
        temp_path = Path(abs_temp_dir)
        json_files = list(temp_path.glob("*.json"))
        if not json_files:
            raise Exception(f"No JSON output file found from pe.exe in {abs_temp_dir}. Return code: {result.returncode}")
        target_json = max(json_files, key=lambda x: x.stat().st_mtime)
        
        if target_json.stat().st_size < 300:
            raise Exception(f"JSON output file is too small ({target_json.stat().st_size} bytes): {target_json}")
        with open(target_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
        try:
            target_json.unlink()
        except:
            pass
        return data
    except subprocess.TimeoutExpired:
        raise Exception("pe.exe timeout (exceeded 3 minutes)")
    except Exception as e:
        raise Exception(f"Error running pe.exe analyzer: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Malware Detector CLI Scanner - Offline Analysis Tool")
    parser.add_argument("file_path", help="Path to the .exe target file to scan")
    parser.add_argument("-t", "--threshold", type=float, default=0.49, help="Malware classification threshold (default: 0.49)")
    parser.add_argument("-o", "--output", help="Optional path to save report as a JSON file")
    
    args = parser.parse_args()
    exe_path = Path(args.file_path)

    if not exe_path.exists():
        print(f"Error: File not found: {exe_path}")
        sys.exit(1)

    if not exe_path.suffix.lower() == '.exe':
        print("Error: Only .exe files are allowed for analysis.")
        sys.exit(1)
    print(f"Analyzing: {exe_path.name}")
    if not verify_pe_integrity(str(exe_path)):
        print("Error: File is not a valid PE executable (MIME type verification failed).")
        sys.exit(1)

    temp_dir = Path("temp_scan")
    temp_dir.mkdir(exist_ok=True)
    try:
        temp_exe = temp_dir / exe_path.name
        shutil.copy2(exe_path, temp_exe)

        if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
            print(f"Error: Missing dependency files.")
            print(f"    Expected model path: {MODEL_PATH}")
            print(f"    Expected features path: {FEATURES_PATH}")
            sys.exit(1)

        print("Loading Model & Features list...")
        model = joblib.load(MODEL_PATH)
        with open(FEATURES_PATH, 'r', encoding='utf-8') as f:
            selected_features = [line.strip() for line in f.readlines() if line.strip()]

        api_ngram_features = [
            feat[len(API_NGRAM_PREFIX):]
            for feat in selected_features
            if feat.startswith(API_NGRAM_PREFIX)
        ]

        print("Running PE Analyzer (Extracting static features)...")
        pe_data = run_pe_analyzer(str(temp_exe), temp_dir)

        print("Transforming extracted features...")
        feat_dict = extract_features_from_json(pe_data, selected_features, api_ngram_features)
        df = pd.DataFrame([feat_dict])
        for col in selected_features:
            if col not in df.columns:
                df[col] = 0.0

        df = df[selected_features].fillna(0)
        log_cols = ['api_seq_length', 'api_unique_calls', 'api_total_transitions', 'api_unique_transitions']
        for col in log_cols:
            if col in df.columns:
                df[col] = np.log1p(df[col].clip(lower=0))
        api_cols = [c for c in df.columns if c.startswith(API_NGRAM_PREFIX)]
        if api_cols:
            df[api_cols] = df[api_cols].astype(np.float64)
            tfidf = TfidfTransformer()
            df_api_tfidf = tfidf.fit_transform(df[api_cols])
            df[api_cols] = df_api_tfidf.toarray()

        print("Running LightGBM Predictor...")
        prob = float(model.predict(df)[0])
        is_malware = prob > args.threshold
        result_status = "MALWARE" if is_malware else "BENIGN (SAFE)"
        color_code = "\033[91m" if is_malware else "\033[92m"
        reset_code = "\033[0m"

        print("=" * 60)
        try:
            print(f"ANALYSIS RESULT: {color_code}{result_status}{reset_code}")
        except:
            print(f"ANALYSIS RESULT: {result_status}")
        print(f"Malware Probability: {prob * 100:.2f}%")
        print(f"Threshold Applied:   {args.threshold * 100:.2f}%")
        print("-" * 60)
        print(f"File Name:           {exe_path.name}")
        print(f"File Size (bytes):   {pe_data.get('size_bytes', 'N/A')}")
        print(f"Number of Sections:  {pe_data.get('num_sections', 'N/A')}")
        print(f"Imported Functions:  {pe_data.get('import_function_count', 'N/A')}")
        print(f"Scan Time:           {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        if args.output:
            report_data = {
                "file_name": exe_path.name,
                "is_malware": bool(is_malware),
                "malware_probability": round(prob, 4),
                "threshold_used": args.threshold,
                "file_metadata": {
                    "file_size_bytes": pe_data.get("size_bytes"),
                    "num_sections": pe_data.get("num_sections"),
                    "import_function_count": pe_data.get("import_function_count"),
                    "entropy": pe_data.get("entropy")
                },
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            with open(args.output, 'w', encoding='utf-8') as rf:
                json.dump(report_data, rf, indent=4, ensure_ascii=False)
            print(f"Scan report saved successfully to: {args.output}")

    except Exception as e:
        print(f"Error occurred: {str(e)}")
        sys.exit(1)
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()