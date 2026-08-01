import json
import math
from pathlib import Path
from typing import Any

import numpy as np

try:
    from sandbox_feature_utils import merge_sandbox_features
except ImportError:  # pragma: no cover
    def merge_sandbox_features(data, sample_path=None):
        return data

API_NGRAM_PREFIX = "api_ng__"


def extract_features_from_json(data: Any, api_ngram_vocab=None, sample_path: str | None = None) -> dict:
    if isinstance(data, (str, Path)):
        with open(data, "r", encoding="utf-8") as handle:
            data = json.load(handle)

    if isinstance(data, dict):
        data = merge_sandbox_features(data, sample_path=sample_path)

    features = {}

    features["code_section_entropy"] = data.get("code_section_entropy", 0.0)
    features["relocation_entropy"] = data.get("relocation_entropy", 0.0)
    features["code_ratio"] = data.get("code_ratio", 0.0)

    sections = data.get("sections", [])
    features["num_sections"] = data.get("num_sections", len(sections))
    if sections:
        entropies = [s.get("entropy", 0) for s in sections]
        features["max_section_entropy"] = max(entropies) if entropies else 0.0
        features["min_section_entropy"] = min(entropies) if entropies else 0.0
        features["mean_section_entropy"] = float(np.mean(entropies))
        features["std_section_entropy"] = float(np.std(entropies)) if len(entropies) > 1 else 0.0
    else:
        features["max_section_entropy"] = 0.0
        features["min_section_entropy"] = 0.0
        features["mean_section_entropy"] = 0.0
        features["std_section_entropy"] = 0.0

    features["overlay_size_bytes"] = data.get("overlay_size_bytes", 0)
    features["resource_size"] = data.get("resource_size", 0)
    features["num_resources"] = data.get("num_resources", 0)
    features["resource_entropy"] = data.get("resource_entropy", 0.0)
    size_bytes = data.get("size_bytes", 1)
    features["overlay_ratio"] = features["overlay_size_bytes"] / max(1, size_bytes)
    features["resource_ratio"] = features["resource_size"] / max(1, size_bytes)

    features["resource_total"] = data.get("resource_total", 0)
    features["resource_icon_count"] = data.get("resource_icon_count", 0)
    features["resource_cursor_count"] = data.get("resource_cursor_count", 0)
    features["resource_bitmap_count"] = data.get("resource_bitmap_count", 0)
    features["resource_dialog_count"] = data.get("resource_dialog_count", 0)
    features["resource_menu_count"] = data.get("resource_menu_count", 0)
    features["resource_stringtable_count"] = data.get("resource_stringtable_count", 0)
    features["resource_accelerator_count"] = data.get("resource_accelerator_count", 0)
    features["resource_manifest_count"] = data.get("resource_manifest_count", 0)
    features["resource_version_count"] = data.get("resource_version_count", 0)
    features["resource_rcdata_count"] = data.get("resource_rcdata_count", 0)
    features["resource_other_count"] = data.get("resource_other_count", 0)
    features["resource_entropy_mean"] = data.get("resource_entropy_mean", 0.0)
    features["resource_entropy_max"] = data.get("resource_entropy_max", 0.0)
    features["resource_entropy_std"] = data.get("resource_entropy_std", 0.0)

    manifest_present = int(bool(data.get("manifest_present", False)))
    manifest_size = data.get("manifest_size", 0)
    features["manifest_present"] = manifest_present
    features["manifest_size_log"] = float(np.log1p(manifest_size)) if manifest_present else 0.0
    features["manifest_entropy"] = data.get("manifest_entropy", 0.0)

    if "manifest_execution_level" in data:
        features["manifest_execution_level"] = data["manifest_execution_level"]
    elif data.get("manifest_requested_admin"):
        features["manifest_execution_level"] = 3
    else:
        features["manifest_execution_level"] = 0

    features["manifest_uiaccess"] = int(bool(data.get("manifest_uiaccess", False)))
    features["manifest_auto_elevate"] = int(bool(data.get("manifest_auto_elevate", False)))
    features["manifest_requested_privilege"] = data.get("manifest_requested_privilege", 0)
    features["manifest_has_dpi"] = int(bool(data.get("manifest_has_dpi", False)))
    features["manifest_has_com"] = int(bool(data.get("manifest_has_com", False)))
    features["manifest_has_dependencies"] = int(bool(data.get("manifest_has_dependencies", False)))
    features["manifest_dependency_count"] = data.get("manifest_dependency_count", 0)

    features["certificate_present"] = int(bool(data.get("certificate_present", False)))
    if "certificate_count" in data:
        features["certificate_count"] = data["certificate_count"]
    elif features["certificate_present"] or data.get("certificate_size", 0) > 0:
        features["certificate_count"] = 1
    else:
        features["certificate_count"] = 0

    features["has_version_info"] = int(bool(data.get("has_version_info", False)))
    features["version_company_name_length"] = data.get("version_company_name_length", 0)
    features["version_product_name_length"] = data.get("version_product_name_length", 0)
    features["version_description_length"] = data.get("version_description_length", 0)
    features["version_original_filename_len"] = data.get("version_original_filename_len", 0)
    features["version_product_version_len"] = data.get("version_product_version_len", 0)

    features["rich_header_present"] = int(bool(data.get("rich_header_present", False)))
    features["rich_header_entries"] = data.get("rich_header_entries", 0)
    features["rich_has_vs2015"] = int(bool(data.get("rich_has_vs2015", False)))
    features["rich_has_vs2017"] = int(bool(data.get("rich_has_vs2017", False)))
    features["rich_has_vs2019"] = int(bool(data.get("rich_has_vs2019", False)))
    features["rich_has_vs2022"] = int(bool(data.get("rich_has_vs2022", False)))
    features["rich_has_masm"] = int(bool(data.get("rich_has_masm", False)))
    features["rich_has_cvtres"] = int(bool(data.get("rich_has_cvtres", False)))

    features["import_function_count"] = data.get("import_function_count", 0)
    features["import_rva"] = data.get("import_rva", 0)
    features["import_size"] = data.get("import_size", 0)
    features["suspicious_api_count"] = data.get("suspicious_api_count", 0)
    features["suspicious_api_ratio"] = data.get("suspicious_api_ratio", 0.0)
    features["has_imphash"] = int(bool(data.get("imphash", "")))

    byte_hist = data.get("byte_histogram", [])
    for i in range(256):
        features[f"byte_hist_{i}"] = float(byte_hist[i]) if i < len(byte_hist) else 0.0
    features["zero_byte_ratio"] = data.get("zero_byte_ratio", 0.0)

    entropy_hist = data.get("byte_entropy_histogram", [])
    for i in range(16):
        features[f"byte_entropy_{i}"] = float(entropy_hist[i]) if i < len(entropy_hist) else 0.0

    entropy_mat = data.get("byte_entropy_matrix", [])
    for i in range(256):
        features[f"byte_entropy_mat_{i}"] = float(entropy_mat[i]) if i < len(entropy_mat) else 0.0

    features["windowed_entropy_mean"] = data.get("windowed_entropy_mean", 0.0)
    features["windowed_entropy_max"] = data.get("windowed_entropy_max", 0.0)
    features["windowed_entropy_min"] = data.get("windowed_entropy_min", 0.0)
    features["windowed_entropy_std"] = data.get("windowed_entropy_std", 0.0)

    markov_mat = data.get("nibble_transition_matrix", [])
    for i in range(256):
        features[f"markov_trans_{i}"] = float(markov_mat[i]) if i < len(markov_mat) else 0.0
    features["markov_matrix_entropy"] = data.get("markov_matrix_entropy", 0.0)

    features["export_count"] = data.get("export_count", 0)
    features["export_named_count"] = data.get("export_named_count", 0)
    features["export_ordinal_only_count"] = data.get("export_ordinal_only_count", 0)
    features["export_name_entropy_mean"] = data.get("export_name_entropy_mean", 0.0)
    features["export_name_entropy_max"] = data.get("export_name_entropy_max", 0.0)
    features["export_name_entropy_min"] = data.get("export_name_entropy_min", 0.0)
    features["export_name_entropy_std"] = data.get("export_name_entropy_std", 0.0)
    features["has_export_table"] = int(features["export_count"] > 0)
    features["has_export_name_hash"] = int(bool(data.get("export_name_hash", "")))

    api_flags = [
        "has_VirtualAlloc", "has_VirtualProtect", "has_WriteProcessMemory",
        "has_ReadProcessMemory", "has_CreateRemoteThread", "has_NtMapViewOfSection",
        "has_QueueUserAPC", "has_WinExec", "has_ShellExecute", "has_LoadLibrary",
        "has_GetProcAddress", "has_InternetOpen", "has_WinHttpOpen",
        "has_CryptEncrypt", "has_BCryptEncrypt"
    ]
    for flag in api_flags:
        features[flag] = int(bool(data.get(flag, False)))

    features["e_lfanew"] = data.get("e_lfanew", 0)
    features["entry_point_rva"] = data.get("entry_point_rva", 0)
    features["file_alignment"] = data.get("file_alignment", 0)
    features["image_base"] = data.get("image_base", 0)
    features["machine"] = data.get("machine", 0)
    features["magic"] = data.get("magic", 0)

    bool_flags = [
        "alignment_weird", "aslr_enabled", "cfg_enabled", "checksum_zero",
        "digital_signature_valid", "e_lfanew_not_aligned", "e_lfanew_too_large",
        "has_debug", "has_http_post_exfil", "has_luhn_or_cc_validation",
        "has_mutex_persistence", "has_signature", "has_tls", "has_track_pattern_strings",
        "is_console", "is_dll", "is_fsg", "is_gui", "is_invalid_dos", "is_upx",
        "is_wwpack", "likely_pos_scraper", "no_imports", "nx_enabled",
        "has_memory_scraping_apis"
    ]
    for flag in bool_flags:
        features[flag] = int(bool(data.get(flag, False)))

    for key, value in data.items():
        if not key.startswith("sandbox_"):
            continue
        if isinstance(value, bool):
            features[key] = int(value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            features[key] = value

    ngrams = data.get("top_suspicious_ngrams", [])
    features["top_suspicious_ngrams_count"] = len(ngrams)
    features["suspicious_ngrams_high_count"] = sum(1 for n in ngrams if n.get("count", 0) > 100)
    features["suspicious_ngrams_total_weight"] = sum(n.get("weight", 0.0) for n in ngrams)

    opcode_info = data.get("opcode_ngrams", {})
    features["opcode_ngrams_total"] = opcode_info.get("total_ngrams_found", len(opcode_info.get("opcode_ngrams", [])))
    features["approx_instructions_analyzed"] = opcode_info.get("approx_instructions_analyzed", 0)

    semantic_histogram = data.get("semantic_group_histogram", {})
    for group in ("DATA_XFER", "ARITHMETIC", "LOGIC", "CMP", "CONTROL_FLOW",
                  "SIMD", "CRYPTO", "STRING_OP", "OTHER"):
        features[f"opcode_semantic_{group.lower()}"] = semantic_histogram.get(group, 0)

    opcode_tfidf = data.get("opcode_tfidf", [])
    tfidf_scores = [item.get("score", 0.0) for item in opcode_tfidf]
    features["opcode_tfidf_term_count"] = len(tfidf_scores)
    features["opcode_tfidf_score_sum"] = sum(tfidf_scores)
    features["opcode_tfidf_score_max"] = max(tfidf_scores, default=0.0)
    features["opcode_tfidf_score_mean"] = float(np.mean(tfidf_scores)) if tfidf_scores else 0.0

    cfg_info = data.get("CFG", data.get("cfg", {}))
    features["cfg_build_success"] = int(bool(cfg_info.get("build_success", False)))
    features["cfg_num_basic_blocks"] = cfg_info.get("num_basic_blocks", 0)
    features["cfg_num_edges"] = cfg_info.get("num_edges", 0)
    features["cfg_cyclomatic_complexity"] = cfg_info.get("cyclomatic_complexity", 0)
    features["cfg_average_out_degree"] = cfg_info.get("average_out_degree", 0.0)
    features["cfg_average_in_degree"] = cfg_info.get("average_in_degree", 0.0)
    features["cfg_max_out_degree"] = cfg_info.get("max_out_degree", 0)
    features["cfg_max_call_depth"] = cfg_info.get("max_call_depth", 0)
    features["cfg_recursive_function_count"] = cfg_info.get("recursive_function_count", 0)
    features["cfg_back_edge_ratio"] = cfg_info.get("back_edge_ratio", 0.0)
    features["cfg_jump_density"] = cfg_info.get("jump_density", 0.0)
    features["cfg_branch_density"] = cfg_info.get("branch_density", 0.0)
    features["cfg_indirect_control_flow"] = cfg_info.get("indirect_control_flow", 0)
    features["cfg_indirect_call_ratio"] = cfg_info.get("indirect_call_ratio", 0.0)
    features["cfg_call_count"] = cfg_info.get("call_count", 0)
    features["cfg_avg_block_size"] = cfg_info.get("avg_block_size", 0.0)
    features["cfg_has_loops"] = int(bool(cfg_info.get("has_loops", False)))
    features["cfg_unreachable_blocks"] = cfg_info.get("unreachable_blocks", 0)
    features["tls_callback_count"] = data.get("tls_callback_count", 0)

    str_info = data.get("string_analysis", {})
    features["total_strings"] = str_info.get("total_strings_found", 0)
    interesting = str_info.get("interesting_strings", [])
    features["interesting_strings_count"] = len(interesting)
    features["interesting_strings_ratio"] = len(interesting) / max(1, features["total_strings"])
    string_stats = str_info.get("string_stats", {})
    features["ascii_string_count"] = string_stats.get("ascii_count", 0)
    features["unicode_string_count"] = string_stats.get("unicode_count", 0)
    features["string_avg_length"] = string_stats.get("avg_length", 0.0)
    features["string_median_length"] = string_stats.get("median_length", 0.0)
    features["string_avg_entropy"] = string_stats.get("avg_entropy", 0.0)
    features["string_printable_ratio"] = string_stats.get("printable_ratio", 0.0)
    features["string_unicode_ratio"] = string_stats.get("unicode_ratio", 0.0)

    api_ng: dict = data.get("api_ngrams", {})
    for ng in api_ngram_vocab or []:
        col = API_NGRAM_PREFIX + ng
        features[col] = api_ng.get(ng, 0)

    seq = data.get("api_sequence", [])
    seq_len = data.get("api_seq_length", len(seq))
    if seq_len is None or seq_len < 0:
        seq_len = len(seq)
    features["api_seq_length"] = int(seq_len)

    unique_calls = data.get("api_unique_calls", len(set(seq)) if seq else 0)
    if unique_calls is None or unique_calls < 0:
        unique_calls = len(set(seq)) if seq else 0
    features["api_unique_calls"] = int(unique_calls)

    if "api_repeat_ratio" in data and data["api_repeat_ratio"] is not None:
        repeat_ratio = data["api_repeat_ratio"]
        if not np.isfinite(repeat_ratio):
            repeat_ratio = 0.0
    else:
        repeat_ratio = (1.0 - unique_calls / max(1, seq_len) if seq_len > 0 else 0.0)
    features["api_repeat_ratio"] = float(repeat_ratio)
    features["api_sequence_present"] = int(bool(seq))

    counts = np.array(list(api_ng.values())) if api_ng else np.array([])
    if len(counts) > 0 and counts.sum() > 0:
        probs = counts / counts.sum()
        features["api_entropy"] = float(-np.sum(probs * np.log2(probs + 1e-12)))
    else:
        features["api_entropy"] = 0.0

    transitions = [(seq[i], seq[i + 1]) for i in range(len(seq) - 1)]
    features["api_total_transitions"] = len(transitions)
    features["api_unique_transitions"] = len(set(transitions))
    out_deg = {}
    loop_cnt = 0
    for src, dst in transitions:
        out_deg.setdefault(src, set()).add(dst)
        if src == dst:
            loop_cnt += 1
    features["api_avg_out_degree"] = float(np.mean([len(t) for t in out_deg.values()])) if out_deg else 0.0
    features["api_loop_ratio"] = loop_cnt / max(len(transitions), 1)
    features["api_repeated_transition_ratio"] = (len(transitions) - len(set(transitions))) / max(len(transitions), 1)

    return features
