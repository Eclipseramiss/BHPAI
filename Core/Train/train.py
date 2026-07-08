import os
import json
import pandas as pd
import numpy as np
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
import lightgbm as lgb
import joblib
import warnings

warnings.filterwarnings('ignore')

DATA_MALWARE = "dataset/malware"
DATA_BENIGN = "dataset/benign"

MODEL_PATH = "malware_detector_lgb.pkl"
FEATURES_PATH = "selected_features.txt"

TEST_SIZE = 0.2
VAL_SIZE = 0.15
RANDOM_STATE = 42

def extract_features_from_json(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
   
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
        features['mean_section_entropy'] = np.mean(entropies)
        features['std_section_entropy'] = np.std(entropies) if len(entropies) > 1 else 0.0
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

def load_dataset():
    data_list = []
    labels = []
   
    print("Gathering malware samples...")
    for filename in tqdm(os.listdir(DATA_MALWARE)):
        if filename.endswith('.json'):
            try:
                feat = extract_features_from_json(os.path.join(DATA_MALWARE, filename))
                data_list.append(feat)
                labels.append(1)
            except Exception as e:
                pass
   
    print("Gathering benign samples...")
    for filename in tqdm(os.listdir(DATA_BENIGN)):
        if filename.endswith('.json'):
            try:
                feat = extract_features_from_json(os.path.join(DATA_BENIGN, filename))
                data_list.append(feat)
                labels.append(0)
            except Exception as e:
                pass
   
    df = pd.DataFrame(data_list)
    print(f"Loaded: {len(df)} samples ({sum(labels)} malware, {len(df)-sum(labels)} benign)")
    return df, np.array(labels)


def main():
    X, y = load_dataset()
    if X.empty:
        print("No valid data found for training!")
        return
        
    X = X.fillna(0)
    
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=(VAL_SIZE + TEST_SIZE), random_state=RANDOM_STATE, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=TEST_SIZE / (VAL_SIZE + TEST_SIZE),
        random_state=RANDOM_STATE, stratify=y_temp
    )

    pos_weight = (len(y_train) - sum(y_train)) / max(1, sum(y_train)) * 0.8

    train_data = lgb.Dataset(X_train, label=y_train)
    val_data   = lgb.Dataset(X_val, label=y_val, reference=train_data)

    params = {
        'objective': 'binary',
        'metric': 'binary_logloss,auc',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.03,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'min_data_in_leaf': 20,
        'lambda_l1': 1.0,
        'lambda_l2': 2.0,
        'scale_pos_weight': pos_weight,
        'verbose': -1,
        'seed': RANDOM_STATE,
    }

    print(f"\nTraining LightGBM - Precision oriented...")
    print(f"scale_pos_weight = {pos_weight:.3f} | Total Features: {X.shape[1]}")

    model = lgb.train(
        params,
        train_data,
        num_boost_round=5000,
        valid_sets=[val_data],
        callbacks=[lgb.early_stopping(150), lgb.log_evaluation(200)]
    )

    y_pred_prob = model.predict(X_test)

    precision, recall, thresholds = precision_recall_curve(y_test, y_pred_prob)
    valid_idx = np.where(precision >= 0.95)[0]
    
    if len(valid_idx) > 0:
        best_idx = valid_idx[np.argmax(recall[valid_idx])]
    else:
        f2_scores = (5 * precision * recall) / (4 * precision + recall + 1e-8)
        best_idx = np.argmax(f2_scores)
    
    optimal_threshold = thresholds[best_idx] if best_idx < len(thresholds) else 0.75

    print(f"\nOptimal threshold: {optimal_threshold:.4f}")
    print(f"Precision at this threshold: {precision[best_idx]:.4f} | Recall: {recall[best_idx]:.4f}")

    y_pred = (y_pred_prob > optimal_threshold).astype(int)

    print("\n=== EVALUATION ===")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware'], digits=4))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importance(importance_type='gain')
    }).sort_values('importance', ascending=False)

    print(importance.head(15))

    joblib.dump(model, MODEL_PATH)
    with open(FEATURES_PATH, 'w') as f:
        f.write('\n'.join(X.columns.tolist()))

    print(f"\nModel saved at: {MODEL_PATH}")

if __name__ == "__main__":
    main()