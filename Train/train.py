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
    
    sections = data.get('sections', [])
    features['num_sections'] = len(sections)
    if sections:
        entropies = [s.get('entropy', 0) for s in sections]
        features['max_section_entropy'] = max(entropies) if entropies else 0.0
        features['min_section_entropy'] = min(entropies) if entropies else 0.0
        features['mean_section_entropy'] = np.mean(entropies)
        features['std_section_entropy'] = np.std(entropies) if len(entropies) > 1 else 0.0
    
    features['code_ratio'] = data.get('code_ratio', 0.0)
    features['overlay_size_bytes'] = data.get('overlay_size_bytes', 0)
    features['resource_size'] = data.get('resource_size', 0)
    features['overlay_ratio'] = features['overlay_size_bytes'] / max(1, data.get('size_bytes', 1))

    features['import_function_count'] = data.get('import_function_count', 0)
    features['suspicious_api_count'] = data.get('suspicious_api_count', 0)
    features['suspicious_api_ratio'] = data.get('suspicious_api_ratio', 0.0)

    features['top_suspicious_ngrams_count'] = len(data.get('top_suspicious_ngrams', []))
    ngrams = data.get('top_suspicious_ngrams', [])
    if ngrams:
        features['suspicious_ngrams_high_count'] = sum(1 for n in ngrams if n.get('count', 0) > 100)
        features['suspicious_ngrams_total_weight'] = sum(n.get('weight', 0) for n in ngrams)
    
    features['opcode_ngrams_total'] = data.get('opcode_ngrams', {}).get('total_ngrams_found', 0)

    str_info = data.get('string_analysis', {})
    features['total_strings'] = str_info.get('total_strings_found', 0)
    interesting = str_info.get('interesting_strings', [])
    features['interesting_strings_count'] = len(interesting)
    features['interesting_strings_ratio'] = len(interesting) / max(1, features['total_strings'])

    features['has_memory_scraping_apis'] = int(data.get('has_memory_scraping_apis', False))
    features['has_tls'] = int(data.get('has_tls', False))
    features['is_gui'] = int(data.get('is_gui', False))
    features['is_dll'] = int(data.get('is_dll', False))

    return features

def load_dataset():
    data_list = []
    labels = []
   
    print("Đang đọc malware samples...")
    for filename in tqdm(os.listdir(DATA_MALWARE)):
        if filename.endswith('.json'):
            try:
                feat = extract_features_from_json(os.path.join(DATA_MALWARE, filename))
                data_list.append(feat)
                labels.append(1)
            except:
                pass
   
    print("Đang đọc benign samples...")
    for filename in tqdm(os.listdir(DATA_BENIGN)):
        if filename.endswith('.json'):
            try:
                feat = extract_features_from_json(os.path.join(DATA_BENIGN, filename))
                data_list.append(feat)
                labels.append(0)
            except:
                pass
   
    df = pd.DataFrame(data_list)
    print(f"Loaded: {len(df)} samples ({sum(labels)} malware, {len(df)-sum(labels)} benign)")
    return df, np.array(labels)


def main():
    X, y = load_dataset()
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
        'num_leaves': 32,
        'learning_rate': 0.03,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'min_data_in_leaf': 30,
        'lambda_l1': 5.0,
        'lambda_l2': 8.0,
        'scale_pos_weight': pos_weight,
        'verbose': -1,
        'seed': RANDOM_STATE,
    }

    print(f"\nTraining LightGBM - Precision oriented...")
    print(f"scale_pos_weight = {pos_weight:.3f} | Features: {X.shape[1]}")

    model = lgb.train(
        params,
        train_data,
        num_boost_round=10000,
        valid_sets=[val_data],
        callbacks=[lgb.early_stopping(200), lgb.log_evaluation(500)]
    )

    y_pred_prob = model.predict(X_test)

    precision, recall, thresholds = precision_recall_curve(y_test, y_pred_prob)
    valid_idx = np.where(precision >= 0.93)[0]
    
    if len(valid_idx) > 0:
        best_idx = valid_idx[np.argmax(recall[valid_idx])]
    else:
        f2_scores = (5 * precision * recall) / (4 * precision + recall + 1e-8)
        best_idx = np.argmax(f2_scores)
    
    optimal_threshold = thresholds[best_idx] if best_idx < len(thresholds) else 0.65

    print(f"\nOptimal threshold: {optimal_threshold:.4f}")
    print(f"Precision: {precision[best_idx]:.4f} | Recall: {recall[best_idx]:.4f}")

    y_pred = (y_pred_prob > optimal_threshold).astype(int)

    print("\n=== EVALUATION ===")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware'], digits=4))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importance(importance_type='gain')
    }).sort_values('importance', ascending=False)

    print("\n=== TOP 15 FEATURES ===")
    print(importance.head(15))

    joblib.dump(model, MODEL_PATH)
    with open(FEATURES_PATH, 'w') as f:
        f.write('\n'.join(X.columns.tolist()))

    print(f"\nModel lưu tại: {MODEL_PATH}")
    print("Khuyến nghị threshold thực tế: 0.65 ~ 0.85")


if __name__ == "__main__":
    main()