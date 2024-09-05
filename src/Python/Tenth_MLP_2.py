import os
import ast
import numpy as np
import joblib
import importlib.util
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score


# 动态导入特征模式库文件
def load_patterns_from_file(file_path):
    spec = importlib.util.spec_from_file_location("patterns", file_path)
    patterns_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns_module)
    return patterns_module


# 导入特征模式库文件中的内容
patterns_file_path = 'D:/STUDY/Junior/JuniorUp/Project_hobbyhorse_2/patterns.py'  # 替换为你的patterns.py文件路径
patterns_module = load_patterns_from_file(patterns_file_path)

# 提取patterns字典，假设每个模式库都存储在文件中的独立字典中
patterns = {name: getattr(patterns_module, name) for name in dir(patterns_module) if not name.startswith('__')}


# 提取特征函数
def extract_features_from_code(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        code = file.read()

    tree = ast.parse(code)
    features = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                features.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            features.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    features.add(f"{node.func.value.id}.{node.func.attr}")
                elif isinstance(node.func.value, ast.Attribute):
                    features.add(f"{node.func.value.attr}.{node.func.attr}")
            elif isinstance(node.func, ast.Name):
                features.add(node.func.id)

    return features



# 向量化特征
def vectorize_features(patterns, sample):
    pattern_list = list(patterns.keys())
    feature_vector = np.zeros(len(pattern_list))

    for feature in sample:
        if feature in pattern_list:
            index = pattern_list.index(feature)
            feature_vector[index] = patterns[feature]

    return feature_vector


# 处理目录中的.py文件
def process_directory(directory, patterns):
    samples = []
    labels = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                features = extract_features_from_code(file_path)
                samples.append(features)

                # 根据恶意程度分配标签，恶意度大于2的认定为恶意（1），否则为非恶意（0）
                label = 1 if any(
                    patterns[category].get(f, 0) > 2 for category in patterns for f in features) else 0
                labels.append(label)

    X = np.array([vectorize_features(patterns, sample) for sample in samples])
    y = np.array(labels)

    return X, y


# 训练模型并保存
def train_and_save_models(directory):
    # 确保保存模型的文件夹存在
    model_dir = os.path.join(os.getcwd(), 'model')
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    for pattern_name, pattern in patterns.items():
        print(f"Training model for pattern: {pattern_name}")
        X, y = process_directory(directory, pattern)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

        model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5, class_weight='balanced')
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        print(f"Accuracy for {pattern_name}: {accuracy_score(y_test, y_pred)}")

        # 保存模型到 'model' 文件夹下
        model_save_path = os.path.join(model_dir, f'{pattern_name}_model.pkl')
        joblib.dump(model, model_save_path)
        print(f"Model for {pattern_name} saved to {model_save_path}")


# 示例执行
directory = 'C:/Users/XXX19/Desktop/directory_to_scan'  # 指定需要扫描的目录路径
train_and_save_models(directory)
