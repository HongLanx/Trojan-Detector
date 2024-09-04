import os
import ast
import numpy as np
import joblib  # 用于保存和加载模型
import importlib.util

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score


# 动态导入特征模式库文件
def load_patterns_from_file(file_path):
    spec = importlib.util.spec_from_file_location("patterns", file_path)
    patterns_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns_module)
    return patterns_module


# 导入特征模式库文件中的内容
patterns_file_path = 'D:/STUDY/Junior/JuniorUp/Project_hobbyhorse_2/patterns.py'  # 替换为上传的文件路径
patterns_module = load_patterns_from_file(patterns_file_path)

# 提取patterns字典，假设每个模式库都存储在文件中的独立字典中
patterns = {name: getattr(patterns_module, name) for name in dir(patterns_module) if not name.startswith('__')}


# 2. 提取特征的函数
def extract_features_from_code(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        code = file.read()

    # 使用AST解析Python代码
    tree = ast.parse(code)

    # 提取特征
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


# 3. 将特征向量化的函数
def vectorize_features(all_patterns, sample):
    # 提取所有特征模式中的所有特征名
    pattern_list = []
    for feature_patterns in all_patterns.values():
        pattern_list.extend(list(feature_patterns.keys()))

    # 初始化特征向量
    feature_vector = np.zeros(len(pattern_list))

    for feature in sample:
        if feature in pattern_list:
            index = pattern_list.index(feature)
            # 根据各模式中的恶意程度值进行赋值
            for category, feature_patterns in all_patterns.items():
                if feature in feature_patterns:
                    feature_vector[index] = feature_patterns[feature]

    return feature_vector


# 4. 处理整个目录下的所有 .py 文件（包括子目录）
def process_directory(directory, all_patterns):
    samples = []
    labels = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                features = extract_features_from_code(file_path)
                samples.append(features)

                # 手动标记：将Project_feast中的文件标记为非恶意（0），其他文件标记为恶意（1）
                if "Project_feast" in root:  # 非恶意样本
                    label = 0
                elif: ""
                else:  # 恶意样本
                    label = 1
                labels.append(label)

    # 向量化所有样本
    X = np.array([vectorize_features(all_patterns, sample) for sample in samples])
    y = np.array(labels)

    return X, y


# 5. 训练模型并将其保存到本地
def train_and_save_model(directory, model_save_path='random_forest_model_3.pkl'):
    X, y = process_directory(directory, patterns)

    # 数据分割为训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

    # # 训练随机森林模型
    # model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    # 使用交叉验证评估模型，并使用正则化参数和类权重平衡策略
    model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5, class_weight='balanced')
    scores = cross_val_score(model, X, y, cv=5)  # 5折交叉验证

    print("Cross-Validation Scores:", scores)
    print("Mean Cross-Validation Score:", np.mean(scores))
    model.fit(X_train, y_train)

    # model.fit(X_train, y_train)


    # 对测试集进行预测
    y_pred = model.predict(X_test)

    # 输出训练结果
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))

    # 保存模型
    joblib.dump(model, model_save_path)
    print(f"模型已保存至 {model_save_path}")

    return model


# 6. 封装预测过程，处理整个目录中的所有.py文件，并输出预测的参数信息
def predict_with_model(model, directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)

                # 提取文件的特征
                features = extract_features_from_code(file_path)
                X_sample = vectorize_features(patterns, features).reshape(1, -1)

                # 预测并输出相关信息
                prediction = model.predict(X_sample)
                prediction_proba = model.predict_proba(X_sample)

                # print(f"文件: {file_path}")
                # print(f"预测结果: {'恶意' if prediction[0] == 1 else '非恶意'}")
                # print(f"预测概率: {prediction_proba}\n")


# 示例执行：训练模型并保存
directory = 'C:/Users/XXX19/Desktop/directory_to_scan'  # 指定你的目录路径
model_save_path = 'random_forest_model_3.pkl'

# 训练并保存模型
model = train_and_save_model(directory, model_save_path)

# 预测示例
# 从本地加载模型
loaded_model = joblib.load(model_save_path)
directory_to_predict = 'C:/Users/XXX19/Desktop/directory_to_scan'  # 指定需要预测的目录路径

# 对目录下的所有.py文件进行预测
predict_with_model(loaded_model, directory_to_predict)
