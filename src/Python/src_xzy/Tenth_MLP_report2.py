import os
import ast
import numpy as np
import joblib
import importlib.util


# 动态导入特征模式库文件
def load_patterns_from_file(file_path):
    spec = importlib.util.spec_from_file_location("patterns", file_path)
    patterns_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns_module)
    return patterns_module


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


# 生成整合报告
def generate_integrated_report(directory, patterns_file_path, model_dir):
    patterns_module = load_patterns_from_file(patterns_file_path)
    patterns = {name: getattr(patterns_module, name) for name in dir(patterns_module) if not name.startswith('__')}

    # 整合的报告数据结构
    report = {}

    # 先遍历每个特征模式库，并加载对应的模型
    for pattern_name, pattern in patterns.items():
        model_file = os.path.join(model_dir, f'{pattern_name}_model.pkl')
        if not os.path.exists(model_file):
            print(f"Model for {pattern_name} not found. Skipping...")
            continue

        print(f"Generating report for pattern: {pattern_name}")
        model = joblib.load(model_file)
        report[pattern_name] = {"count": 0, "predictions": [], "probabilities": []}

        # 遍历目录中的文件，并针对每个特征模式库进行预测
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)

                    # 提取文件的特征
                    features = extract_features_from_code(file_path)
                    X_sample = vectorize_features(pattern, features).reshape(1, -1)

                    # 进行预测并保存结果
                    prediction = model.predict(X_sample)[0]

                    # 获取概率预测值
                    probabilities = model.predict_proba(X_sample)[0]

                    # 如果只有一个类的概率（可能是单类分类器的结果）
                    if len(probabilities) == 1:
                        # 假设为单类分类，则概率为1类（我们手动创建二元概率）
                        prediction_proba = [1 - probabilities[0], probabilities[0]]
                    else:
                        prediction_proba = probabilities

                    report[pattern_name]["count"] += 1
                    report[pattern_name]["predictions"].append(prediction)
                    report[pattern_name]["probabilities"].append(prediction_proba)

    # 生成最终报告
    with open("integrated_report.txt", "w", encoding="utf-8") as report_file:
        for pattern_name, data in report.items():
            positive_count = sum(1 for pred in data["predictions"] if pred == 1)

            # 检查是否有二元概率，否则设为0
            if data["probabilities"] and len(data["probabilities"][0]) > 1:
                average_probability = np.mean([prob[1] for prob in data["probabilities"]])
            else:
                average_probability = 0

            # 写入报告
            report_file.write(f"{pattern_name}特征-机器学习模型检测报告:\n")
            report_file.write(f"预测结果: {'符合该模式特征' if positive_count > 0 else '不符合该模式特征'}\n")
            report_file.write(f"预测概率: {average_probability:.4f}\n\n")

    print("整合报告已生成并保存在 integrated_report.txt 文件中.")


# 示例执行
directory_to_predict = 'C:/Users/XXX19/Desktop/directory_to_scan'  # 指定需要生成报告的目录路径
patterns_file_path = 'D:/STUDY/Junior/JuniorUp/Project_hobbyhorse_2/patterns.py'  # 替换为你的patterns.py文件路径
model_dir = os.path.join(os.getcwd(), 'model')  # 指定存储模型的目录路径

generate_integrated_report(directory_to_predict, patterns_file_path, model_dir)
