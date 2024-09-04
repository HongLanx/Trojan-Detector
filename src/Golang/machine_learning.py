import os
import pickle

from sklearn.ensemble import RandomForestClassifier

import ssa_patterns_fin


# 训练并将模型保存到本地指定路径
def train_and_save_model(X_train, y_train, model_path):
    # 创建随机森林模型
    model = RandomForestClassifier(n_estimators=500)
    model.fit(X_train, y_train)

    # 将模型存储到本地
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"模型已保存到 {model_path}")


# 输入模式特征库和模型路径，对该模式库进行学习并保存模型到本地
def save_model(pattern, model_path):
    # 合并调用和字符串特征，去重
    all_features = list(set(list(pattern['calls'].keys()) + list(pattern['strings'].keys())))

    # 生成输入数据和标签
    X_train = []
    y_train = []
    for feature_set, feature_scores in pattern.items():
        for feature, score in feature_scores.items():
            vector = [1 if feature == fn else 0 for fn in all_features]
            X_train.append(vector)
            y_train.append(1 if score > 5 else 0)  # 恶意度大于5认为是恶意的

    train_and_save_model(X_train, y_train, model_path)


# 输入模型路径，加载模型
def load_model(model_path):
    # 从本地加载模型
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    return model


# 输入模型路径，项目信息JSON文件，模式库，返回模型检测报告
def predict_with_model(model_path, project_info, pattern):
    report = {
        "report_importance": "",
        "report_probability": "",
        "probability": 0
    }
    # 加载模型
    model = load_model(model_path)
    all_features = list(set(list(pattern['calls'].keys()) + list(pattern['strings'].keys())))

    # 示例文件特征向量化
    # 创建了一个包括项目信息内所有特征（调用和字符串）的列表，并为每个特征在这个列表中的位置创建了一个向量。
    # 如果某个特征在样本中出现，则其对应的向量位置将被标记为1，否则为0。这种方法被称为“one - hot编码”
    X_test = []
    test_vector = [0] * len(all_features)

    project_features = list(set(list(project_info['calls'].keys()) + list(project_info['strings'].keys())))

    for feature in project_features:
        if feature in all_features:
            test_vector[all_features.index(feature)] = 1

    X_test.append(test_vector)

    # 使用加载的模型进行预测
    predictions = model.predict(X_test)
    prediction_probabilities = model.predict_proba(X_test)

    # 输出预测结果和概率
    report["report_probability"] = f"预测结果：{'符合该模式特征' if predictions[0] == 1 else '不符合该模式特征'}\n"
    report["report_probability"] += f"预测概率：{prediction_probabilities[0][1]:.4f}\n"  # 输出被预测为符合模式特征的概率
    report["probability"] = prediction_probabilities[0][1]

    # 输出特征重要性
    feature_importances = model.feature_importances_
    important_features = sorted(zip(all_features, feature_importances), key=lambda x: x[1], reverse=True)
    report["report_importance"] += "模式特征重要性：\n"
    for feature, importance in important_features:
        report["report_importance"] += f"{feature}: {importance:.4f}\n"

    return report

# # 训练模型并保存示例：内核攻击特征模式库
# model_path = os.path.join(os.getcwd(),r"model/kernel_model.pkl")
# save_model(ssa_patterns_fin.kernel_patterns, model_path)
# print(predict_with_model(model_path,a,ssa_patterns_fin.kernel_patterns))
