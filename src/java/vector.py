import os
import javalang  # 用于解析 Java 代码
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import datetime

from src.java.feature import encryption_patterns, botnet_patterns, penetration_patterns, obfuscation_patterns, phishing_patterns, Keyboard_patterns, backdoor_patterns, ransomware_patterns, Trojan_virus_patterns, rootkit_patterns, Defense_Bypass_patterns, antivirus_patterns, adware_patterns, hackingtool_patterns

# 定义所有的特征库在一个字典中
all_patterns = {
    "加密": encryption_patterns,
    "僵尸网络": botnet_patterns,
    "渗透测试": penetration_patterns,
    "混淆": obfuscation_patterns,
    "网络钓鱼": phishing_patterns,
    "键盘记录器": Keyboard_patterns,
    "后门": backdoor_patterns,
    "勒索软件": ransomware_patterns,  # 新增
    "木马病毒": Trojan_virus_patterns,  # 新增
    "Rootkit": rootkit_patterns,  # 新增
    "杀毒软件": antivirus_patterns,  # 新增
    "广告软件": adware_patterns,  # 新增
    "黑客工具": hackingtool_patterns,  # 新增
}

# 展平特征库并创建类别标签
flattened_trojan_features = []
categories = []

for category, features in all_patterns.items():
    flattened_trojan_features.extend(features)
    categories.extend([category] * len(features))  # 为每个特征关联对应的类别

# 定义一个接收文件路径的函数，包含整个检测流程
def detect_malicious_code(directory_path):
    """
    根据传入的Java文件夹路径，使用随机森林进行恶意代码检测，并生成中文报告。
    :param directory_path: 包含Java文件的文件夹路径
    """

    # 1. 选择包含Java源代码的文件路径
    def get_java_files_from_directory(directory_path):
        java_files = []  # 用于存储文件路径
        java_code_samples = []  # 用于存储代码内容
        # 遍历文件夹及其子文件夹
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith(".java"):  # 找到所有的Java文件
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            java_code = f.read()  # 读取文件内容
                            java_files.append(file_path)  # 保存文件路径
                            java_code_samples.append(java_code)  # 保存Java代码内容
                    except Exception as e:
                        print(f"读取文件 {file_path} 时出错: {str(e)}")
        return java_files, java_code_samples

    # 获取Java文件及其代码
    java_files, java_code_samples = get_java_files_from_directory(directory_path)

    if len(java_files) == 0:
        print("未找到任何Java文件。")
        return

    # 2. 将 Java 代码和特征库向量化 (TF-IDF)
    vectorizer = TfidfVectorizer()
    vectors = vectorizer.fit_transform(java_code_samples + flattened_trojan_features)

    # 3. 准备训练数据
    X = vectors.toarray()  # 将稀疏矩阵转换为普通数组
    y = [0] * len(java_code_samples) + [1] * len(flattened_trojan_features)  # Java文件为0，恶意特征为1

    # 4. 拆分训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # 5. 训练随机森林模型
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 6. 预测并输出结果
    y_pred = model.predict(X_test)

    # 打印分类报告
    classification_report_str = classification_report(y_test, y_pred, zero_division=1)  # 避免除0错误

    # 输出准确率
    accuracy = accuracy_score(y_test, y_pred)
    accuracy_str = f"模型准确率: {accuracy * 100:.2f}%\n"

    # 生成检测报告
    report_file_name = f"检测报告_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_path = os.path.join(directory_path, report_file_name)

    with open(report_path, 'w', encoding='utf-8') as report_file:
        report_file.write("分类报告:\n")
        report_file.write(classification_report_str)
        report_file.write("\n")
        report_file.write(accuracy_str)

        # 检测每个Java文件并写入报告
        for i, (file_path, java_code) in enumerate(zip(java_files, java_code_samples)):
            report_file.write(f"\n检测文件 {i + 1}: {file_path}\n")

            # 将Java文件内容向量化
            new_vectors = vectorizer.transform([java_code])
            new_X = new_vectors.toarray()

            # 使用训练好的模型预测
            new_y_pred = model.predict(new_X)

            # 输出预测结果（0 或 1）
            detection_result_str = f"新Java代码检测结果: {new_y_pred}\n"
            report_file.write(detection_result_str)

            # 使用概率预测获取相似度
            probabilities = model.predict_proba(new_X)
            malicious_probability = probabilities[0][1]  # 第二列是恶意代码的概率
            malicious_probability_str = f"恶意代码相似度: {malicious_probability * 100:.2f}%\n"
            report_file.write(malicious_probability_str)

            # 输出预测结果
            if new_y_pred[0] == 1:
                report_file.write("警告: 检测到潜在的恶意代码！\n")

                # 计算新代码和特征库中每个类别的相似度
                similarities = cosine_similarity(new_X, vectors[len(java_code_samples):])

                # 找到最相似的特征索引
                most_similar_index = np.argmax(similarities[0])

                # 输出对应的恶意代码类别
                detected_category = categories[most_similar_index]
                detected_category_str = f"检测到的恶意代码类别: {detected_category}\n"
                report_file.write(detected_category_str)
            else:
                report_file.write("代码是安全的。\n")

    # 输出生成的报告路径
    print(f"检测报告已生成: {report_path}")
