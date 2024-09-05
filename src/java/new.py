import os
import json
from javalang.tree import Node
from javalang.tokenizer import Keyword
import javalang
from javalang.parse import parse
from javalang.tree import Node
from tkinter import Tk
from tkinter.filedialog import askdirectory
from tkinter.filedialog import askopenfilename

# 从 feature.py 中导入模块或函数
from src.java.feature import encryption_patterns,botnet_patterns,penetration_patterns,obfuscation_patterns,phishing_patterns,Keyboard_patterns,backdoor_patterns,ransomware_patterns,Trojan_virus_patterns,rootkit_patterns,Defense_Bypass_patterns,antivirus_patterns,adware_patterns,hackingtool_patterns  # 替换成 feature.py 中实际的函数名或类名


# 定义所有的特征库在一个字典中
all_patterns = {
    "Encryption": encryption_patterns,
    "Botnet": botnet_patterns,
    "Penetration": penetration_patterns,
    "Obfuscation": obfuscation_patterns,
    "Phishing": phishing_patterns,
    "Keylogger": Keyboard_patterns,
    "Backdoor": backdoor_patterns,
    "Ransomware": ransomware_patterns,  # 新增
    "Trojan_Virus": Trojan_virus_patterns,  # 新增
    "Rootkit": rootkit_patterns,  # 新增
    "Antivirus": antivirus_patterns,  # 新增
    "Adware": adware_patterns,  # 新增
    "HackingTool": hackingtool_patterns,  # 新增
}


#定义每种恶意代码的分数阈值
thresholds = {
    "Keylogger": 20,
    "Encryption": 15,
    "Botnet": 12,
    "Penetration": 20,
    "Obfuscation": 8,
    "Phishing": 10,
    "Trojan": 18,
    "Ransomware": 17,  # 新增
    "Trojan_Virus": 16,  # 新增
    "Rootkit": 19,  # 新增
    "Antivirus": 18,  # 新增
    "Adware": 14,  # 新增
    "HackingTool": 15,  # 新增
}



# 递归地将AST节点转换为字典
def node_to_dict(node):
    if isinstance(node, Node):
        result = {}
        result['node_type'] = node.__class__.__name__
        for field in node.attrs:
            value = getattr(node, field)
            if isinstance(value, set):
                result[field] = list(value)  # 转换set为list
            else:
                result[field] = node_to_dict(value)
        return result
    elif isinstance(node, list):
        return [node_to_dict(item) for item in node]
    elif isinstance(node, Keyword):
        return str(node)  # 将Keyword对象转换为字符串
    else:
        return node


# 解析Java文件并将其转换为AST的JSON表示
def java_file_to_ast_json(java_file_path, output_dir="ast_output"):
    try:
        with open(java_file_path, 'r', encoding='utf-8') as file:
            java_code = file.read()

        java_file_dir=os.path.dirname(java_file_path)
        # 解析Java代码生成AST
        tree = parse(java_code)
        ast_dict = node_to_dict(tree)

        # 生成JSON文件名
        json_file_name = os.path.basename(java_file_path).replace('.java', '_ast.json')
        if not os.path.exists(os.path.join(java_file_dir,output_dir)):
            os.makedirs(os.path.join(java_file_dir,output_dir))
        json_file_path = os.path.join(java_file_dir, output_dir, json_file_name)

        # 标准化路径以确保跨平台兼容
        json_file_path = os.path.normpath(json_file_path)

        # 打印生成的文件路径
        print(f"Generated JSON file path: {json_file_path}")

        # 将AST写入JSON文件
        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(ast_dict, json_file, indent=4)

        return json_file_path

    except Exception as e:
        print(f"Failed to process {java_file_path}: {str(e)}")
        return None


# 解析JSON文件并与特征库对比
def check_malicious_code(json_data, patterns, detected, severity_scores):
    def recursive_check(data, patterns):
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    recursive_check(value, patterns)
                else:
                    for category, pattern_set in patterns.items():
                        for pattern_dict in pattern_set.values():
                            for pattern_key, severity in pattern_dict.items():
                                if str(value) == pattern_key:
                                    if category not in detected:
                                        detected[category] = {}
                                        severity_scores[category] = 0  # 初始化分数

                                    if pattern_key not in detected[category]:
                                        detected[category][pattern_key] = {"severity": severity, "count": 1}
                                        severity_scores[category] += severity  # 只计入一次分数
                                    else:
                                        detected[category][pattern_key]["count"] += 1  # 计数增加
                                    print(f"Detected {category} pattern: {value} matches {pattern_key}")

        elif isinstance(data, list):
            for item in data:
                recursive_check(item, patterns)

    recursive_check(json_data, patterns)


def generate_project_report(detected, severity_scores, report_path):
    # 找出超过阈值且分数最高的恶意代码类型
    filtered_categories = {cat: score for cat, score in severity_scores.items() if score >= thresholds.get(cat, 0)}
    if filtered_categories:
        dominant_category = max(filtered_categories, key=filtered_categories.get)
    else:
        dominant_category = "无"

    with open(report_path, 'w', encoding='utf-8') as report_file:
        if detected:
            report_file.write("检测到的恶意模式:\n")
            for category, patterns in detected.items():
                report_file.write(f"\n类别: {category} (总严重性得分: {severity_scores[category]})\n")
                for pattern_key, info in patterns.items():
                    report_file.write(
                        f"  - 模式: {pattern_key}, 严重性: {info['severity']}, 出现次数: {info['count']}\n")
            if dominant_category != "无":
                report_file.write(
                    f"\n主要恶意代码类型: {dominant_category} (总严重性得分: {severity_scores[dominant_category]})\n")
            else:
                report_file.write("\n没有恶意代码类型超过定义的阈值。\n")
        else:
            report_file.write("未检测到恶意模式。\n")
    print(f"项目检测报告已生成: {report_path}")


def select_and_process_project(folder_path):
        if not folder_path:
            print("No folder path provided.")
            return

        detected = {}
        severity_scores = {}

        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".java"):
                    java_file_path = os.path.join(root, file)
                    print(f"Processing: {java_file_path}")

                    # 将Java文件转换为AST JSON
                    json_file_path = java_file_to_ast_json(java_file_path)

                    # 检查是否成功生成AST JSON文件
                    if json_file_path is None:
                        print(f"Skipping {java_file_path} due to parsing failure.")
                        continue
                    # 读取并检查生成的JSON文件
                    try:
                        with open(json_file_path, "r") as json_file:
                            json_data = json.load(json_file)
                            check_malicious_code(json_data, all_patterns, detected, severity_scores)
                    except Exception as e:
                        print(f"Error processing {json_file_path}: {str(e)}")
                        continue
        # 生成项目级别的检测报告
        report_path = os.path.join(folder_path, 'Project_Report.txt')
        generate_project_report(detected, severity_scores, report_path)


