import json
import importlib.util
import os
from collections import defaultdict

def load_patterns_module(patterns_file_path):
    spec = importlib.util.spec_from_file_location("patterns", patterns_file_path)
    patterns = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns)
    return patterns

def calculate_and_format_score(key_info, patterns, category_name):
    score = 0
    matched_patterns = defaultdict(lambda: {"count": 0, "type": None, "severity": 0})

    # 完全匹配的得分计算
    for imp in key_info['Imports']:
        for pattern in patterns.get('Imports', {}):
            if imp == pattern:  # 完全匹配
                severity = patterns['Imports'][pattern]
                score += severity
                matched_patterns[pattern]["count"] += 1
                matched_patterns[pattern]["type"] = "Imports"
                matched_patterns[pattern]["severity"] = severity

    for call in key_info['Function_Calls']:
        for pattern in patterns.get('Function_Calls', {}):
            if call == pattern:  # 完全匹配
                severity = patterns['Function_Calls'][pattern]
                score += severity
                matched_patterns[pattern]["count"] += 1
                matched_patterns[pattern]["type"] = "Function_Calls"
                matched_patterns[pattern]["severity"] = severity

    for string in key_info['Strings']:
        for pattern in patterns.get('Strings', {}):
            if string == pattern:  # 完全匹配
                severity = patterns['Strings'][pattern]
                score += severity
                matched_patterns[pattern]["count"] += 1
                matched_patterns[pattern]["type"] = "Strings"
                matched_patterns[pattern]["severity"] = severity

    # 模糊匹配的得分计算
    for imp in key_info['Imports']:
        if imp not in matched_patterns:
            for pattern in patterns.get('Imports', {}):
                if pattern in imp:  # 模糊匹配
                    original_severity = patterns['Imports'][pattern]
                    severity = max(0, original_severity - 5)
                    if severity > 0:
                        score += severity
                        matched_patterns[pattern]["count"] += 1
                        matched_patterns[pattern]["type"] = "Imports"
                        matched_patterns[pattern]["severity"] = severity
                    break

    for call in key_info['Function_Calls']:
        if call not in matched_patterns:
            for pattern in patterns.get('Function_Calls', {}):
                if pattern in call:  # 模糊匹配
                    original_severity = patterns['Function_Calls'][pattern]
                    severity = max(0, original_severity - 5)
                    if severity > 0:
                        score += severity
                        matched_patterns[pattern]["count"] += 1
                        matched_patterns[pattern]["type"] = "Function_Calls"
                        matched_patterns[pattern]["severity"] = severity
                    break

    for string in key_info['Strings']:
        if string not in matched_patterns:
            for pattern in patterns.get('Strings', {}):
                if pattern in string:  # 模糊匹配
                    original_severity = patterns['Strings'][pattern]
                    severity = max(0, original_severity - 5)
                    if severity > 0:
                        score += severity
                        matched_patterns[pattern]["count"] += 1
                        matched_patterns[pattern]["type"] = "Strings"
                        matched_patterns[pattern]["severity"] = severity
                    break

    # 格式化输出
    pattern_details = []
    for pattern, details in matched_patterns.items():
        type_len = max(len(details["type"]), 12)
        pattern_len = max(len(pattern), 20)
        severity_len = 8
        count_len = 6

        # 对齐表项
        pattern_details.append(
            f"    Type: {details['type']:<{type_len}} | Pattern: {pattern:<{pattern_len}} | Severity: {details['severity']:<{severity_len}} | Count: {details['count']:<{count_len}}"
        )

    # 输出结果
    if pattern_details:
        formatted_result = f"Category: {category_name} (Total Severity: {score})\n" + "\n".join(pattern_details)
        return score, formatted_result
    else:
        return score, None  # 无匹配项则返回None

if __name__ == "__main__":
    # 指定patterns.py的路径
    patterns_file_path = r'C:\Users\86156\Desktop\share\Trojan-Detector\src\Python\process\patterns.py'
    patterns_module = load_patterns_module(patterns_file_path)

    # 让用户输入待检测文件夹的路径
    parent_directory = input("请输入待检测文件夹的路径: ")
    json_output_dir = os.path.join(parent_directory, 'json_output')

    # 从 json_output 子文件夹中的 key_info_all_files.json 文件加载关键信息
    key_info_path = os.path.join(json_output_dir, 'key_info_all_files.json')

    # 检查 key_info_all_files.json 是否存在
    if not os.path.exists(key_info_path):
        raise FileNotFoundError(f"Key info JSON file not found: {key_info_path}")

    # 从 JSON 文件加载关键信息
    with open(key_info_path, 'r', encoding='utf-8') as infile:
        key_info = json.load(infile)

    # 获取patterns.py中的所有模式库
    patterns_categories = {
        "Botnet": patterns_module.botnet_patterns,
        "Penetration Testing": patterns_module.penetrationTesting_patterns,
        "Obfuscation": patterns_module.obfuscation_patterns,
        "Phishing": patterns_module.phishingAttack_patterns,
        "Malware": patterns_module.malware_patterns,
        "Ethical Hacking": patterns_module.ethicalHacking_patterns,
        "Ransomware": patterns_module.ransomware_patterns,
        "Bypass Attack": patterns_module.bypassAttack_patterns,
        "Keyboard Logger": patterns_module.keyboard_patterns,
        "Exploit": patterns_module.exploit_patterns
    }

    # 初始化最大分数和相应的模式库类别
    max_score = 0
    dominant_category = None
    all_results = []

    # 逐个匹配每个模式库并输出结果
    for category_name, patterns in patterns_categories.items():
        score, result = calculate_and_format_score(key_info, patterns, category_name)
        if result:
            all_results.append(result)
        if score > max_score:
            max_score = score
            dominant_category = category_name

    # 添加 Dominant Malicious Code Type 信息
    if dominant_category:
        all_results.append(f"Dominant Malicious Code Type: {dominant_category} (Total Severity: {max_score})")

    # 提取待检测文件夹的名称
    folder_name = os.path.basename(os.path.normpath(parent_directory))

    # 确定输出文件的路径，文件名为"待检测文件夹名称_detection_results.txt"
    output_file_name = f"{folder_name}_detection_results.txt"
    output_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_file_name)

    # 输出结果到 txt 文件
    with open(output_file_path, 'w') as outfile:
        outfile.write("\n\n".join(all_results))

    print(f"Results have been written to {output_file_path}")
