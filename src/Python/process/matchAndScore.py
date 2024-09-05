import json
import importlib.util
import os
from collections import defaultdict


def load_patterns_module():
    """
    加载当前文件夹中的 patterns.py 模块。
    """
    current_directory = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本所在的目录
    patterns_file_path = os.path.join(current_directory, "patterns.py")  # 构造patterns.py的路径
    spec = importlib.util.spec_from_file_location("patterns", patterns_file_path)
    patterns = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns)
    return patterns


def calculate_and_format_score(key_info, patterns, category_name):
    """
    计算和格式化关键信息的匹配得分。
    """
    score = 0
    matched_patterns = defaultdict(lambda: {"count": 0, "type": None, "severity": 0, "scored": False})

    # 完全匹配的得分计算
    for imp in key_info['Imports']:
        for pattern, severity in patterns.get('Imports', {}).items():
            if imp == pattern:
                if not matched_patterns[pattern]["scored"]:
                    score += severity
                    matched_patterns[pattern]["scored"] = True
                matched_patterns[pattern]["count"] += 1
                matched_patterns[pattern]["type"] = "Imports"
                matched_patterns[pattern]["severity"] = severity

    for string in key_info['Strings']:
        for pattern, severity in patterns.get('Strings', {}).items():
            if string == pattern:
                if not matched_patterns[pattern]["scored"]:
                    score += severity
                    matched_patterns[pattern]["scored"] = True
                matched_patterns[pattern]["count"] += 1
                matched_patterns[pattern]["type"] = "Strings"
                matched_patterns[pattern]["severity"] = severity

    for call in key_info['Function_Calls']:
        for pattern, severity in patterns.get('Function_Calls', {}).items():
            if call == pattern:
                if not matched_patterns[pattern]["scored"]:
                    score += severity
                    matched_patterns[pattern]["scored"] = True
                else:
                    score += 1
                matched_patterns[pattern]["count"] += 1
                matched_patterns[pattern]["type"] = "Function_Calls"
                matched_patterns[pattern]["severity"] = severity

    # 模糊匹配的得分计算
    for imp in key_info['Imports']:
        if imp not in matched_patterns:
            for pattern, severity in patterns.get('Imports', {}).items():
                if pattern in imp:
                    if not matched_patterns[pattern]["scored"]:
                        adjusted_severity = max(0, severity - 5)
                        if adjusted_severity > 0:
                            score += adjusted_severity
                        matched_patterns[pattern]["scored"] = True
                    matched_patterns[pattern]["count"] += 1
                    matched_patterns[pattern]["type"] = "Imports"
                    matched_patterns[pattern]["severity"] = severity
                    break

    for string in key_info['Strings']:
        if string not in matched_patterns:
            for pattern, severity in patterns.get('Strings', {}).items():
                if pattern in string:
                    if not matched_patterns[pattern]["scored"]:
                        adjusted_severity = max(0, severity - 5)
                        if adjusted_severity > 0:
                            score += adjusted_severity
                        matched_patterns[pattern]["scored"] = True
                    matched_patterns[pattern]["count"] += 1
                    matched_patterns[pattern]["type"] = "Strings"
                    matched_patterns[pattern]["severity"] = severity
                    break

    for call in key_info['Function_Calls']:
        if call not in matched_patterns:
            for pattern, severity in patterns.get('Function_Calls', {}).items():
                if pattern in call:
                    if not matched_patterns[pattern]["scored"]:
                        adjusted_severity = max(0, severity - 5)
                        if adjusted_severity > 0:
                            score += adjusted_severity
                        matched_patterns[pattern]["scored"] = True
                    matched_patterns[pattern]["count"] += 1
                    matched_patterns[pattern]["type"] = "Function_Calls"
                    matched_patterns[pattern]["severity"] = severity
                    break

    # 格式化输出
    pattern_details = []
    for pattern, details in matched_patterns.items():
        pattern_details.append(
            f"    Type: {details['type']} | Pattern: {pattern} | Severity: {details['severity']} | Count: {details['count']}"
        )

    if pattern_details:
        formatted_result = f"Category: {category_name} (Total Severity: {score})\n" + "\n".join(pattern_details)
        return score, formatted_result
    else:
        return score, None  # 无匹配项则返回 None


def get_score(folder_path):
    """
    检测指定文件夹中的 Python 文件，并根据 patterns.py 中的模式计算匹配分数。
    """
    # 加载 patterns.py 模块
    patterns_module = load_patterns_module()

    # 从 json_output 文件夹中的 key_info_all_files.json 文件加载关键信息
    json_output_dir = os.path.join(folder_path, 'json_output')
    key_info_path = os.path.join(json_output_dir, 'key_info_all_files.json')

    if not os.path.exists(key_info_path):
        raise FileNotFoundError(f"Key info JSON file not found: {key_info_path}")

    with open(key_info_path, 'r', encoding='utf-8') as infile:
        key_info = json.load(infile)

    # 获取 patterns.py 中的模式库
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

    max_score = 0
    dominant_category = None
    all_results = []

    # 遍历模式库并输出结果
    for category_name, patterns in patterns_categories.items():
        score, result = calculate_and_format_score(key_info, patterns, category_name)
        if result:
            all_results.append(result)
        if score > max_score:
            max_score = score
            dominant_category = category_name

    # 输出 Dominant Malicious Code Type 信息
    if dominant_category:
        all_results.append(f"Dominant Malicious Code Type: {dominant_category} (Total Severity: {max_score})")

    # 提取待检测文件夹的名称
    folder_name = os.path.basename(os.path.normpath(folder_path))

    # 生成结果文件名
    output_file_name = f"{folder_name}_AST_results.txt"
    output_file_path = os.path.join(folder_path, output_file_name)

    # 将结果保存为文本文件
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        outfile.write("\n\n".join(all_results))

    print(f"Results have been written to {output_file_path}")
    return output_file_path
