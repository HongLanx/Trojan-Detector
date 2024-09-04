import json
import importlib.util
import os
from collections import defaultdict

def load_patterns_module(patterns_file_path):
    spec = importlib.util.spec_from_file_location("patterns", patterns_file_path)
    patterns = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns)
    return patterns

<<<<<<< HEAD
def calculate_and_format_score(key_info, patterns, category_name):
    score = 0
    matched_patterns = defaultdict(lambda: {"count": 0, "type": None, "severity": 0})
    
    # 完全匹配的得分计算
    for imp in key_info['Imports']:
        if imp in patterns.get('Imports', {}):
            severity = patterns['Imports'][imp]
            score += severity
            matched_patterns[imp]["count"] += 1
            matched_patterns[imp]["type"] = "Imports"
            matched_patterns[imp]["severity"] = severity
=======
# 待检测文件夹地址
folder_path = r"D:\AAAshuju\feast-master"
>>>>>>> 89d272efce4edfebcec68d20cab6ac636bf52605

    for call in key_info['Function_Calls']:
        if call in patterns.get('Function_Calls', {}):
            severity = patterns['Function_Calls'][call]
            score += severity
            matched_patterns[call]["count"] += 1
            matched_patterns[call]["type"] = "Function_Calls"
            matched_patterns[call]["severity"] = severity

<<<<<<< HEAD
    for string in key_info['Strings']:
        if string in patterns.get('Strings', {}):
            severity = patterns['Strings'][string]
            score += severity
            matched_patterns[string]["count"] += 1
            matched_patterns[string]["type"] = "Strings"
            matched_patterns[string]["severity"] = severity
=======
# 定义一个函数用于检测Python文件中的特征
def detect_trojans_in_file(file_path, patterns, matched_patterns):
    matches = defaultdict(lambda: defaultdict(lambda: {"exact": 0, "fuzzy": 0}))
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()

        for category, pattern_types in patterns.items():
            for pattern_type, pattern_dict in pattern_types.items():
                for pattern, score in pattern_dict.items():
                    if pattern_type == "Imports":
                        # Imports: 只计一次
                        if re.search(r'\b' + re.escape(pattern) + r'\b', file_content) and pattern not in matched_patterns[category][pattern_type]:
                            matches[category][(pattern_type, pattern)]["exact"] = 1
                            matched_patterns[category][pattern_type].add(pattern)
                    elif pattern_type == "Function_Calls":
                        # Function_Calls: 第一次完全匹配后加分，后续每次匹配只加 1 分
                        match_count = len(re.findall(r'\b' + re.escape(pattern) + r'\b', file_content))
                        if match_count > 0 and pattern not in matched_patterns[category][pattern_type]:
                            matches[category][(pattern_type, pattern)]["exact"] = 1
                            matches[category][(pattern_type, pattern)]["fuzzy"] = match_count - 1
                            matched_patterns[category][pattern_type].add(pattern)
                    elif pattern_type == "Strings":
                        # Strings: 精确匹配和模糊匹配，模糊匹配加分比精确匹配低 5 分
                        if re.search(r'\b' + re.escape(pattern) + r'\b', file_content) and pattern not in matched_patterns[category][pattern_type]:
                            exact_matches = len(re.findall(r'\b' + re.escape(pattern) + r'\b', file_content))
                            matches[category][(pattern_type, pattern)]["exact"] = exact_matches
                            matched_patterns[category][pattern_type].add(pattern)
                        elif re.search(re.escape(pattern), file_content) and pattern not in matched_patterns[category][pattern_type]:
                            fuzzy_matches = len(re.findall(re.escape(pattern), file_content))
                            matches[category][(pattern_type, pattern)]["fuzzy"] = fuzzy_matches
                            matched_patterns[category][pattern_type].add(pattern)
    return matches
>>>>>>> 89d272efce4edfebcec68d20cab6ac636bf52605

    # 生成匹配结果
    pattern_details = []
    for pattern, details in matched_patterns.items():
        pattern_details.append(
            f"    -Pattern: {pattern} | Type: {details['type']} | Severity: {details['severity']} | Count: {details['count']}"
        )

<<<<<<< HEAD
    # 输出结果
    if pattern_details:
        formatted_result = f"Category: {category_name} (Total Severity: {score})\n" + "\n".join(pattern_details)
        return score, formatted_result
    else:
        return score, None  # 无匹配项则返回None
=======
    # 初始化结果统计
    detection_results = defaultdict(lambda: defaultdict(lambda: {"count": 0, "score": 0}))
    category_total_scores = defaultdict(int)
    matched_patterns = defaultdict(lambda: defaultdict(set))  # 用于存储已经匹配过的模式

    # 遍历文件夹中的所有Python文件
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.py'):
                file_path = os.path.join(root, file_name)
                file_matches = detect_trojans_in_file(file_path, all_patterns, matched_patterns)
                # 汇总检测结果
                for category, patterns in file_matches.items():
                    for (pattern_type, pattern), match_counts in patterns.items():
                        score = all_patterns[category][pattern_type][pattern]
                        # 计算不同类型的得分规则
                        if pattern_type == "Imports":
                            if match_counts["exact"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += 1
                                detection_results[category][(pattern_type, pattern)]["score"] += score
                                category_total_scores[category] += score
                        elif pattern_type == "Function_Calls":
                            if match_counts["exact"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += match_counts["exact"] + match_counts["fuzzy"]
                                detection_results[category][(pattern_type, pattern)]["score"] += score + match_counts["fuzzy"]
                                category_total_scores[category] += score + match_counts["fuzzy"]
                        elif pattern_type == "Strings":
                            if match_counts["exact"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += match_counts["exact"]
                                detection_results[category][(pattern_type, pattern)]["score"] += score * match_counts["exact"]
                                category_total_scores[category] += score * match_counts["exact"]
                            if match_counts["fuzzy"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += match_counts["fuzzy"]
                                detection_results[category][(pattern_type, pattern)]["score"] += (score - 5) * match_counts["fuzzy"]
                                category_total_scores[category] += (score - 5) * match_counts["fuzzy"]

    # 找出最高得分的木马行为类别
    max_category = max(category_total_scores, key=category_total_scores.get)
    max_score = category_total_scores[max_category]

    # 将结果写入当前脚本所在目录下的result.txt文件
    output_file_path = os.path.join(current_folder, "BFMresult.txt")
    with open(output_file_path, "w", encoding="utf-8") as result_file:
        result_file.write("检测结果：\n")
        for category, patterns in detection_results.items():
            result_file.write(f"\n类别: {category}\n")
            # 按照 Imports、Function_Calls、Strings 顺序列出每个特征
            for pattern_type in ["Imports", "Function_Calls", "Strings"]:
                for (ptype, pattern), data in patterns.items():
                    if ptype == pattern_type and data["count"] > 0:
                        result_file.write(
                            f"类型: {pattern_type:<15} | 特征: {pattern:<40} | 次数: {data['count']:<5} | 总分数: {data['score']:<5}\n"
                        )
            # 输出每个类别的总分
            result_file.write(f"类别总分: {category_total_scores[category]}\n")

        # 输出最终检测出的木马类别
        result_file.write(f"\n检测出的病毒木马类别为: {max_category}，总得分: {max_score}\n")
>>>>>>> 89d272efce4edfebcec68d20cab6ac636bf52605

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

    # 获取当前脚本所在的目录
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 确定输出文件的路径，放在当前代码所在的文件夹
    output_file_path = os.path.join(script_dir, 'detection_results.txt')

    # 输出结果到 txt 文件
    with open(output_file_path, 'w') as outfile:
        outfile.write("\n\n".join(all_results))

    print(f"Results have been written to {output_file_path}")
