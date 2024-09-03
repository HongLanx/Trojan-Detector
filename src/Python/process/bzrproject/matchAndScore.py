import json
import importlib.util
import os

def load_patterns_module(patterns_file_path):
    spec = importlib.util.spec_from_file_location("patterns", patterns_file_path)
    patterns = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns)
    return patterns

def calculate_and_format_score(key_info_list, patterns, category_name):
    score = 0
    matched_imports = set()
    matched_function_calls = {}
    matched_strings = set()
    pattern_details = []

    # 遍历每个文件的关键信息
    for key_info in key_info_list:
        # 完全匹配的得分计算
        for imp in key_info['Imports']:
            if imp in patterns.get('Imports', {}) and imp not in matched_imports:
                severity = patterns['Imports'][imp]
                score += severity
                matched_imports.add(imp)
                pattern_details.append(f"    -Pattern: {imp}, Severity: {severity}, Count: 1")

        for call in key_info['Function_Calls']:
            if call in patterns.get('Function_Calls', {}):
                severity = patterns['Function_Calls'][call]
                if call not in matched_function_calls:
                    score += severity
                    matched_function_calls[call] = 1
                else:
                    matched_function_calls[call] += 1
                    score += 1
                pattern_details.append(f"    -Pattern: {call}, Severity: {severity}, Count: {matched_function_calls[call]}")

        for string in key_info['Strings']:
            if string in patterns.get('Strings', {}) and string not in matched_strings:
                severity = patterns['Strings'][string]
                score += severity
                matched_strings.add(string)
                pattern_details.append(f"    -Pattern: {string}, Severity: {severity}, Count: 1")

        # 模糊匹配的得分计算
        for imp in key_info['Imports']:
            if imp not in matched_imports:
                for pattern in patterns.get('Imports', {}):
                    if pattern in imp:
                        original_severity = patterns['Imports'].get(pattern, 0)
                        severity = max(0, original_severity - 5)
                        if severity > 0:
                            score += severity
                            matched_imports.add(imp)
                            pattern_details.append(f"    -Pattern: {pattern} (fuzzy), Severity: {severity}, Count: 1")
                        break

        for call in key_info['Function_Calls']:
            if call not in matched_function_calls:
                for pattern in patterns.get('Function_Calls', {}):
                    if pattern in call:
                        original_severity = patterns['Function_Calls'].get(pattern, 0)
                        severity = max(0, original_severity - 5)
                        if severity > 0:
                            matched_function_calls[call] = 1
                            score += severity
                            pattern_details.append(f"    -Pattern: {pattern} (fuzzy), Severity: {severity}, Count: 1")
                        break

        for string in key_info['Strings']:
            if string not in matched_strings:
                for pattern in patterns.get('Strings', {}):
                    if pattern in string:
                        original_severity = patterns['Strings'].get(pattern, 0)
                        severity = max(0, original_severity - 5)
                        if severity > 0:
                            matched_strings.add(string)
                            score += severity
                            pattern_details.append(f"    -Pattern: {pattern} (fuzzy), Severity: {severity}, Count: 1")
                        break

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
    directory_path = os.path.join(parent_directory, 'json_output')

    # 构建 key_info_path.txt 文件的路径
    key_info_path_txt = os.path.join(directory_path, 'key_info_path.txt')

    # 从 key_info_path.txt 中读取 key_info_all_files.json 的路径
    if not os.path.exists(key_info_path_txt):
        raise FileNotFoundError(f"Key info path file not found: {key_info_path_txt}")

    with open(key_info_path_txt, 'r', encoding='utf-8') as path_file:
        key_info_path = path_file.read().strip()

    # 从 JSON 文件加载关键信息
    with open(key_info_path, 'r', encoding='utf-8') as infile:
        key_info_list = json.load(infile)

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
        score, result = calculate_and_format_score(key_info_list, patterns, category_name)
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
