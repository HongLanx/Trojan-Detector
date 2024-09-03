import json
import importlib.util
import os

def load_patterns_module(patterns_file_path):
    """
    动态加载指定路径的 patterns 模块
    """
    spec = importlib.util.spec_from_file_location("patterns", patterns_file_path)
    patterns = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns)
    return patterns

def calculate_and_format_score(key_info, patterns, category_name):
    score = 0
    matched_imports = set()
    matched_function_calls = {}
    matched_strings = set()
    pattern_details = []

    # 完全匹配的得分计算
    # 处理 Imports 的完全匹配
    for imp in key_info['Imports']:
        if imp in patterns.get('Imports', {}) and imp not in matched_imports:
            severity = patterns['Imports'][imp]
            score += severity
            matched_imports.add(imp)
            pattern_details.append(f"-Pattern: {imp}, Severity: {severity}, Count: 1")

    # 处理 Function_Calls 的完全匹配
    for call in key_info['Function_Calls']:
        if call in patterns.get('Function_Calls', {}):
            severity = patterns['Function_Calls'][call]
            if call not in matched_function_calls:
                score += severity
                matched_function_calls[call] = 1
            else:
                matched_function_calls[call] += 1
                score += 1  # 每次匹配成功后加 1 分
            pattern_details.append(f"-Pattern: {call}, Severity: {severity}, Count: {matched_function_calls[call]}")

    # 处理 Strings 的完全匹配
    for string in key_info['Strings']:
        if string in patterns.get('Strings', {}) and string not in matched_strings:
            severity = patterns['Strings'][string]
            score += severity
            matched_strings.add(string)
            pattern_details.append(f"-Pattern: {string}, Severity: {severity}, Count: 1")

    # 模糊匹配的得分计算
    # 处理 Imports 的模糊匹配
    for imp in key_info['Imports']:
        if imp not in matched_imports:
            fuzzy_match = [pattern for pattern in patterns.get('Imports', {}) if imp in pattern]
            if fuzzy_match:
                original_severity = patterns['Imports'].get(fuzzy_match[0], 0)
                severity = max(0, original_severity - 5)  # 原分数减5，但不低于0
                if severity > 0:
                    score += severity
                    matched_imports.add(imp)
                    pattern_details.append(f"-Pattern: {imp} (fuzzy), Severity: {severity}, Count: 1")

    # 处理 Function_Calls 的模糊匹配
    for call in key_info['Function_Calls']:
        if call not in matched_function_calls:
            fuzzy_match = [pattern for pattern in patterns.get('Function_Calls', {}) if call in pattern]
            if fuzzy_match:
                original_severity = patterns['Function_Calls'].get(fuzzy_match[0], 0)
                severity = max(0, original_severity - 5)  # 原分数减5，但不低于0
                if severity > 0:
                    matched_function_calls[call] = 1
                    score += severity
                    pattern_details.append(f"-Pattern: {call} (fuzzy), Severity: {severity}, Count: 1")

    # 处理 Strings 的模糊匹配
    for string in key_info['Strings']:
        if string not in matched_strings:
            fuzzy_match = [pattern for pattern in patterns.get('Strings', {}) if string in pattern]
            if fuzzy_match:
                original_severity = patterns['Strings'].get(fuzzy_match[0], 0)
                severity = max(0, original_severity - 5)  # 原分数减5，但不低于0
                if severity > 0:
                    matched_strings.add(string)
                    score += severity
                    pattern_details.append(f"-Pattern: {string} (fuzzy), Severity: {severity}, Count: 1")

    # 输出结果
    if pattern_details:
        print(f"Calculated score for {category_name}: {score}")
        formatted_result = f"Category: {category_name} (Total Severity: {score})\n" + "\n".join(pattern_details)
        return formatted_result
    else:
        return None  # 无匹配项则返回None

if __name__ == "__main__":
    # 指定patterns.py的路径
    patterns_file_path = r'C:\Users\86156\Desktop\share\Trojan-Detector\src\Python\patterns.py'
    patterns_module = load_patterns_module(patterns_file_path)

    # 从JSON文件加载关键信息
    with open('key_info.json', 'r') as infile:
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

    # 逐个匹配每个模式库并输出结果
    for category_name, patterns in patterns_categories.items():
        result = calculate_and_format_score(key_info, patterns, category_name)
        if result:
            print(result)
