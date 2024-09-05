import os
import ast
import json
import importlib.util
from collections import defaultdict

def extract_key_info_from_ast(ast_tree):
    """
    从 AST 树中提取关键信息，包括 Imports、Function_Calls 和 Strings。
    """
    Imports = []
    Function_Calls = []
    Strings = []

    for node in ast.walk(ast_tree):
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            for alias in node.names:
                Imports.append(alias.name)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                Function_Calls.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                Function_Calls.append(node.func.attr)
        elif isinstance(node, ast.Str):
            # 仅提取长度不超过 100 个字符且不包含换行符的字符串
            if len(node.s) <= 100 and '\n' not in node.s:
                Strings.append(node.s)

    return {
        "Imports": Imports,
        "Function_Calls": Function_Calls,
        "Strings": Strings
    }

def process_python_files_in_directory(directory_path):
    """
    处理指定目录中的所有 .py 文件，将它们提取的关键信息合并到一起。
    跳过包含语法错误的文件，并在运行界面给出提示。
    """
    # 创建一个新子文件夹来存储 .json 文件
    json_output_dir = os.path.join(directory_path, 'json_output')
    os.makedirs(json_output_dir, exist_ok=True)
    
    # 合并后的关键信息
    combined_info = {
        "Imports": [],
        "Function_Calls": [],
        "Strings": []
    }

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                python_file_path = os.path.join(root, file)

                try:
                    # 解析 AST 并提取关键信息
                    with open(python_file_path, 'r', encoding='utf-8') as file:
                        python_code = file.read()
                    ast_tree = ast.parse(python_code)
                    key_info = extract_key_info_from_ast(ast_tree)

                    # 合并提取的关键信息（保留重复项）
                    combined_info['Imports'].extend(key_info['Imports'])
                    combined_info['Function_Calls'].extend(key_info['Function_Calls'])
                    combined_info['Strings'].extend(key_info['Strings'])
                
                except SyntaxError:
                    # 捕获语法错误并跳过该文件
                    print(f"{python_file_path} 文件解析失败，包含语法错误。")
                    continue

    # 生成 key_info_all_files.json 的路径
    key_info_output_path = os.path.join(json_output_dir, 'key_info_all_files.json')

    # 将合并的关键信息保存为一个 JSON 文件
    with open(key_info_output_path, 'w', encoding='utf-8') as outfile:
        json.dump(combined_info, outfile, indent=4)

    return key_info_output_path  # 返回 JSON 文件的路径

def load_patterns_module(patterns_file_path):
    spec = importlib.util.spec_from_file_location("patterns", patterns_file_path)
    patterns = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patterns)
    return patterns

def calculate_and_format_score(key_info, patterns, category_name):
    score = 0
    matched_patterns = defaultdict(lambda: {"count": 0, "type": None, "severity": 0, "scored": False})

    # 完全匹配的得分计算
    for imp in key_info['Imports']:  # 累计所有匹配次数
        for pattern, severity in patterns.get('Imports', {}).items():
            if imp == pattern:  # 完全匹配
                if not matched_patterns[pattern]["scored"]:  # 确保只计一次分
                    score += severity
                    matched_patterns[pattern]["scored"] = True
                matched_patterns[pattern]["count"] += 1  # 每次匹配都记录次数
                matched_patterns[pattern]["type"] = "Imports"
                matched_patterns[pattern]["severity"] = severity

    for string in key_info['Strings']:  # 累计所有匹配次数
        for pattern, severity in patterns.get('Strings', {}).items():
            if string == pattern:  # 完全匹配
                if not matched_patterns[pattern]["scored"]:  # 确保只计一次分
                    score += severity
                    matched_patterns[pattern]["scored"] = True
                matched_patterns[pattern]["count"] += 1  # 每次匹配都记录次数
                matched_patterns[pattern]["type"] = "Strings"
                matched_patterns[pattern]["severity"] = severity

    for call in key_info['Function_Calls']:  # 累计所有匹配次数
        for pattern, severity in patterns.get('Function_Calls', {}).items():
            if call == pattern:  # 完全匹配
                if not matched_patterns[pattern]["scored"]:  # 第一次匹配
                    score += severity
                    matched_patterns[pattern]["scored"] = True
                else:  # 后续每次匹配加 1
                    score += 1
                matched_patterns[pattern]["count"] += 1
                matched_patterns[pattern]["type"] = "Function_Calls"
                matched_patterns[pattern]["severity"] = severity

    # 输出结果
    pattern_details = []
    for pattern, details in matched_patterns.items():
        pattern_details.append(
            f"    Type: {details['type']} | Pattern: {pattern} | Severity: {details['severity']} | Count: {details['count']}"
        )

    if pattern_details:
        formatted_result = f"Category: {category_name} (Total Severity: {score})\n" + "\n".join(pattern_details)
        return score, formatted_result
    else:
        return score, None  # 无匹配项则返回None

if __name__ == "__main__":
    # 从用户输入获取待检测文件夹路径
    directory_path = input("请输入待检测文件夹的路径: ")
    
    # 处理目录中的所有 Python 文件并生成 key_info_all_files.json
    key_info_output_path = process_python_files_in_directory(directory_path)

    # 加载 patterns.py 模块
    current_directory = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本所在的目录
    patterns_file_path = os.path.join(current_directory, "patterns.py")  # 构造 patterns.py 的路径
    patterns_module = load_patterns_module(patterns_file_path)

    # 从 JSON 文件加载关键信息
    with open(key_info_output_path, 'r', encoding='utf-8') as infile:
        key_info = json.load(infile)

    # 获取 patterns.py 中的所有模式库
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

    # 输出结果
    if dominant_category:
        all_results.append(f"Dominant Malicious Code Type: {dominant_category} (Total Severity: {max_score})")

    # 确定输出文件的路径为待检测文件夹
    folder_name = os.path.basename(os.path.normpath(directory_path))
    output_file_name = f"{folder_name}_AST_results.txt"
    output_file_path = os.path.join(directory_path, output_file_name)

    # 输出结果到 txt 文件
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        outfile.write("\n\n".join(all_results))

    print(f"Results have been written to {output_file_path}")
