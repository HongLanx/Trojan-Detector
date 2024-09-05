import os
import ast
import json

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

    return key_info_output_path  # 返回生成的 JSON 文件路径

# 定义一个主函数用于外部调用
def turnToJson(directory_path):
    """
    检测指定文件夹中的所有 Python 文件，并提取 AST 树的关键信息。
    """
    if not os.path.isdir(directory_path):
        raise ValueError(f"指定的路径无效: {directory_path}")
    
    print(f"开始处理文件夹: {directory_path}")
    result_json_path = process_python_files_in_directory(directory_path)
    print(f"关键信息提取完成，结果已保存到: {result_json_path}")

    return result_json_path  # 返回结果文件的路径
