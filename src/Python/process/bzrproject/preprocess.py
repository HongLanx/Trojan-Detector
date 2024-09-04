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
            Strings.append(node.s)

    return {
        "Imports": Imports,
        "Function_Calls": Function_Calls,
        "Strings": Strings
    }

def process_python_files_in_directory(directory_path):
    """
    处理指定目录中的所有 .py 文件，将它们提取的关键信息合并到一起。
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
                
                # 解析 AST 并提取关键信息
                with open(python_file_path, 'r', encoding='utf-8') as file:
                    python_code = file.read()
                ast_tree = ast.parse(python_code)
                key_info = extract_key_info_from_ast(ast_tree)
                
                # 合并提取的关键信息（保留重复项）
                combined_info['Imports'].extend(key_info['Imports'])
                combined_info['Function_Calls'].extend(key_info['Function_Calls'])
                combined_info['Strings'].extend(key_info['Strings'])

    # 生成 key_info_all_files.json 的路径
    key_info_output_path = os.path.join(json_output_dir, 'key_info_all_files.json')

    # 将合并的关键信息保存为一个 JSON 文件
    with open(key_info_output_path, 'w', encoding='utf-8') as outfile:
        json.dump(combined_info, outfile, indent=4)

if __name__ == "__main__":
    # 从用户输入获取待检测文件夹路径
    directory_path = input("请输入待检测文件夹的路径: ")
    
    # 处理目录中的所有 Python 文件
    process_python_files_in_directory(directory_path)
