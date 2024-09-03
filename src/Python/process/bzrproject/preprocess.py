import os
import ast
import json

def save_ast_to_json(python_file_path, json_output_dir):
    """
    将 Python 文件转化为 AST,并保存为 JSON 文件到指定的目录。
    """
    with open(python_file_path, 'r', encoding='utf-8') as file:
        python_code = file.read()
    tree = ast.parse(python_code)
    ast_json = ast.dump(tree)
    
    # 获取文件名并生成对应的 .json 文件路径
    file_name = os.path.basename(python_file_path)
    json_file_path = os.path.join(json_output_dir, f"{os.path.splitext(file_name)[0]}.json")
    
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        json.dump(ast_json, json_file)

def extract_key_info_from_ast(ast_tree):
    """
    从 AST 树中提取关键信息，包括 Imports、Function_Calls 和 Strings。
    """
    Imports = set()
    Function_Calls = set()
    Strings = set()

    for node in ast.walk(ast_tree):
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            for alias in node.names:
                Imports.add(alias.name)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                Function_Calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                Function_Calls.add(node.func.attr)
        elif isinstance(node, ast.Str):
            Strings.add(node.s)

    return {
        "Imports": list(Imports),
        "Function_Calls": list(Function_Calls),
        "Strings": list(Strings)
    }

def process_python_files_in_directory(directory_path):
    """
    处理指定目录中的所有 .py 文件，将它们转化为 JSON 文件并提取关键信息。
    """
    # 创建一个新子文件夹来存储 .json 文件
    json_output_dir = os.path.join(directory_path, 'json_output')
    os.makedirs(json_output_dir, exist_ok=True)
    
    key_info_all_files = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                python_file_path = os.path.join(root, file)
                
                # 将 .py 文件转化为 AST 并保存为 JSON 文件
                save_ast_to_json(python_file_path, json_output_dir)

                # 解析 AST 并提取关键信息
                with open(os.path.join(json_output_dir, f"{os.path.splitext(file)[0]}.json"), 'r', encoding='utf-8') as json_file:
                    ast_json = json.load(json_file)
                ast_tree = ast.parse(ast_json)
                key_info = extract_key_info_from_ast(ast_tree)
                key_info_all_files.append(key_info)

    # 生成 key_info_all_files.json 的路径
    key_info_output_path = os.path.join(json_output_dir, 'key_info_all_files.json')

    # 将所有文件的关键信息保存为一个 JSON 文件
    with open(key_info_output_path, 'w', encoding='utf-8') as outfile:
        json.dump(key_info_all_files, outfile, indent=4)

    # 将存储路径写入一个文本文件，以便匹配代码读取
    key_info_path_txt_path = os.path.join(json_output_dir, 'key_info_path.txt')
    with open(key_info_path_txt_path, 'w', encoding='utf-8') as path_file:
        path_file.write(key_info_output_path)

if __name__ == "__main__":
    # 从用户输入获取待检测文件夹路径
    directory_path = input("请输入待检测文件夹的路径: ")
    
    # 处理目录中的所有 Python 文件
    process_python_files_in_directory(directory_path)
