import ast
import json

def save_ast_to_json(python_file_path, json_file_path):
    with open(python_file_path, 'r', encoding='utf-8') as file:  # 指定编码为utf-8
        python_code = file.read()

    # 解析AST
    tree = ast.parse(python_code)
    
    # AST转化为dict并保存为JSON
    ast_dict = ast.dump(tree, annotate_fields=True, include_attributes=True)
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        json.dump(ast_dict, json_file)

def extract_key_info_from_json(json_file_path):
    with open(json_file_path, 'r') as json_file:
        ast_dict = json.load(json_file)

    Imports = []
    Function_Calls = []
    Strings = []

    # 遍历AST节点，提取Imports, FunctionCalls, Strings
    for node in ast.walk(ast.parse(ast_dict)):
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            for alias in node.names:
                Imports.append(f"{node.module}.{alias.name}" if node.module else alias.name)
        elif isinstance(node, ast.Call):
            func_name = getattr(node.func, 'id', None) or '.'.join([getattr(node.func.value, 'id', ''), getattr(node.func.attr, '')])
            Function_Calls.append(func_name)
        elif isinstance(node, ast.Str) or isinstance(node, ast.Constant) and isinstance(node.value, str):
            Strings.append(node.value)

    return {'Imports': Imports, 'Function_Calls': Function_Calls, 'Strings': Strings}

if __name__ == "__main__":
    # 假设提供了恶意代码的路径
    python_file_path = r'C:\Users\86156\Desktop\share\Trojan-Detector\src\Python\src_bzr\the_last_four\obfuscation\BlankOBFv2.py'  # 需要检测的代码文件路径
    json_file_path = r'C:\Users\86156\Desktop\share\Trojan-Detector\src\Python\process\bzrproject\output.json'

    # 保存AST为JSON文件
    save_ast_to_json(python_file_path, json_file_path)

    # 从JSON中提取关键信息
    key_info = extract_key_info_from_json(json_file_path)

    # 将关键信息保存为另一个JSON文件，供后续匹配使用
    with open('key_info.json', 'w') as outfile:
        json.dump(key_info, outfile)
