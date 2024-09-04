import json
import re
import os
import subprocess
import tkinter as tk
from tkinter import filedialog

import json_analyzer


# 输入一个go文件，在其目录输出一个go自带ast库生成的ast文本文件
def get_go_ast(file_path):
    result = subprocess.run(['GolangTool/AstGenerator.exe', file_path], capture_output=True, text=True)

def process_ast_text(input_text):
    # 使用正则表达式去除每行开头的数字、点和多余的空格
    cleaned_lines = []
    for line in input_text:
        # 从每行的起始位置去除数字和点，再去除随后的空格
        cleaned_line = re.sub(r'^\s*\d+\s*\.*\s*', '', line)
        # 进一步去除中间剩余的点及其前后的空格
        cleaned_line = re.sub(r'^(\.  )+(?=\S)', '', cleaned_line, flags=re.MULTILINE)
        cleaned_lines.append(cleaned_line)

    # 将清理后的文本重新拼接为字符串
    result_text = ''.join(cleaned_lines)
    return result_text


def parse_to_json(lines):
    stack = [{}]
    current_obj = stack[0]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 检测行缩进以确定层级
        depth = len(stack) - 1
        if line.endswith('{'):
            # 新对象的开始
            key = line.split(' ')[0]
            new_obj = {}
            if key.endswith('[]'):
                if key[:-2] not in stack[-1]:
                    stack[-1][key[:-2]] = []
                stack[-1][key[:-2]].append(new_obj)
            else:
                stack[-1][key] = new_obj
            stack.append(new_obj)
        elif line == '}':
            # 对象结束
            stack.pop()
        else:
            # 处理键值对
            if ': ' in line:
                key, value = line.split(': ', 1)
                value = value.replace('"', '')  # 移除字符串的引号
                stack[-1][key] = value

    return stack[0]


# 将ast文件转换为JSON文件，并解析
def convert_ast_to_json(file_path):
    file_path_base = '.'.join(file_path.split('.')[:-1])
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.readlines()

    print(f"正在将{file_path_base}.go的AST树转换为JSON...")
    # 处理文本
    processed_text = process_ast_text(content)
    lines = processed_text.split('\n')

    ast_dict = parse_to_json(lines)

    # 将解析结果写入JSON文件
    json_output_path = f'{file_path_base}.json'
    with open(json_output_path, 'w', encoding='utf-8') as f:
        json.dump(ast_dict, f, indent=4, ensure_ascii=False)

    # 再解析JSON文件，提取Import，函数调用等关键信息
    info = json_analyzer.extract_key_info(json_output_path)
    return info




# 输入一个go文件，在其目录直接输出一个ast转换而来的JSON文件
def get_json_from_go_ast(file_path):
    get_go_ast(file_path)
    ast_path = '.'.join(file_path.split('.')[:-1]) + ".ast"
    info = convert_ast_to_json(ast_path)
    os.remove(ast_path)
    return info


# 输入go工程文件夹，提取其内部所有go文件的AST树，转换成JSON，并提取所有JSON的关键信息并存储
def get_key_info_from_project_folder(directory):
    project_info = {
        "imports": [],
        "functions": [],
        "scope_objects": {},
        "calls": [],
        "string": []
    }

    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_path.split('.')[-1] == "go":
                info = get_json_from_go_ast(file_path)
                project_info["imports"].extend(info["imports"])
                project_info["functions"].extend(info["functions"])
                project_info["calls"].extend(info["calls"])
                project_info["string"].extend(info["string"])
                project_info["scope_objects"].update(info["scope_objects"])
    print("已整合所有代码关键信息...")
    return json.dumps(project_info, indent=4)


# 选择Go项目文件夹 进行处理，得到
def get_info_from_project(folder_selected=None):
    json_data = None
    if not folder_selected:
        root = tk.Tk()
        root.withdraw()  # Hide the main tkinter window
        folder_selected = r''+filedialog.askdirectory()
    if folder_selected:
        json_data = get_key_info_from_project_folder(folder_selected)
        print(f"已处理完项目: {folder_selected}")
    else:
        print("未选择文件夹")
    return json_data, folder_selected


# 测试用例，指定go文件，生成原生ast文件
# get_go_ast("test.go")