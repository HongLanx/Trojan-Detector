import subprocess
import tkinter as tk
from tkinter import filedialog
import GoASTConverter
import os
import json
import get_score
import patterns


# 输入一个go文件，在其目录输出一个go自带ast库生成的ast文本文件
def get_go_ast(file_path):
    result = subprocess.run(['GolangTool/AstGenerator.exe', file_path], capture_output=True, text=True)


# 输入一个go文件，在其目录输出一个go自带ssa库生成的ssa中间代码
def get_go_ssa(file_path):
    result = subprocess.run(['GolangTool/SSAGenerator.exe', '-build=F', file_path], capture_output=True, text=True)


# 输入一个go文件，在其目录直接输出一个ast转换而来的JSON文件
def get_json_from_go_ast(file_path):
    get_go_ast(file_path)
    ast_path = ''.join(file_path.split('.')[:-1]) + ".ast"
    info = GoASTConverter.convert_ast_to_json(ast_path)
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


def select_directory():
    json_data = None
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        json_data = get_key_info_from_project_folder(folder_selected)
        print(f"已处理完项目: {folder_selected}")
    else:
        print("未选择文件夹")
    return json_data



# 测试用例:选择项目目录下的test文件夹即可进行测试
print(f"僵尸网络评分: {get_score.get_score_from_info(select_directory(),patterns.botnet_patterns)}")

# get_go_ssa('test_encrypted.go')
