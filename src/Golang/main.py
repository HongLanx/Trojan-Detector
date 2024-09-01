import subprocess
import tkinter as tk
from tkinter import filedialog
import GoASTConverter
import os


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
    GoASTConverter.convert_ast_to_json(ast_path)


def get_json_from_folder(directory):
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_path.split('.')[-1] == "go":
                get_json_from_go_ast(file_path)


def select_directory():
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        get_json_from_folder(folder_selected)
        print(f"Processing completed for folder: {folder_selected}")
    else:
        print("No folder selected.")


select_directory()
# get_go_ssa('test.go')
