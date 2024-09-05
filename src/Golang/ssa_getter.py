"""
此脚本主要用于为Go语言项目生成SSA（Static Single Assignment）形式的中间代码，以便进行深入的静态分析。主要功能包括：
1. 自动检测和安装缺失的Go模块依赖项。
2. 使用指定的SSA生成工具（SSAGenerator.exe）来生成Go文件的SSA表示。
3. 提供图形界面选择Go项目文件夹和go.mod文件，以支持SSA生成过程。
4. 自动处理和重试机制，确保在依赖项解决后重新尝试生成SSA。
5. 支持批量处理整个Go项目，将生成的SSA文件收集并存放到指定目录。

"""

import shutil
import subprocess
import re
import os
import tkinter as tk
from tkinter import filedialog
from src.Golang import ssa_analyzer

SSA_path = os.path.join(os.getcwd(), "src/Golang/GolangTool/SSAGenerator.exe")


def run_command(command, working_directory=os.getcwd()):
    """在指定的工作目录中运行命令并返回输出和错误。"""
    result = None
    # 保存当前目录
    current_dir = os.getcwd()
    # 更改到指定的工作目录
    os.chdir(working_directory)
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
    except UnicodeDecodeError:
        print("解码失败")
    finally:
        # 切换回原始工作目录
        os.chdir(current_dir)
    return result.stdout, result.stderr


def generate_ssa(go_file, go_mod_file=None):
    """自动检测缺失的 Go 模块依赖项并安装它们，然后运行 go mod tidy。"""
    module_dir = os.path.dirname(go_file)

    # 检查用户是否选择了文件，如果没有，则在module_dir下创建一个新的go.mod文件
    if not go_mod_file:
        print("未选择go.mod文件，自动在目录下创建新go.mod文件")
        go_mod_file = os.path.join(module_dir, "go.mod")
        if not go_mod_file:
            with open(go_mod_file, 'w') as mod_file:
                mod_file.write(f"module TrojanDetector")  # 创建基本的go.mod文件
            run_command(['go', 'mod', 'init', os.path.basename(module_dir)], module_dir)

    go_mod_dir = os.path.dirname(go_mod_file)
    if go_mod_dir != module_dir:
        if not os.path.exists(os.path.join(module_dir, os.path.basename(go_mod_file))):
            shutil.copy(go_mod_file, os.path.join(module_dir, os.path.basename(go_mod_file)))
        go_mod_dir = module_dir

    print(f"生成 {go_file} 的SSA中间代码，使用依赖项为 {go_mod_file}")

    print("正在第一次尝试生成SSA...")
    stdout, stderr = run_command([SSA_path, '-build=F', go_file], module_dir)

    if stderr and ("no required module provides package" or "missing go.sum entry" in stderr):
        missing_packages = re.findall(r"no required module provides package (.+?);", stderr)
        missing_imports = re.findall(r'go mod download ([\w\.\-\/@]+)', stderr)
        if missing_imports or missing_packages:
            print("发现有模块缺失，正在下载...")
        for package in missing_packages:
            print(f"安装缺失依赖包: {package}")
            install_stdout, install_stderr = run_command(['go', 'get', package], module_dir)
            print(install_stdout)
            print(install_stderr)

        for package in missing_imports:
            print(f"尝试下载缺失依赖模块: {package}")
            install_stdout, install_stderr = run_command(['go', 'mod', 'download', package], module_dir)
            print(install_stdout)
            print(install_stderr)

        print("运行指令： go mod tidy...")
        run_command(['go', 'mod', 'tidy', '-e'], go_mod_dir)

        print("依赖项已自动安装，正在第二次尝试生成SSA...")
        stdout, stderr = run_command([SSA_path, '-build=F', go_file], module_dir)
        print("SSA生成完成")

    if stderr and ("could not import" in stderr or "invalid package name" in stderr):
        print("依赖包仍有错误，或仍然缺失")
    else:
        print("全部依赖项已安装，SSA已经生成")

    print(stdout)
    print(stderr)


def choose_go_project_and_generate_ssa(folder_selected=None, is_html=False):
    if not is_html:
        # 初始化Tk界面
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        if not folder_selected:
            folder_selected = filedialog.askdirectory(title="选择Go项目目录",
                                                      initialdir=os.getcwd())  # 初始目录设为当前工作目录

        print("请选择项目go.mod文件")
        # 弹出文件选择对话框，让用户选择一个go.mod文件
        go_mod_file = filedialog.askopenfilename(
            title="选择项目的go.mod依赖项文件",
            filetypes=[("Go Mod files", "go.mod")],  # 只允许选择go.mod文件
            initialdir=folder_selected  # 假设go.mod通常与go文件在同一目录
        )
    else:
        if not folder_selected:
            folder_selected = filedialog.askdirectory(title="选择Go项目目录",
                                                      initialdir=os.getcwd())  # 初始目录设为当前工作目录
        go_mod_file = None
    if folder_selected:
        for root, _, files in os.walk(folder_selected):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if file_path.split('.')[-1] == "go":
                    generate_ssa(file_path, go_mod_file)
        print(f"已处理完项目: {folder_selected}")
    else:
        print("未选择文件夹")

    return folder_selected


# 选择项目文件夹，生成ssa文件，再将所有ssa文件取出，移动到所选项目根目录下的./SSAFiles文件夹
def get_ssa_from_folder(folder_to_be_processd=None, is_html=False):
    folder = choose_go_project_and_generate_ssa(folder_to_be_processd, is_html)
    if folder:
        ssa_dest_folder = os.path.join(folder, "SSAFiles")
        if not os.path.exists(ssa_dest_folder):
            os.makedirs(ssa_dest_folder)
        for root, _, files in os.walk(folder):
            for file_name in files:
                if file_name.endswith(".ssa"):
                    file_path = os.path.join(root, file_name)
                    if os.path.getsize(file_path) > 0:  # Check if file is not empty
                        # Move non-empty .ssa files to the specified destination folder
                        shutil.move(file_path, os.path.join(ssa_dest_folder, file_name))
                        print(f"移动非空SSA文件: {file_path} 到 {ssa_dest_folder}")
                    else:
                        os.remove(file_path)  # 删除内容为空的SSA文件（即由于无法安装库等原因，无法正常生成）

    return folder
