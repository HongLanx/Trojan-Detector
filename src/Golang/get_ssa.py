import shutil
import subprocess
import re
import os
import tkinter as tk
from tkinter import filedialog
import ssa_analyzer

SSA_path = os.path.join(os.getcwd(), "GolangTool/SSAGenerator.exe")


def run_command(command, working_directory=os.getcwd()):
    """在指定的工作目录中运行命令并返回输出和错误。"""
    result=None
    # 保存当前目录
    current_dir = os.getcwd()
    # 更改到指定的工作目录
    os.chdir(working_directory)
    try:
        result = subprocess.run(command, capture_output=True, text=True,encoding='utf-8')
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
        print("No go.mod file selected. Creating a new go.mod file.")
        go_mod_file = os.path.join(module_dir, "go.mod")
        with open(go_mod_file, 'w') as mod_file:
            mod_file.write(f"module TrojanDetector")  # 创建基本的go.mod文件
        run_command(['go', 'mod', 'init', os.path.basename(module_dir)], module_dir)

    go_mod_dir = os.path.dirname(go_mod_file)
    if go_mod_dir != module_dir:
        if not os.path.exists(os.path.join(module_dir, os.path.basename(go_mod_file))):
            shutil.copy(go_mod_file, os.path.join(module_dir, os.path.basename(go_mod_file)))
        go_mod_dir = module_dir

    print(f"Generating SSA for {go_file} using {go_mod_file}")

    print("Running initial SSA Generator...")
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

        print("Running go mod tidy...")
        run_command(['go', 'mod', 'tidy', '-e'], go_mod_dir)

        print("Re-running SSA Generator after dependency resolution...")
        stdout, stderr = run_command([SSA_path, '-build=F', go_file], module_dir)
        print("SSA Generation Complete")

    if stderr and ("could not import" in stderr or "invalid package name" in stderr):
        print("There are still errors with the packages or invalid package names.")
    else:
        print("All dependencies resolved and SSA generated successfully.")

    print(stdout)
    print(stderr)


def choose_go_project_and_generate_ssa(folder_selected=None):
    # 初始化Tk界面
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    if not folder_selected:
        folder_selected = filedialog.askdirectory(title="Select A Go Project Folder",
                                                  initialdir=os.getcwd())  # 初始目录设为当前工作目录

    print("请选择项目go.mod文件")
    # 弹出文件选择对话框，让用户选择一个go.mod文件
    go_mod_file = filedialog.askopenfilename(
        title="Select a go.mod file",
        filetypes=[("Go Mod files", "go.mod")],  # 只允许选择go.mod文件
        initialdir=folder_selected  # 假设go.mod通常与go文件在同一目录
    )
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
def get_ssa_from_folder(folder_to_be_processd=None):
    folder = choose_go_project_and_generate_ssa(folder_to_be_processd)
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
                        print(f"Moved non-empty SSA file: {file_path} to {ssa_dest_folder}")
                    else:
                        os.remove(file_path)  # 删除内容为空的SSA文件（即由于无法安装库等原因，无法正常生成）
