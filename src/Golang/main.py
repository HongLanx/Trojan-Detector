import os
import get_score
import get_ssa
import go_analyzer_ast
import patterns
import os
import tkinter as tk
from tkinter import filedialog

from ssa_analyzer import generate_JSON

# #测试用例:选择项目目录下的test文件夹即可进行测试
# print(f"僵尸网络评分: {get_score.get_score_from_info(go_analyzer_ast.ast_select_project_folder(),patterns.botnet_patterns)}")

# 测试用例：选择一个文件夹（比如项目下的test文件夹），自动生成ssa（自动安装依赖项）并将所有成功生成的SSA移动到文件夹下的SSAFiles（test/SSAFiles）
# get_ssa.get_ssa_from_folder()

# 对已有的所有病毒样本提取SSA，并提取信息关键信息
# root = tk.Tk()
# root.withdraw()
# folder_selected = filedialog.askdirectory(title="Select A Go Project Folder",
#                                                   initialdir=os.getcwd())
# dirs_1=os.listdir(folder_selected)
# print(folder_selected)
# for directory in dirs_1:
#     dirs_2=os.listdir(os.path.join(folder_selected,directory))
#     for direct in dirs_2:
#         get_ssa.get_ssa_from_folder(os.path.join(folder_selected,directory,direct))
#         generate_JSON(os.path.join(folder_selected,directory,direct))

