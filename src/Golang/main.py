import os
import ast_get_report
import get_ssa
import ast_analyzer
import patterns
import os
import tkinter as tk
from tkinter import filedialog

from ssa_analyzer import generate_JSON

#测试用例:选择项目目录下的test文件夹即可进行测试
# print(f"僵尸网络评分: {get_score.get_score_from_info(ast_analyzer.ast_select_project_folder(), patterns.botnet_patterns)}")

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

#测试用例 输出ast模式匹配报告
ast_get_report.output_ast_matching_report()