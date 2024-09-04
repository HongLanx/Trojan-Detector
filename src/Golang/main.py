import os
import ast_get_report
from src.Golang import machine_learning_get_report
import ssa_get_report
import ssa_getter
import ast_analyzer
import ast_patterns


from ssa_analyzer import generate_json

#测试用例:选择项目目录下的test文件夹即可进行测试
# print(f"僵尸网络评分: {get_score.get_score_from_info(ast_analyzer.get_info_from_project(), patterns.botnet_patterns)}")

# 测试用例：选择一个文件夹（比如项目下的test文件夹），自动生成ssa（自动安装依赖项）并将所有成功生成的SSA移动到文件夹下的SSAFiles（test/SSAFiles）
# get_ssa.get_ssa_from_folder()


#测试用例 输出ast模式匹配报告
# ast_get_report.output_ast_matching_report()

#测试用例 输出SSA模式匹配报告
# ssa_get_report.output_ssa_matching_report()

#测试用例 输出代码向量化-随机森林模型检测报告
machine_learning_get_report.output_machine_learning_matching_report()