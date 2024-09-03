import os
import get_score
import get_ssa
import go_analyzer_ast
import patterns

# #测试用例:选择项目目录下的test文件夹即可进行测试
# print(f"僵尸网络评分: {get_score.get_score_from_info(go_analyzer_ast.ast_select_project_folder(),patterns.botnet_patterns)}")

# 测试用例：选择一个文件夹（比如项目下的test文件夹），自动生成ssa（自动安装依赖项）并将所有成功生成的SSA移动到文件夹下的SSAFiles（test/SSAFiles）
get_ssa.get_ssa_from_folder()
