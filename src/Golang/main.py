import os
import get_score
import get_ssa
import go_analyzer_ast
import patterns

# #测试用例:选择项目目录下的test文件夹即可进行测试
# print(f"僵尸网络评分: {get_score.get_score_from_info(go_analyzer_ast.ast_select_project_folder(),patterns.botnet_patterns)}")

# 测试用例：生成ssa（自动安装依赖项）
get_ssa.choose_go_project_and_generate_ssa()
