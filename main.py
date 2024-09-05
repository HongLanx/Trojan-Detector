import src.Golang.ast_get_report
import src.Golang.ssa_get_report
import src.Golang.machine_learning_get_report

import src.Python.process.ast_get_report
import src.Python.process.bfm_get_report

import src.java.new
import src.java.vector
import src.java.typeCode

# 前端公共API
def detect_trojan(folder_path=None, language=None, method=None, is_html=False):
    if folder_path and language and method:
        if language == "Go":
            if method == "AST模式匹配":
                src.Golang.ast_get_report.output_ast_matching_report(folder_path)
            elif method == "中间代码转换":
                src.Golang.ssa_get_report.output_ssa_matching_report(folder_path,is_html)
            elif method == "代码向量化/机器学习":
                src.Golang.machine_learning_get_report.output_machine_learning_matching_report(folder_path, is_html)
            else:
                print("未选择检测方法！")

        elif language == "Python":
            if method == "AST模式匹配":
                src.Python.process.ast_get_report.AST(folder_path)
            elif method == "中间代码转换":
                src.Python.process.bfm_get_report.BFM(folder_path)
            elif method == "代码向量化/机器学习":
                print("待调用")
            else:
                print("未选择检测方法！")
                
        elif language == "Java":
            if method == "AST模式匹配":
                src.java.new.select_and_process_project(folder_path)
            elif method == "中间代码转换":
                src.java.typeCode.analyze_java_files(folder_path)
            elif method == "代码向量化/机器学习":
                src.java.vector.detect_malicious_code(folder_path)
            else:
                print("未选择检测方法！")
        else:
            print("未选择语言！")

