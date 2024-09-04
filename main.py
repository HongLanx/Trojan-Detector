import src.Golang.ast_get_report
import src.Golang.ssa_get_report
import src.Golang.machine_learning_get_report

def detect_trojan(folder_path=None, language=None, method=None):
    if folder_path and language and method:
        if language=="Go":
            if method=="Pattern Matching":
                src.Golang.ast_get_report.output_ast_matching_report(folder_path)
            elif method == "Intermediate Language Transformation":
                src.Golang.ssa_get_report.output_ssa_matching_report(folder_path)
            elif method == "Vector Transformation":
                src.Golang.machine_learning_get_report.output_machine_learning_matching_report(folder_path)
            else:
                print("No Method Choosed!")
        elif language=="Python":
            if method == "Pattern Matching":
                print("待调用")
            elif method == "Intermediate Language Transformation":
                print("待调用")
            elif method == "Vector Transformation":
                print("待调用")
            else:
                print("No Method Choosed!")
        elif language=="Java":
            if method == "Pattern Matching":
                print("待调用")
            elif method == "Intermediate Language Transformation":
                print("待调用")
            elif method == "Vector Transformation":
                print("待调用")
            else:
                print("No Method Choosed!")
        else:
            print("No Language Choosed")
