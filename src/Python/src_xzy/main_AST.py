from GenerateAST import process_directory
from PatternMatch import analyze_patterns

def main():
    # 设置要处理的目录路径
    directory_path = './directory_to_scan'

    # 处理目录中的所有 Python 文件
    ast_files = process_directory(directory_path)

    # 对每个生成的 AST 文件进行模式分析
    for ast_file in ast_files:
        analyze_patterns(ast_file)

if __name__ == "__main__":
    main()
