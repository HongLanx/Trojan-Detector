import os
from preprocess import turnToJson  # 从 preprocess.py 中导入函数
from matchAndScore import get_score  # 从 matchAndScore.py 中导入函数

def AST(folder_path):
    """
    封装 preprocess.py 和 matchAndScore.py 的功能到一个函数中。
    该函数先进行预处理，再进行模式匹配和得分计算。
    """
    try:
        # 第一步：预处理，生成包含关键信息的 JSON 文件
        print("正在预处理文件...")
        json_file_path = turnToJson(folder_path)
        print(f"预处理完成，生成的 JSON 文件路径为: {json_file_path}")
        
        # 第二步：使用 matchAndScore.py 中的检测功能进行模式匹配和得分计算
        print("正在进行模式匹配和得分计算...")
        get_score(folder_path)  # 直接调用匹配和得分函数，不需要返回值
        print(f"模式匹配和得分计算完成。")
        
    except Exception as e:
        print(f"执行过程中发生错误: {e}")
