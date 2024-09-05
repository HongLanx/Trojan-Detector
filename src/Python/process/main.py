import os
from BruteForceMatching import BFM  # 假设你将函数存储在 your_module.py 中
from AST import AST

def main():
    # 从用户输入获取待检测文件夹路径
    folder_path = input("请输入待检测的Python文件夹路径：")
    
    # 检查文件夹路径是否有效
    if not os.path.isdir(folder_path):
        print("无效的文件夹路径，请重新输入一个有效的路径。")
        return
    
    # 调用检测函数
    #BFM(folder_path)
    
    # 直接调用 AST 函数进行预处理和检测，不需要处理返回值
    AST(folder_path)

    print("检测完成。")

if __name__ == "__main__":
    main()
