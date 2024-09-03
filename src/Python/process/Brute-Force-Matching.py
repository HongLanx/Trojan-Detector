import os
import re
from collections import defaultdict
import patterns  # 导入 patterns.py 模块

# 获取当前脚本所在的文件夹路径
current_folder = os.path.dirname(os.path.abspath(__file__))

# 待检测文件夹地址
folder_path = r"C:\Users\86156\Desktop\share\Trojan-Detector\src\Python\src_zys\Trojan"

# 定义一个函数用于加载所有模式
def load_patterns():
    all_patterns = defaultdict(lambda: defaultdict(dict))
    for category_name, category_patterns in patterns.__dict__.items():
        if isinstance(category_patterns, dict):
            for pattern_type, pattern_dict in category_patterns.items():
                if isinstance(pattern_dict, dict):
                    for pattern, score in pattern_dict.items():
                        all_patterns[category_name][pattern_type][pattern] = score
    return all_patterns

# 定义一个函数用于检测Python文件中的特征
def detect_trojans_in_file(file_path, patterns):
    matches = defaultdict(lambda: defaultdict(int))
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()
        for category, pattern_types in patterns.items():
            for pattern_type, pattern_dict in pattern_types.items():
                for pattern, score in pattern_dict.items():
                    if re.search(re.escape(pattern), file_content):
                        matches[category][pattern_type] += 1
    return matches

# 主程序
def main():
    # 加载所有模式
    all_patterns = load_patterns()

    # 初始化结果统计
    detection_results = defaultdict(lambda: defaultdict(lambda: {"count": 0, "score": 0}))

    # 遍历文件夹中的所有Python文件
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.py'):
                file_path = os.path.join(root, file_name)
                file_matches = detect_trojans_in_file(file_path, all_patterns)
                # 汇总检测结果
                for category, pattern_types in file_matches.items():
                    for pattern_type, count in pattern_types.items():
                        detection_results[category][pattern_type]["count"] += count
                        detection_results[category][pattern_type]["score"] += sum(
                            all_patterns[category][pattern_type][pattern] * count
                            for pattern in all_patterns[category][pattern_type]
                        )

    # 将结果写入当前脚本所在目录下的result.txt文件
    output_file_path = os.path.join(current_folder, "result.txt")
    with open(output_file_path, "w", encoding="utf-8") as result_file:
        result_file.write("检测结果：\n")
        for category, pattern_types in detection_results.items():
            result_file.write(f"\n类别: {category}\n")
            for pattern_type in ["Imports", "Function_Calls", "Strings"]:
                if pattern_type in pattern_types:
                    for pattern, data in all_patterns[category][pattern_type].items():
                        if pattern_types[pattern_type]["count"] > 0:
                            result_file.write(
                                f"类型: {pattern_type}\t| 特征: {pattern:<40}\t| 次数: {pattern_types[pattern_type]['count']}\t| 总分数: {pattern_types[pattern_type]['score']}\n"
                            )

if __name__ == "__main__":
    main()
