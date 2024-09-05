import os
import re
from collections import defaultdict
import patterns  # 导入 patterns.py 模块

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
def detect_trojans_in_file(file_path, patterns, matched_patterns):
    matches = defaultdict(lambda: defaultdict(lambda: {"exact": 0, "fuzzy": 0}))
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()

        for category, pattern_types in patterns.items():
            for pattern_type, pattern_dict in pattern_types.items():
                for pattern, score in pattern_dict.items():
                    if pattern_type == "Imports":
                        if re.search(r'\b' + re.escape(pattern) + r'\b', file_content) and pattern not in matched_patterns[category][pattern_type]:
                            matches[category][(pattern_type, pattern)]["exact"] = 1
                            matched_patterns[category][pattern_type].add(pattern)
                    elif pattern_type == "Function_Calls":
                        match_count = len(re.findall(r'\b' + re.escape(pattern) + r'\b', file_content))
                        if match_count > 0:
                            if pattern not in matched_patterns[category][pattern_type]:
                                matches[category][(pattern_type, pattern)]["exact"] = 1
                                matches[category][(pattern_type, pattern)]["fuzzy"] = match_count - 1
                                matched_patterns[category][pattern_type].add(pattern)
                            else:
                                matches[category][(pattern_type, pattern)]["fuzzy"] += match_count
                    elif pattern_type == "Strings":
                        exact_matches = len(re.findall(r'\b' + re.escape(pattern) + r'\b', file_content))
                        fuzzy_matches = len(re.findall(re.escape(pattern), file_content)) - exact_matches
                        matches[category][(pattern_type, pattern)]["exact"] += exact_matches
                        matches[category][(pattern_type, pattern)]["fuzzy"] += fuzzy_matches
    return matches

# 定义主函数
def BFM(folder_path):
    # 加载所有模式
    all_patterns = load_patterns()

    # 初始化结果统计
    detection_results = defaultdict(lambda: defaultdict(lambda: {"count": 0, "score": 0}))
    category_total_scores = defaultdict(int)
    matched_patterns = defaultdict(lambda: defaultdict(set))  # 用于存储已经匹配过的模式

    folder_name = os.path.basename(os.path.normpath(folder_path))

    # 遍历文件夹中的所有Python文件
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.py'):
                file_path = os.path.join(root, file_name)
                file_matches = detect_trojans_in_file(file_path, all_patterns, matched_patterns)
                # 汇总检测结果
                for category, patterns in file_matches.items():
                    for (pattern_type, pattern), match_counts in patterns.items():
                        score = all_patterns[category][pattern_type][pattern]
                        if pattern_type == "Imports":
                            if match_counts["exact"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += 1
                                detection_results[category][(pattern_type, pattern)]["score"] += score
                                category_total_scores[category] += score
                        elif pattern_type == "Function_Calls":
                            if match_counts["exact"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += match_counts["exact"]
                                detection_results[category][(pattern_type, pattern)]["score"] += score
                                category_total_scores[category] += score
                            if match_counts["fuzzy"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += match_counts["fuzzy"]
                                detection_results[category][(pattern_type, pattern)]["score"] += match_counts["fuzzy"]
                                category_total_scores[category] += match_counts["fuzzy"]
                        elif pattern_type == "Strings":
                            if match_counts["exact"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += match_counts["exact"]
                                detection_results[category][(pattern_type, pattern)]["score"] += score * match_counts["exact"]
                                category_total_scores[category] += score * match_counts["exact"]
                            if match_counts["fuzzy"] > 0:
                                detection_results[category][(pattern_type, pattern)]["count"] += match_counts["fuzzy"]
                                detection_results[category][(pattern_type, pattern)]["score"] += (score - 5) * match_counts["fuzzy"]
                                category_total_scores[category] += (score - 5) * match_counts["fuzzy"]

    max_category = max(category_total_scores, key=category_total_scores.get)
    max_score = category_total_scores[max_category]

    output_file_name = f"{folder_name}_BFM_results.txt"
    output_file_path = os.path.join(folder_path, output_file_name)

    with open(output_file_path, "w", encoding="utf-8") as result_file:
        result_file.write("检测结果：\n")
        for category, patterns in detection_results.items():
            result_file.write(f"\n类别: {category}\n")
            for pattern_type in ["Imports", "Function_Calls", "Strings"]:
                for (ptype, pattern), data in patterns.items():
                    if ptype == pattern_type and data["count"] > 0:
                        result_file.write(
                            f"特征: {pattern:<40} | 次数: {data['count']:<5} | 总分数: {data['score']:<5}\n"
                        )
            result_file.write(f"类别总分: {category_total_scores[category]}\n")
        result_file.write(f"\n检测出的病毒木马类别为: {max_category}，总得分: {max_score}\n")

    print(f"检测结果已写入: {output_file_path}")

