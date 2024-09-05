import os
import json

def get_folder_size_in_kb(folder_path):
    """
    获取整个文件夹的大小，单位为KB
    """
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size / 1024  # 转换为KB

def get_total_severity(result_file_path, detection_type):
    """
    从检测结果中获取总评分
    - AST: Dominant Malicious Code Type:xxx  (Total Severity: xx)
    - BFM: 检测出的病毒木马类别为: xxx，总得分: xx
    """
    total_severity = 0
    with open(result_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

        if not lines:
            return total_severity

        last_line = lines[-1].strip()
        
        if detection_type == "AST" and "Total Severity" in last_line:
            total_severity = float(last_line.split("Total Severity:")[1].strip().strip(')'))
        elif detection_type == "BFM" and "总得分" in last_line:
            total_severity = float(last_line.split("总得分:")[1].strip())

    return total_severity

def get_detection_results(result_file_path, folder_path, threshold, detection_type):
    """
    根据总评分/文件夹大小的值来判断文件夹是否为恶意
    """
    total_severity = get_total_severity(result_file_path, detection_type)
    folder_size_kb = get_folder_size_in_kb(folder_path)  # 获取文件夹总大小

    score_per_kb = total_severity / folder_size_kb  # 用文件夹大小来计算

    if score_per_kb > threshold:
        return "Malicious"
    else:
        return "Non-Malicious"

def calculate_metrics(results, ground_truth, total_malicious, total_non_malicious):
    """
    计算TP, FP, TN, FN以及准确率和误报率，同时记录漏报的恶意文件
    :param results: 检测算法的输出结果 (预测的类别)
    :param ground_truth: 实际的标签 (真实的类别)
    :param total_malicious: ground_truth 中标记的恶意文件总数
    :param total_non_malicious: ground_truth 中标记的正常文件总数
    :return: 准确率、误报率以及漏报的恶意文件列表
    """
    TP = FP = TN = FN = 0
    undetected_malicious_files = []  # 记录漏报的文件

    for folder_name, predicted_category in results.items():
        actual_category = ground_truth.get(folder_name, "Non-Malicious")
        
        if actual_category == "Malicious" and predicted_category == "Malicious":
            TP += 1  # 真正例：正确检测为恶意
        elif actual_category == "Non-Malicious" and predicted_category == "Non-Malicious":
            TN += 1  # 真负例：正确检测为正常
        elif actual_category == "Non-Malicious" and predicted_category == "Malicious":
            FP += 1  # 假正例：误报
        elif actual_category == "Malicious" and predicted_category == "Non-Malicious":
            FN += 1  # 假负例：漏报
            undetected_malicious_files.append(folder_name)  # 记录漏报的恶意文件夹
    
    # 使用 total_malicious + total_non_malicious 作为准确率的分母
    accuracy = (TP + TN) / (total_malicious + total_non_malicious)

    # 使用 total_non_malicious 作为误报率的分母
    false_positive_rate = FP / total_non_malicious if total_non_malicious > 0 else 0.0

    return {
        "TP": TP,
        "FP": FP,
        "TN": TN,
        "FN": FN,
        "Accuracy": round(accuracy, 2),  # 保留两位小数
        "False Positive Rate": round(false_positive_rate, 2),  # 保留两位小数
        "Undetected Malicious": undetected_malicious_files  # 漏报的恶意文件
    }

def get_ground_truth(ground_truth_file):
    """
    加载实际标签（真实的类别）
    """
    with open(ground_truth_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def process_folder(main_folder_path, threshold, detection_type):
    """
    处理主文件夹，获取子文件夹中的检测结果并计算准确率和误报率
    :param main_folder_path: 主文件夹路径
    :param threshold: 恶意评分阈值
    :param detection_type: 检测类型（AST或BFM）
    """
    ground_truth_file = os.path.join(main_folder_path, "ground_truth.json")
    ground_truth = get_ground_truth(ground_truth_file)

    detection_results = {}

    # 计算 ground truth 中的恶意和正常项目总数
    total_malicious = sum(1 for v in ground_truth.values() if v == "Malicious")
    total_non_malicious = sum(1 for v in ground_truth.values() if v == "Non-Malicious")

    for sub_folder_name in os.listdir(main_folder_path):
        sub_folder_path = os.path.join(main_folder_path, sub_folder_name)
        if os.path.isdir(sub_folder_path):
            result_file_name = f"{sub_folder_name}_{detection_type}_results.txt"
            result_file_path = os.path.join(sub_folder_path, result_file_name)
            
            if os.path.exists(result_file_path):
                detection_results[sub_folder_name] = get_detection_results(result_file_path, sub_folder_path, threshold, detection_type)

    metrics = calculate_metrics(detection_results, ground_truth, total_malicious, total_non_malicious)
    
    return metrics, total_malicious, total_non_malicious

if __name__ == "__main__":
    main_folder_path = input("请输入主文件夹路径: ")

    if not os.path.exists(main_folder_path):
        print("输入的主文件夹路径不存在，请检查后重试。")
        exit()

    detection_type = input("请输入检测类型 (AST 或 BFM): ").upper()

    if detection_type == "AST":
        threshold = 0.1
    elif detection_type == "BFM":
        threshold = 0.3
    else:
        print("输入有误，仅支持AST或BFM。")
        exit()

    metrics, total_malicious, total_non_malicious = process_folder(main_folder_path, threshold, detection_type)

    tp = metrics['TP']
    fp = metrics['FP']
    tn = metrics['TN']
    fn = metrics['FN']
    accuracy = metrics['Accuracy']
    false_positive_rate = metrics['False Positive Rate']
    undetected_malicious_files = metrics['Undetected Malicious']  # 获取漏报的恶意文件

    print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
    print(f"{detection_type} 检测算法运行后，有{tp}个病毒项目被检测到（共{total_malicious}个），有{fp}个正常项目被误伤（共{total_non_malicious}个）。")
    print(f"{detection_type} 检测算法的准确率为：{accuracy:.2f}，误报率为：{false_positive_rate:.2f}。")

    if undetected_malicious_files:
        print(f"以下文件被标记为恶意但未检测到：")
        for file in undetected_malicious_files:
            print(f"- {file}")
