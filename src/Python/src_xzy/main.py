import os
from detector import CodeDetector  # 确保正确导入模块
from patterns import PATTERNS

def scan_directory(directory_path):
    detector = CodeDetector(PATTERNS)
    report = []

    for root, dirs, files in os.walk(directory_path):
        print(f"Scanning directory: {root}")  # 调试信息
        for file in files:
            if file.endswith('.py'):  # 根据需要扫描其他语言的文件
                file_path = os.path.join(root, file)
                print(f"Analyzing file: {file_path}")  # 调试信息
                findings = detector.analyze_code_file(file_path)
                if findings:
                    report.append({
                        'file': file_path,
                        'findings': findings
                    })

    return report

def print_report(report):
    for item in report:
        print(f"File: {item['file']}")
        for finding in item['findings']:
            print(f"  {finding['name']}: {finding['description']}")
            print(f"  Matches: {finding['matches']}")
        print("-" * 80)

if __name__ == "__main__":
    directory_to_scan = './directory_to_scan'  # 替换为实际的目录路径
    report = scan_directory(directory_to_scan)
    print_report(report)
