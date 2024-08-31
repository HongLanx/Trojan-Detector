# detector.py

import re
from patterns import PATTERNS

class CodeDetector:
    def __init__(self, patterns):
        self.patterns = patterns

    def detect(self, code):
        findings = []
        for pattern in self.patterns:
            matches = re.findall(pattern['pattern'], code)  # 使用正则表达式查找匹配项
            if matches:
                findings.append({
                    'name': pattern['name'],
                    'description': pattern['description'],
                    'matches': matches  # 匹配到的内容
                })
        return findings

    def analyze_code_file(self, file_path):
        with open(file_path, 'r') as file:
            code = file.read()  # 读取文件内容
        return self.detect(code)  # 检测文件内容中的恶意模式
