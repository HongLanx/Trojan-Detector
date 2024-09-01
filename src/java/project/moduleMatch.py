import os
import json


class JSONAnomalyDetector:

    def __init__(self, file_path):
        self.file_path = file_path
        self.data = None

    def load_json(self):
        """加载并解析JSON文件"""
        try:
            with open(self.file_path, 'r') as file:
                self.data = json.load(file)
            print(f"JSON文件 '{self.file_path}' 加载完成。")
        except Exception as e:
            print(f"加载JSON文件 '{self.file_path}' 时出错: {e}")

    def analyze_max_depth(self):
        """分析最大嵌套深度，非递归实现"""
        if self.data is None:
            return 0

        max_depth = 0
        stack = [(self.data, 1)]  # 栈保存对象和当前深度

        while stack:
            current_obj, current_depth = stack.pop()
            if isinstance(current_obj, dict):
                for value in current_obj.values():
                    stack.append((value, current_depth + 1))
            elif isinstance(current_obj, list):
                for item in current_obj:
                    stack.append((item, current_depth + 1))
            max_depth = max(max_depth, current_depth)

        return max_depth

    def analyze_string_lengths(self, threshold=200):
        """分析长字符串，非递归实现"""
        if self.data is None:
            return []

        long_strings = []
        stack = [self.data]

        while stack:
            current_obj = stack.pop()
            if isinstance(current_obj, dict):
                for value in current_obj.values():
                    stack.append(value)
            elif isinstance(current_obj, list):
                for item in current_obj:
                    stack.append(item)
            elif isinstance(current_obj, str) and len(current_obj) > threshold:
                long_strings.append(current_obj)

        return long_strings

    def analyze_field_frequencies(self):
        """分析字段频率，非递归实现"""
        if self.data is None:
            return {}

        field_count = {}
        stack = [self.data]

        while stack:
            current_obj = stack.pop()
            if isinstance(current_obj, dict):
                for key, value in current_obj.items():
                    field_count[key] = field_count.get(key, 0) + 1
                    stack.append(value)
            elif isinstance(current_obj, list):
                for item in current_obj:
                    stack.append(item)

        return field_count

    def analyze_uncommon_fields(self, common_fields):
        """检测不常见的字段，非递归实现"""
        if self.data is None:
            return []

        uncommon_fields = []
        stack = [(self.data, '')]

        while stack:
            current_obj, path = stack.pop()
            if isinstance(current_obj, dict):
                for key, value in current_obj.items():
                    full_path = f"{path}.{key}" if path else key
                    if key not in common_fields:
                        uncommon_fields.append(full_path)
                    stack.append((value, full_path))
            elif isinstance(current_obj, list):
                for index, item in enumerate(current_obj):
                    full_path = f"{path}[{index}]"
                    stack.append((item, full_path))

        return uncommon_fields

    def detect_anomalies(self):
        """综合检测异常"""
        # 检测嵌套深度异常
        max_depth = self.analyze_max_depth()
        if max_depth > 10:  # 假设10为异常嵌套深度阈值
            print(f"异常：嵌套深度过深，最大深度为 {max_depth}")

        # 检测长字符串
        long_strings = self.analyze_string_lengths()
        if long_strings:
            print(f"异常：检测到异常长字符串，共 {len(long_strings)} 个")

        # 检测字段频率异常
        field_frequencies = self.analyze_field_frequencies()
        for field, count in field_frequencies.items():
            if count > 50:  # 设定某字段出现超过50次为异常
                print(f"异常：字段 `{field}` 出现频率过高，出现次数为 {count}")

        # 检测不常见字段
        common_fields = ['dependencies', 'plugins', 'scripts', 'repositories']  # 示例常见字段列表
        uncommon_fields = self.analyze_uncommon_fields(common_fields)
        if uncommon_fields:
            print(f"异常：检测到不常见字段，共 {len(uncommon_fields)} 个")
            print(f"不常见字段列表：{uncommon_fields}")


# 主程序
def main(directory_path):
    # 遍历目录中的所有JSON文件
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                print(f"\n开始检测文件: {file_path}")
                detector = JSONAnomalyDetector(file_path)
                detector.load_json()
                detector.detect_anomalies()


if __name__ == "__main__":
    # 替换为您的文件夹路径
    main('E:\python')
