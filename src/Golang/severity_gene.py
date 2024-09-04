import json
import random

import inter_patterns_raw


def adjust_values(data):
    new_data = {}
    for key, values in data.items():
        new_data[key] = {}
        for sub_key, value in values.items():
            if value == 2:
                # 针对value为2，随机赋值为2或3，出现次数太少
                new_value = random.randint(5, 6)
            elif value == 1:
                # 对于只出现1次的条目，由于出现次数太少，很难说明什么
                new_value = random.randint(2, 3)
            elif value <= 4:
                # 针对value为3或4，随机赋值为6或7
                new_value = random.randint(6, 7)
            elif value <= 6:
                # 针对value为5或6，赋值为5
                new_value = 5
            elif value <= 8:
                # 针对value为7或8，赋值为3或4
                new_value = random.randint(3, 4)
            else:
                # 对于特别高的值，赋值为0到2
                new_value = random.randint(0, 2)
            new_data[key][sub_key] = new_value
    return new_data


# 调用函数调整value
adjusted_encryption_patterns = adjust_values(inter_patterns_raw.botnet_patterns)


json_output = json.dumps(adjusted_encryption_patterns, indent=4)
print(json_output)