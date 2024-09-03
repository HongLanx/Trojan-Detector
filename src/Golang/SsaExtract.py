import re


def process_ssa_code_from_file(file_path):
    # 读取文件内容
    with open(file_path, 'r') as file:
        ssa_code = file.read()

    # 将 SSA 代码按行分割
    lines = ssa_code.strip().splitlines()

    # 初始化结果数组
    functions = []

    # 初始化当前处理的函数和代码块
    current_function = None
    current_block = None

    for line in lines:
        # 匹配函数定义行
        if line.startswith("func "):
            # 如果当前有正在处理的函数，先将其加入函数数组中
            if current_function is not None:
                functions.append(current_function)

            # 初始化新的函数对象
            current_function = {
                "name": line.strip(),  # 保留函数定义行作为函数名
                "blocks": []  # 初始化代码块数组
            }
            current_block = None

        # 检查代码块的开始
        elif re.match(r'\d+:', line):
            # 如果当前有正在处理的代码块，先将其加入代码块数组中
            if current_block is not None:
                current_function["blocks"].append(current_block)

            # 初始化新的代码块
            current_block = ""

        elif current_block is not None and line.strip():
            # 处理代码块中的行，提取直到遇到连续两个及以上空格为止的字符串
            # 并且只保留包含等号的行
            if '=' in line:
                trimmed_line = re.split(r'\s{2,}', line.strip())[0]
                # 将处理后的结果加入当前代码块，并添加换行符
                current_block += trimmed_line + "\n"

    # 最后一个代码块需要手动添加到当前函数中
    if current_block is not None:
        current_function["blocks"].append(current_block)

    # 最后一个函数需要手动添加到函数数组中
    if current_function is not None:
        functions.append(current_function)

    return functions


# 示例用法：传入文件路径
file_path = r"D:\xiaoxueqi\Trojan-Detector\src\Golang\test.ssa"
result = process_ssa_code_from_file(file_path)

# 打印结果
for func in result:
    print("Function:", func["name"])
    print("Processed Blocks:")
    for block in func["blocks"]:
        print(block)
    print()

from gensim.models import Word2Vec
import numpy as np


def preprocess_code_blocks(code_blocks):
    """
    预处理代码块，将每行代码分割成词列表。
    """
    return [line.split() for block in code_blocks for line in block]


def train_word2vec_model(sentences, vector_size=100, window=5, min_count=1):
    """
    训练 Word2Vec 模型。
    """
    model = Word2Vec(sentences=sentences, vector_size=vector_size, window=window, min_count=min_count, workers=4)
    return model


def vectorize_code_block(model, block):
    """
    将代码块中的每行代码向量化，并计算整个代码块的向量表示。
    """
    block_vectors = []
    for line in block:
        line_vector = np.mean([model.wv[word] for word in line.split() if word in model.wv], axis=0)
        block_vectors.append(line_vector)

    # 代码块向量可以通过平均或其他方式组合所有行的向量
    block_vector = np.mean(block_vectors, axis=0)
    return block_vector


# 示例用法

# 假设 `result` 是之前处理后的包含代码块的结果
code_blocks = [func['blocks'] for func in result]

# 预处理代码块文本，生成词列表
sentences = preprocess_code_blocks(code_blocks)

print("Preprocessed Code Blocks (Word Lists):")
for sentence in sentences:
    print(sentence)

# 训练 Word2Vec 模型
word2vec_model = train_word2vec_model(sentences)

# 为每个代码块生成向量
code_block_vectors = [vectorize_code_block(word2vec_model, block) for block in code_blocks]

# 打印结果
for i, vec in enumerate(code_block_vectors):
    print(f"Code Block {i + 1} Vector:\n", vec)
