"""
该脚本是SSA（Static Single Assignment）代码分析的一部分，用于计算两个Go语言SSA文件之间的语义相似性。主要功能如下：
1. 读取和解析SSA代码文件，提取其中的函数和相关代码块。
2. 使用Word2Vec模型，训练提取的代码块上的词向量，以捕获代码块中的语义信息。
3. 将每个代码块转换为向量表示，通过计算均值向量来聚合一个代码块中所有单词的向量。
4. 使用余弦相似性度量来比较两个SSA文件中代码块的向量表示，从而评估它们之间的语义相似性。
5. 输出两个文件间代码块的平均相似度，以量化两段代码的语义接近程度。

注意：由于语义相似度匹配效果不佳，且难以用于匹配整个项目
该代码未用于最终演示版本，但保留源码，期待未来有机会能实现这个方法
"""

import re
import numpy as np
from gensim.models import Word2Vec
from sklearn.metrics.pairwise import cosine_similarity

def process_ssa_code_from_file(file_path):
    # 读取文件内容
    with open(file_path, 'r',encoding='utf-8') as file:
        ssa_code = file.read()

    # 将 SSA 代码按行分割
    lines = ssa_code.strip().splitlines()

    # 初始化结果数组
    functions = []
    current_function = None
    current_block = None

    for line in lines:
        if line.startswith("func "):
            if current_function is not None and current_block is not None:
                current_function["blocks"].append(current_block)
                functions.append(current_function)
            current_function = {
                "name": line.strip(),
                "blocks": []
            }
            current_block = None
        elif re.match(r'\d+:', line):
            if current_block is not None:
                current_function["blocks"].append(current_block)
            current_block = ""
        elif current_block is not None and line.strip():
            trimmed_line = re.split(r'\s{2,}|\n', line.strip())[0]
            if "=" in trimmed_line:
                current_block += trimmed_line + "\n"
    if current_function is not None and current_block is not None:
        current_function["blocks"].append(current_block)
        functions.append(current_function)
    return functions

def train_word2vec(sentences, num_iterations=5):
    models = []
    for _ in range(num_iterations):
        np.random.seed(42)
        model = Word2Vec(sentences, vector_size=100, window=5, min_count=1, workers=4)
        models.append(model)
    return models

def vectorize_blocks(blocks, models):
    vectors = []
    for block in blocks:
        block_vectors = []
        for model in models:
            block_words = block.split()
            word_vectors = [model.wv[word] for word in block_words if word in model.wv]
            if word_vectors:
                block_vector = np.mean(word_vectors, axis=0)
                block_vectors.append(block_vector)
        if block_vectors:
            final_vector = np.mean(block_vectors, axis=0)
            vectors.append(final_vector)
    return vectors

def compute_similarity(vectors1, vectors2):
    vectors1 = [vec for vec in vectors1 if vec is not None]
    vectors2 = [vec for vec in vectors2 if vec is not None]
    similarity_matrix = cosine_similarity(np.array(vectors1), np.array(vectors2))
    return np.mean(similarity_matrix)

# 示例用法
file_path1 = r"Constants.ssa"
file_path2 = r"FormatLog.ssa"

functions1 = process_ssa_code_from_file(file_path1)
functions2 = process_ssa_code_from_file(file_path2)

sentences = [block.split() for func in functions1 for block in func['blocks']] + \
            [block.split() for func in functions2 for block in func['blocks']]

models = train_word2vec(sentences, num_iterations=10)

vectors1 = vectorize_blocks([block for func in functions1 for block in func['blocks']], models)
vectors2 = vectorize_blocks([block for func in functions2 for block in func['blocks']], models)

average_similarity = compute_similarity(vectors1, vectors2)

print(f"Average Similarity: {average_similarity}")
