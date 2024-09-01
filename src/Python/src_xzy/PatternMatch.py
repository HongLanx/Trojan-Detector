import ast
import pickle

class PatternAnalyzer(ast.NodeVisitor):
    def visit_Call(self, node):
        # 检查是否有 exec() 函数调用
        if isinstance(node.func, ast.Name) and node.func.id == "exec":
            print(f"Suspicious exec call at line {node.lineno}")
        # 继续遍历其他节点
        self.generic_visit(node)

def analyze_patterns(ast_tree_file):
    # 从文件中加载 AST 树
    with open(ast_tree_file, 'rb') as file:
        tree = pickle.load(file)

    # 创建并运行模式分析器
    analyzer = PatternAnalyzer()
    analyzer.visit(tree)
