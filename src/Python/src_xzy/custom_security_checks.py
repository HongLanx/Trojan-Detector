import ast
import re


# 引入plugin_Str.py中的检测函数

def hardcoded_bind_all_interfaces(context):
    if context.get("string_val") == "0.0.0.0":
        return {"test_id": "001", "severity": "Medium", "text": "Possible binding to all interfaces."}


RE_WORDS = "(pas+wo?r?d|pass(phrase)?|pwd|token|secrete?)"
RE_CANDIDATES = re.compile(
    "(^{0}$|_{0}_|^{0}_|_{0}$)".format(RE_WORDS), re.IGNORECASE
)


def _report(value):
    return {"test_id": "002", "severity": "Low", "text": f"Possible hardcoded password: '{value}'"}


def hardcoded_password_string(context):
    node = context.get("node")
    if isinstance(node, (ast.Str, ast.Constant)):  # 仅在适当类型时访问 node.s
        if isinstance(node._PySec_parent, ast.Assign):
            for targ in node._PySec_parent.targets:
                if isinstance(targ, ast.Name) and RE_CANDIDATES.search(targ.id):
                    return _report(node.s)
                elif isinstance(targ, ast.Attribute) and RE_CANDIDATES.search(targ.attr):
                    return _report(node.s)
        elif isinstance(node._PySec_parent, ast.Subscript) and RE_CANDIDATES.search(node.s):
            assign = node._PySec_parent._PySec_parent
            if isinstance(assign, ast.Assign) and isinstance(assign.value, (ast.Str, ast.Constant)):
                return _report(assign.value.s)
        elif isinstance(node._PySec_parent, ast.Index) and RE_CANDIDATES.search(node.s):
            assign = node._PySec_parent._PySec_parent._PySec_parent
            if isinstance(assign, ast.Assign) and isinstance(assign.value, (ast.Str, ast.Constant)):
                return _report(assign.value.s)
        elif isinstance(node._PySec_parent, ast.Compare):
            comp = node._PySec_parent
            if isinstance(comp.left, ast.Name):
                if RE_CANDIDATES.search(comp.left.id):
                    if isinstance(comp.comparators[0], (ast.Str, ast.Constant)):
                        return _report(comp.comparators[0].s)
            elif isinstance(comp.left, ast.Attribute):
                if RE_CANDIDATES.search(comp.left.attr):
                    if isinstance(comp.comparators[0], (ast.Str, ast.Constant)):
                        return _report(comp.comparators[0].s)



SIMPLE_SQL_RE = re.compile(
    r"(select\s.*from\s|"
    r"delete\s+from\s|"
    r"insert\s+into\s.*values\s|"
    r"update\s.*set\s)",
    re.IGNORECASE | re.DOTALL,
)


def _check_string(data):
    return SIMPLE_SQL_RE.search(data) is not None


def _evaluate_ast(node):
    wrapper = None
    statement = ""

    if isinstance(node._PySec_parent, ast.BinOp):
        # 简化的实现，假设 utils.concat_string 函数存在
        wrapper = node._PySec_parent
        statement = "..."  # 这里你需要添加适当的逻辑
    elif (
            isinstance(node._PySec_parent, ast.Attribute)
            and node._PySec_parent.attr == "format"
    ):
        if isinstance(node, (ast.Str, ast.Constant)):
            statement = node.s
        wrapper = node._PySec_parent._PySec_parent._PySec_parent
    elif hasattr(ast, "JoinedStr") and isinstance(node._PySec_parent, ast.JoinedStr):
        substrings = [
            child
            for child in node._PySec_parent.values
            if isinstance(child, (ast.Str, ast.Constant))
        ]
        if substrings and node == substrings[0]:
            statement = "".join([str(child.s) for child in substrings])
            wrapper = node._PySec_parent._PySec_parent

    if isinstance(wrapper, ast.Call):
        names = ["execute", "executemany"]
        # 假设 utils.get_called_name 函数存在
        name = "execute"  # 简化示例
        return (name in names, statement)
    else:
        return (False, statement)


def hardcoded_sql_expressions(context):
    val = _evaluate_ast(context.get("node"))
    if _check_string(val[1]):
        return {"test_id": "003", "severity": "Medium", "text": "Possible SQL injection vector through string-based "
                                                                "query construction."}


def run_plugin_str_checks(node):
    """运行所有plugin_Str中的检测功能"""
    context = {"node": node, "string_val": getattr(node, "s", None)}

    result = []
    if hardcoded_bind_all_interfaces(context):
        res = hardcoded_bind_all_interfaces(context)
        result.append(res)
    if hardcoded_password_string(context):
        res = hardcoded_password_string(context)
        result.append(res)
    if hardcoded_sql_expressions(context):
        res = hardcoded_sql_expressions(context)
        result.append(res)

    return result
