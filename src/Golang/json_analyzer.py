import json

# 提取JSON中的Import、自定义函数、作用域对象、函数调用、字符串
def extract_key_info(ast_json):
    with open(ast_json, 'r', encoding='utf-8') as file:
        data = json.load(file)

    print(f"正在提取{ast_json}信息")
    # 初始化结果字典
    results = {
        "imports": [],
        "functions": [],
        "scope_objects": {},
        "calls": [],
        "string": []
    }

    ast_file = data["*ast.File"]

    results["calls"].extend(extract_function_calls(ast_file))

    results["string"].extend(extract_strings(ast_file))
    # 提取声明部分
    if "Decls:" in ast_file:
        decls = ast_file["Decls:"]
        for key, decl in decls.items():
            # 确保decl是一个字典
            if isinstance(decl, dict):
                # 提取导入列表
                if decl.get("Tok") == "import":
                    specs = decl.get("Specs:", {})
                    for spec_key, spec in specs.items():
                        if isinstance(spec, dict) and "Path:" in spec:
                            path = spec["Path:"].get("Value", "")
                            results["imports"].append(path.strip("\\"))

                if "Name:" in decl:
                    name_section = decl["Name:"]
                    if "Obj:" in name_section and name_section["Obj:"]["Kind"] == "func":
                        func_name = name_section["Name"]
                        func_position = name_section.get("NamePos", "Unknown position")
                        results["functions"].append({
                            "name": func_name,
                            "position": func_position.split('\\')[-1]
                        })

    # 检查是否存在Scope部分
    if "Scope:" in ast_file:
        scope = ast_file["Scope:"]
        if "Objects:" in scope:
            objects = scope["Objects:"]
            for obj_name, obj_ref in objects.items():
                # 去除引号
                clean_name = obj_name.strip('"')
                results["scope_objects"][clean_name] = obj_ref

    return results

def extract_full_function_name(func_node):
    """递归提取函数全名，包括处理嵌套的选择器。"""
    if "X:" in func_node:
        if "Sel:" in func_node:
            base_name = extract_full_function_name(func_node["X:"])
            return f"{base_name}.{func_node['Sel:']['Name']}"
        else:
            base_name = extract_full_function_name(func_node["X:"])
            return f"{base_name}"
    elif "Name" in func_node:
        return func_node["Name"]
    elif "Elt:" in func_node:
        if "Name" in func_node["Elt:"]:
            return func_node["Elt:"]["Name"]

    return "Unknown"


def extract_args(args_node):
    """递归解析参数节点，参数也可能是复杂的表达式或函数调用。"""
    args = []
    for key, arg in args_node.items():
        if "Name" in arg:
            args.append(arg["Name"])
        elif "Fun:" in arg:
            # 如果参数本身是一个函数调用，递归提取函数调用信息
            func_call = extract_function_calls(arg)
            args.append(func_call)
    return args


def extract_function_calls(node):
    """递归遍历AST节点，提取所有函数调用。"""
    calls = []
    if isinstance(node, dict):
        if "Fun:" in node:
            func = node["Fun:"]
            func_name = extract_full_function_name(func)
            args = extract_args(node.get("Args:", {}))
            calls.append({
                "function": func_name,
                "arguments": args,
                "location": func.get('NamePos',
                                     func.get('X:', {}).get('NamePos',
                                                            func.get('Sel:', {}).get('NamePos',
                                                                                     func.get("Elt:", {}).get('NamePos',
                                                                                                              'Unknown position')))).split(
                    '\\')[-1]
            })
        # 递归搜索所有子节点
        for key, value in node.items():
            calls.extend(extract_function_calls(value))
    elif isinstance(node, list):
        for item in node:
            calls.extend(extract_function_calls(item))
    return calls


def extract_strings(node, extracted_strings=None):
    """递归遍历AST节点，提取所有带有特定格式的字符串值。"""
    if extracted_strings is None:
        extracted_strings = []

    if isinstance(node, dict):
        # 检查是否含有带双反斜杠的字符串
        if "Value" in node and isinstance(node["Value"], str):
            value = node["Value"]
            if value.startswith("\\") and value.endswith("\\"):
                extracted_strings.append(value.strip('\\').replace('\\\\\\\\', '\\'))
        # 递归搜索所有子节点
        for value in node.values():
            extract_strings(value, extracted_strings)
    elif isinstance(node, list):
        for item in node:
            extract_strings(item, extracted_strings)

    return extracted_strings


# # 使用脚本提取信息
# info = extract_key_info('test2.json')
# print(json.dumps(info, indent=4))
