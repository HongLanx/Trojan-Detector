import json


def extract_key_info(ast_json):
    with open(ast_json, 'r', encoding='utf-8') as file:
        data = json.load(file)

    # 初始化结果字典
    results = {
        "imports": [],
        "functions": [],
        "constants": [],
        "scope_objects": {}
    }

    ast_file = data["*ast.File"]

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
                            "position": func_position
                        })
                # 提取常量定义
                if decl.get("Tok") == "const":
                    specs = decl.get("Specs:", {})
                    for spec_key, spec in specs.items():
                        if isinstance(spec, dict):
                            names = spec.get("Names:", {})
                            values = spec.get("Values:", {})
                            if "0:" in names and "0:" in values:
                                const_name = names["0:"].get("Name", "")
                                const_value = values["0:"].get("Value", "")
                                results["constants"].append({const_name: const_value.strip("\\")})

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


# 使用脚本提取信息
info = extract_key_info('test1.json')
print(json.dumps(info, indent=4))