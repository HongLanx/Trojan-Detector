import os
import subprocess
import socket

# 1. 绑定到所有接口（0.0.0.0）
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 8080))  # 可能的绑定到所有接口

# 2. 硬编码密码
password = "SuperSecret123!"  # 可能的硬编码密码
api_key = "APIKEY12345"

# 3. 不安全的函数调用
exec("print('This is unsafe!')")  # 可能的exec函数调用
eval("2 + 2")  # 可能的eval函数调用

# 4. 不安全的模块导入
os.system("rm -rf /")  # 可能的命令执行
subprocess.call(["ls", "-l"])  # 可能的命令执行

# 5. SQL 注入
user_input = "'; DROP TABLE users; --"
query = "SELECT * FROM users WHERE username = '" + user_input + "'"  # 可能的SQL注入

# 6. 更多硬编码敏感信息
hardcoded_token = "token12345"  # 可能的硬编码token

# 7. 文件操作
with open("malicious_file.txt", "w") as file:
    file.write("This is malicious content!")  # 可能的文件操作

def execute_query(query):
    db_connection.execute(query)  # 可能的SQL注入

def use_format_string():
    # 8. 格式字符串问题
    query = "SELECT * FROM users WHERE username = {}".format(user_input)
    execute_query(query)
