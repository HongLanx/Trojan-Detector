# patterns.py

# 定义一些常见的恶意代码模式
PATTERNS = [
    {
        'name': 'Potentially Malicious Exec',
        'pattern': r'exec\(',  # 正则表达式匹配 exec( 的模式
        'description': 'Usage of exec() can execute arbitrary code.'
    },
    {
        'name': 'Suspicious Import',
        'pattern': r'import os',  # 正则表达式匹配 import os
        'description': 'Importing os can be used to execute system commands.'
    },
    {
        'name': 'Possible Backdoor',
        'pattern': r'socket\.socket',  # 正则表达式匹配 socket.socket
        'description': 'Opening a socket could be used to create a backdoor.'
    },
    {
        'name': 'Eval Injection',
        'pattern': r'eval\(',  # 正则表达式匹配 eval( 的模式
        'description': 'Usage of eval() can be exploited to run arbitrary code.'
    }
    # 你可以根据需要添加更多的模式
]
