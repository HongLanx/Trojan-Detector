from flask import Flask, render_template, request, redirect, url_for, session
import os
import sys
import io
from main import detect_trojan  # 确保main.py与app.py在同一目录下

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'


@app.route('/', methods=['GET', 'POST'])
def index():
    # 每次请求时清空报告内容
    if 'report' not in session:
        session['report'] = ""

    if request.method == 'POST':
        folder_path = request.form['folderPath']
        language = request.form['language']
        method = request.form['method']

        # 捕获print输出
        captured_output = io.StringIO()
        sys.stdout = captured_output

        # 调用main.py中的函数
        detect_trojan(folder_path, language, method, True)

        # 恢复stdout
        sys.stdout = sys.__stdout__

        # 获取捕获的输出并转换换行符
        output = captured_output.getvalue().replace('\n', '<br>')

        # 存储处理后的输出到session
        session['report'] = output
        return redirect(url_for('index'))

    return render_template('index.html', report=session.get('report'))


@app.route('/clear', methods=['GET'])
def clear():
    # 清空session中的报告内容
    session.pop('report', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
