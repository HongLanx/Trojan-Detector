import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import sys
import io
from main import detect_trojan


# 强制启用高DPI支持（仅适用于Windows）
try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("源代码后门检测")
        self.root.geometry("1200x1000")
        self.root.minsize(1200, 800)

        # 设置主题
        style = ttk.Style()
        style.theme_use('clam')

        # 设置系统字体
        custom_font = ("Segoe UI", 12)  # 使用系统默认字体
        output_font = ("Consolas", 10)  # 输出区域使用等宽字体
        # 设置文件夹路径变量
        self.folder_path = tk.StringVar()



        # 文件夹选择按钮
        self.folder_button = tk.Button(root, text="选择源代码文件夹", command=self.select_folder, font=custom_font, bg="lightblue", fg="black", relief="solid", bd=2)
        self.folder_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # 语言选择下拉菜单
        self.language_var = tk.StringVar()
        self.language_choices = ["Java", "Python", "Go"]
        self.language_dropdown = ttk.Combobox(root, textvariable=self.language_var, values=self.language_choices, font=custom_font)
        self.language_dropdown.set("选择编程语言")
        self.language_dropdown.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        # 检测方法选择下拉菜单
        self.method_var = tk.StringVar()
        self.method_choices = ["AST模式匹配", "中间代码转换", "代码向量化/机器学习"]
        self.method_dropdown = ttk.Combobox(root, textvariable=self.method_var, values=self.method_choices, font=custom_font)
        self.method_dropdown.set("选择检测方法")
        self.method_dropdown.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        # 检测按钮
        self.detect_button = tk.Button(root, text="开始检测", command=self.start_detection, font=custom_font, bg="lightgreen", fg="black", relief="solid", bd=2)
        self.detect_button.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        # 输出显示区域
        self.output_area = scrolledtext.ScrolledText(root, width=70, height=20, font=("Microsoft YaHei", 10), bg="black", fg="white")
        self.output_area.grid(row=4, column=0, padx=10, pady=10, sticky="nsew")

        # 进度条
        self.progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
        self.progress.grid(row=5, column=0, padx=10, pady=10, sticky="ew")

        # 让输出区域可以自动扩展
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(4, weight=1)

    def select_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
            self.print_to_gui(f"已选择文件夹: {folder_selected}")

    def print_to_gui(self, message):
        self.output_area.insert(tk.END, message + "\n")
        self.output_area.see(tk.END)  # 自动滚动到最新文本

    def start_detection(self):
        if not self.folder_path.get():
            messagebox.showerror("错误", "请首先选择一个文件夹。")
            return

        if self.language_var.get() == "选择编程语言" or self.method_var.get() == "选择检测方法":
            messagebox.showerror("错误", "请同时选择编程语言和检测方法。")
            return

        # 重定向print到GUI
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

        # 调用检测函数
        detect_trojan(self.folder_path.get(), self.language_var.get(), self.method_var.get())

        # 恢复标准输出并获取内容
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout

        self.print_to_gui(output)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
