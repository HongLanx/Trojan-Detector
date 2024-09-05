import subprocess
import os

def analyze_java_files(folder_path):
    """
    编译文件路径中的所有Java文件，提取字节码并反编译，生成检测报告
    :param folder_path: 包含Java文件的文件夹路径
    """
    # 确保输出文件夹与输入文件夹一致
    output_folder = folder_path

    # 特征库示例
    feature_library = [
        "Runtime.getRuntime().exec",  # 检测恶意命令执行
        # 其他特征可以继续添加
    ]

    def compile_java_to_bytecode(java_file_path, output_dir):
        """
        将Java文件编译为字节码并将结果保存在指定的输出目录中
        """
        class_file_name = os.path.basename(java_file_path).replace('.java', '.class')
        output_class_path = os.path.join(output_dir, class_file_name)

        # 编译命令，指定输出目录
        compile_command = ['javac', '-d', output_dir, java_file_path]

        try:
            result = subprocess.run(compile_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                print(f"Compilation successful for {java_file_path}")
            else:
                print(f"Compilation failed for {java_file_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error processing {java_file_path}: {e.stderr.decode('utf-8', errors='replace')}")

        return output_class_path

    def extract_bytecode_features(class_file_path):
        """
        使用javap反编译工具提取Java字节码
        """
        # 标准化路径
        class_file_path = os.path.normpath(class_file_path)

        # 使用javap工具的完整路径
        javap_command = ['javap', '-c', class_file_path]

        try:
            bytecode_output = subprocess.run(javap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if bytecode_output.returncode != 0:
                print(f"Error: {bytecode_output.stderr}")
            return bytecode_output.stdout
        except FileNotFoundError:
            print(f"javap not found. Please check the path and ensure JDK is installed.")
            return ""

    def save_report(report_lines, report_file_path):
        """
        将检测报告写入文件中
        """
        with open(report_file_path, 'w', encoding='utf-8') as report_file:
            report_file.writelines(report_lines)
        print(f"Report saved to {report_file_path}")

    # 初始化报告内容
    report_lines = []
    report_lines.append("Malware Detection Report\n")
    report_lines.append(f"Scanned Folder: {folder_path}\n\n")

    # 遍历文件夹中的所有Java文件
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".java"):
                java_file_path = os.path.join(root, file)
                print(f"Processing {java_file_path}...")
                report_lines.append(f"Processing {java_file_path}...\n")

                try:
                    # 编译Java文件生成字节码
                    class_file_path = compile_java_to_bytecode(java_file_path, output_folder)
                    if os.path.exists(class_file_path):  # 确保.class文件存在
                        # 提取字节码并反编译
                        bytecode = extract_bytecode_features(class_file_path)
                        report_lines.append(f"\nBytecode for {class_file_path}:\n")
                        report_lines.append(bytecode + "\n")
                    else:
                        report_lines.append(f"Compilation failed for {java_file_path}\n")
                except subprocess.CalledProcessError as e:
                    error_message = f"Error processing {java_file_path}: {e}\n"
                    report_lines.append(error_message)
                    print(error_message)

    # 保存检测报告到输入的文件夹中
    report_file_path = os.path.join(output_folder, "Malware_Detection_Report.txt")
    save_report(report_lines, report_file_path)

