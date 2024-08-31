package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		println("Usage: AstGenerator <file_path>")
		os.Exit(1)
	}
	filePath := os.Args[1]

	// 创建FileSet对象，这对于记录位置信息是必需的
	fset := token.NewFileSet()

	// 使用parser包将Go源代码文件解析为AST
	f, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	// 创建输出文件
	outFile, err := os.Create(strings.TrimSuffix(filePath, ".go") + ".ast")
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	// 创建一个将输出重定向到文件的writer
	writer := os.NewFile(outFile.Fd(), outFile.Name())

	// 打印AST到文件
	ast.Fprint(writer, fset, f, nil)
}
