// SSAGenerator: Go程序的SSA形式展示和解释工具。
package main

import (
	"flag" // 引入flag包，用于解析命令行参数
	"fmt"  // 引入fmt包，用于格式化输出
	"go/build"  // 引入build包，用于获取Go程序的构建信息
	"go/types"  // 引入types包，用于处理Go类型信息
	"os"  // 引入os包，用于文件和命令行操作
	"runtime"  // 引入runtime包，用于获取运行时信息
	"runtime/pprof"  // 引入pprof包，用于性能分析
	"strings"  // 引入strings包，用于字符串操作

	"golang.org/x/tools/go/buildutil"  // 引入buildutil包，提供构建Go程序的实用工具
	"golang.org/x/tools/go/packages"  // 引入packages包，用于加载和解析Go包
	"golang.org/x/tools/go/ssa"  // 引入ssa包，用于生成和操作SSA形式的Go程序
	"golang.org/x/tools/go/ssa/interp"  // 引入interp包，用于解释执行SSA程序
	"golang.org/x/tools/go/ssa/ssautil"  // 引入ssautil包，提供SSA相关的工具
)

// flags变量定义
var (
	mode = ssa.BuilderMode(0)  // SSA构建模式，默认为0

	testFlag = flag.Bool("test", false, "包括隐式的测试包和可执行文件")  // 命令行参数-test，表示是否包含测试包

	runFlag = flag.Bool("run", false, "解释执行SSA程序")  // 命令行参数-run，用于控制是否执行解释器

	interpFlag = flag.String("interp", "", `控制SSA测试解释器的选项。
选项值是以下字母的组合：
R	禁用从panic中的[R]ecover(); 显示解释器崩溃。
T	追踪程序执行。适用于单线程程序！
`)  // 解释器选项

	cpuprofile = flag.String("cpuprofile", "", "将cpu性能分析结果写入文件")  // CPU性能分析文件路径

	args stringListValue  // 命令行参数-arg，用于向解释执行的程序添加参数
)

func init() {
	flag.Var(&mode, "build", ssa.BuilderModeDoc)  // 初始化-build标志
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)  // 初始化-tags标志
	flag.Var(&args, "arg", "向解释执行的程序添加参数")  // 初始化-arg标志
}

const usage = `SSA构建器和解释器。
使用方式: SSAGenerator [-build=[DBCSNFLG]] [-test] [-run] [-interp=[TR]] [-arg=...] package...
使用-help标志显示选项。

示例:
% SSAGenerator -build=F hello.go              # 输出单个包的SSA形式
% SSAGenerator -build=F -test fmt             # 输出包及其测试的SSA形式
% SSAGenerator -run -interp=T hello.go        # 解释执行程序，带有追踪

-run标志使SSAGenerator构建代码并运行名为main的第一个包。

`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "SSAGenerator: %s\n", err)
		os.Exit(1)
	}
}

func doMain() error {
	flag.Parse()  // 解析命令行参数
	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, usage)  // 如果没有输入参数，打印用法
		os.Exit(1)
	}

	// 根据输入文件名设置输出文件
	srcFilename := flag.Arg(0)  // 假设第一个参数是源文件
	outputFilename := strings.TrimSuffix(srcFilename, ".go") + ".ssa"  // 设置输出文件名
	outputFile, err := os.Create(outputFilename)  // 创建输出文件
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()  // 确保文件关闭

	// 将所有fmt的输出重定向到输出文件
	oldStdout := os.Stdout
	os.Stdout = outputFile
	defer func() { os.Stdout = oldStdout }()  // 恢复标准输出

	// 设置包的配置
	cfg := &packages.Config{
		Mode:  packages.LoadSyntax,
		Tests: *testFlag,
	}
	// 从conf.Build选择types.Sizes。
	var wordSize int64 = 8
	switch build.Default.GOARCH {
	case "386", "arm":
		wordSize = 4
	}
	sizes := &types.StdSizes{
		MaxAlign: 8,
		WordSize: wordSize,
	}

	var interpMode interp.Mode
	for _, c := range *interpFlag {
		switch c {
		case 'T':
			interpMode |= interp.EnableTracing  // 启用追踪
		case 'R':
			interpMode |= interp.DisableRecover  // 禁用恢复
		default:
			return fmt.Errorf("未知的-interp选项: '%c'", c)
		}
	}

	// 支持性能分析。
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)  // 创建性能分析文件
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)  // 开始CPU性能分析
		defer pprof.StopCPUProfile()  // 结束性能分析
	}

	// 加载、解析和类型检查初始包，
	// 如果设置了-run，还需处理其依赖。
	if *runFlag {
		cfg.Mode = packages.LoadAllSyntax
	}
	initial, err := packages.Load(cfg, flag.Args()...)  // 加载包
	if err != nil {
		return err
	}
	if len(initial) == 0 {
		return fmt.Errorf("没有包")
	}
	if packages.PrintErrors(initial) > 0 {
		return fmt.Errorf("包含错误的包")
	}

	// 如果程序将被运行，打开实例化泛型的开关。
	if *runFlag {
		mode |= ssa.InstantiateGenerics
	}

	// 创建SSA形式的程序表示。
	prog, pkgs := ssautil.AllPackages(initial, mode)  // 获取所有包的SSA表示

	for i, p := range pkgs {
		if p == nil {
			return fmt.Errorf("无法为包 %s 构建SSA", initial[i].PkgPath)
		}
	}

	if !*runFlag {
		// 只构建并展示初始包
		// （和合成的封装）。
		for _, p := range pkgs {
			p.Build()  // 构建包的SSA
		}

	} else {
		// 运行解释器。
		// 为所有包构建SSA。
		prog.Build()  // 构建程序的SSA

		if prog.ImportedPackage("runtime") != nil {
			return fmt.Errorf("-run: 程序依赖于runtime包（解释器只能运行非常简单的程序）")
		}

		if runtime.GOARCH != build.Default.GOARCH {
			return fmt.Errorf("不支持交叉解释（目标为GOARCH %s，解释器为 %s）",
				build.Default.GOARCH, runtime.GOARCH)
		}

		// 运行第一个main包。
		for _, main := range ssautil.MainPackages(pkgs) {
			fmt.Fprintf(os.Stderr, "正在运行: %s\n", main.Pkg.Path())
			os.Exit(interp.Interpret(main, interpMode, sizes, main.Pkg.Path(), args))
		}
		return fmt.Errorf("没有main包")
	}
	return nil
}

// stringListValue是一个flag.Value，用于累积字符串。
// 例如 --flag=one --flag=two 会产生 []string{"one", "two"}。
type stringListValue []string

func newStringListValue(val []string, p *[]string) *stringListValue {
	*p = val
	return (*stringListValue)(p)
}

func (ss *stringListValue) Get() interface{} { return []string(*ss) }

func (ss *stringListValue) String() string { return fmt.Sprintf("%q", *ss) }

func (ss *stringListValue) Set(s string) error { *ss = append(*ss, s); return nil }
