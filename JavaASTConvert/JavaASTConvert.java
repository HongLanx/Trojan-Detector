package JavaASTConvert;

// 定义AST节点
abstract class Expr {
    abstract String accept(ExprVisitor visitor);
}

class NumberExpr extends Expr {
    int value;

    NumberExpr(int value) {
        this.value = value;
    }

    @Override
    String accept(ExprVisitor visitor) {
        return visitor.visitNumberExpr(this);
    }
}

class AddExpr extends Expr {
    Expr left, right;

    AddExpr(Expr left, Expr right) {
        this.left = left;
        this.right = right;
    }

    @Override
    String accept(ExprVisitor visitor) {
        return visitor.visitAddExpr(this);
    }
}

class MultiplyExpr extends Expr {
    Expr left, right;

    MultiplyExpr(Expr left, Expr right) {
        this.left = left;
        this.right = right;
    }

    @Override
    String accept(ExprVisitor visitor) {
        return visitor.visitMultiplyExpr(this);
    }
}

// 定义访问者接口
interface ExprVisitor {
    String visitNumberExpr(NumberExpr expr);
    String visitAddExpr(AddExpr expr);
    String visitMultiplyExpr(MultiplyExpr expr);
}

// 实现转换器
class PrefixConverter implements ExprVisitor {
    @Override
    public String visitNumberExpr(NumberExpr expr) {
        return String.valueOf(expr.value);
    }

    @Override
    public String visitAddExpr(AddExpr expr) {
        return "(+ " + expr.left.accept(this) + " " + expr.right.accept(this) + ")";
    }

    @Override
    public String visitMultiplyExpr(MultiplyExpr expr) {
        return "(* " + expr.left.accept(this) + " " + expr.right.accept(this) + ")";
    }
}

// 使用转换器
public class JavaASTConvert {
    public static void main(String[] args) {
        // 构建更复杂的表达式: 1 + (2 * 3)
        Expr expression = new AddExpr(
            new NumberExpr(1),
            new MultiplyExpr(
                new NumberExpr(2),
                new NumberExpr(3)
            )
        );

        // 创建前缀转换器
        PrefixConverter converter = new PrefixConverter();

        // 执行转换
        String result = expression.accept(converter);

        // 打印结果
        System.out.println(result); // 输出: (+ 1 (* 2 3))
    }
}
