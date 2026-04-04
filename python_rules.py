# autocritic/engine/rules/python_rules.py

import ast
from pathlib import Path
from typing import List, Optional

from engine.models.scan_models import Issue, Severity, Category
from engine.rules.base import BaseRule


# ============================================================
# ======================= SECURITY ============================
# ============================================================


class DangerousEvalExecRule(BaseRule):
    id = "PY-S-001"
    name = "Dangerous eval/exec Usage"
    description = "Detects use of eval() or exec() which can execute arbitrary code."
    severity = Severity.CRITICAL
    category = Category.SECURITY

    def check(
        self,
        file_path: Path,
        content: str,
        tree: Optional[ast.AST],
    ) -> List[Issue]:

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title=f"Use of {node.func.id}() detected",
                            message=f"Use of {node.func.id}() detected. This can execute arbitrary code.",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=node.lineno,
                            confidence=1.0,
                            explanation="eval() and exec() execute arbitrary strings as Python code. If user-controlled input reaches these functions, it enables remote code execution.",
                            suggestion=f"Replace {node.func.id}() with a safe alternative like ast.literal_eval() for data parsing, or use a whitelist-based approach.",
                        )
                    )

        return issues


class SubprocessShellTrueRule(BaseRule):
    id = "PY-S-002"
    name = "Subprocess shell=True"
    description = "Detects subprocess calls with shell=True which enables shell injection."
    severity = Severity.CRITICAL
    category = Category.SECURITY

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"call", "run", "Popen"}:
                    for kw in node.keywords:
                        if (
                            kw.arg == "shell"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                        ):
                            issues.append(
                                Issue(
                                    rule_id=self.id,
                                    title="Subprocess called with shell=True",
                                    message=f"subprocess.{node.func.attr}() called with shell=True.",
                                    severity=self.severity,
                                    category=self.category,
                                    file_path=str(file_path),
                                    line=node.lineno,
                                    confidence=1.0,
                                    explanation="Using shell=True passes the command through the system shell, enabling shell injection attacks if any part of the command is user-controlled.",
                                    suggestion="Use shell=False (the default) and pass arguments as a list: subprocess.run(['cmd', 'arg1', 'arg2']).",
                                )
                            )

        return issues


class HardcodedSecretRule(BaseRule):
    id = "PY-S-003"
    name = "Hardcoded Secret"
    description = "Detects hardcoded passwords, API keys, and tokens in source code."
    severity = Severity.CRITICAL
    category = Category.SECURITY

    SECRET_KEYWORDS = {"password", "secret", "api_key", "token", "apikey", "secret_key"}

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(k in name for k in self.SECRET_KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                issues.append(
                                    Issue(
                                        rule_id=self.id,
                                        title=f"Possible hardcoded secret in '{target.id}'",
                                        message=f"Possible hardcoded secret detected in variable '{target.id}'.",
                                        severity=self.severity,
                                        category=self.category,
                                        file_path=str(file_path),
                                        line=node.lineno,
                                        confidence=0.95,
                                        explanation="Hardcoding secrets in source code exposes them in version control, build artifacts, and logs. This is a common attack vector.",
                                        suggestion="Use environment variables or a secrets manager (e.g., os.environ['SECRET'], AWS Secrets Manager, HashiCorp Vault).",
                                    )
                                )

        return issues


class TaintFlowRule(BaseRule):
    id = "PY-S-004"
    name = "Taint Flow to Dangerous Sink"
    description = "Detects user-controlled input flowing into eval/exec."
    severity = Severity.CRITICAL
    category = Category.SECURITY

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        function_nodes = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef)
        ]

        for func in function_nodes:

            tainted = set()

            for node in ast.walk(func):

                # Source
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Name) and node.value.func.id == "input":
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                tainted.add(target.id)

                # Propagation
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                    if node.value.id in tainted:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                tainted.add(target.id)

                # Sink
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                        if node.args:
                            arg = node.args[0]
                            if isinstance(arg, ast.Name) and arg.id in tainted:
                                issues.append(
                                    Issue(
                                        rule_id=self.id,
                                        title="User input reaches dangerous function",
                                        message=f"User-controlled input '{arg.id}' flows into {node.func.id}().",
                                        severity=self.severity,
                                        category=self.category,
                                        file_path=str(file_path),
                                        line=node.lineno,
                                        confidence=1.0,
                                        explanation="Untrusted input from input() reaches eval/exec, creating a remote code execution vulnerability.",
                                        suggestion="Validate and sanitize all user input. Use ast.literal_eval() for safe data parsing, or avoid dynamic code execution entirely.",
                                    )
                                )

        return issues


# ============================================================
# ==================== RELIABILITY / BUGS ====================
# ============================================================

class MutableDefaultArgumentRule(BaseRule):
    id = "PY-R-001"
    name = "Mutable Default Argument"
    description = "Detects mutable default arguments in function definitions."
    severity = Severity.MAJOR
    category = Category.RELIABILITY

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in node.args.defaults):
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title=f"Mutable default argument in '{node.name}()'",
                            message=f"Mutable default argument detected in function '{node.name}'.",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=node.lineno,
                            confidence=1.0,
                            explanation="Mutable defaults (list, dict, set) are shared across all calls. Modifying them in one call affects all subsequent calls, causing subtle bugs.",
                            suggestion="Use None as default and initialize inside the function: def f(items=None): items = items or []",
                        )
                    )

        return issues


class DuplicateDictKeyRule(BaseRule):
    id = "PY-R-002"
    name = "Duplicate Dictionary Key"
    description = "Detects duplicate keys in dictionary literals."
    severity = Severity.MAJOR
    category = Category.RELIABILITY

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                seen = set()
                for key in node.keys:
                    if isinstance(key, ast.Constant):
                        if key.value in seen:
                            issues.append(
                                Issue(
                                    rule_id=self.id,
                                    title=f"Duplicate dictionary key '{key.value}'",
                                    message=f"Duplicate dictionary key '{key.value}' detected.",
                                    severity=self.severity,
                                    category=self.category,
                                    file_path=str(file_path),
                                    line=node.lineno,
                                    confidence=1.0,
                                    explanation="Duplicate keys in a dictionary literal silently overwrite the previous value. This is almost always a bug.",
                                    suggestion="Remove the duplicate key or rename it if both values are needed.",
                                )
                            )
                        seen.add(key.value)

        return issues


class UnreachableCodeRule(BaseRule):
    id = "PY-R-003"
    name = "Unreachable Code"
    description = "Detects code after return statements that will never execute."
    severity = Severity.MAJOR
    category = Category.RELIABILITY

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        function_nodes = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef)
        ]

        for func in function_nodes:
            for i, stmt in enumerate(func.body[:-1]):
                if isinstance(stmt, ast.Return):
                    next_stmt = func.body[i + 1]
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title="Unreachable code after return",
                            message=f"Unreachable code detected after return in '{func.name}'.",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=next_stmt.lineno,
                            confidence=0.95,
                            explanation="Code placed after a return statement will never execute. This may indicate a logic error or forgotten cleanup.",
                            suggestion="Remove the unreachable code, or move it before the return statement.",
                        )
                    )

        return issues


class ExceptionHandlingRule(BaseRule):
    id = "PY-R-004"
    name = "Poor Exception Handling"
    description = "Detects bare except, overly broad Exception catches, and empty handlers."
    severity = Severity.MAJOR
    category = Category.RELIABILITY

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:

                    problems = []

                    if handler.type is None:
                        problems.append("bare except")

                    elif isinstance(handler.type, ast.Name) and handler.type.id == "Exception":
                        problems.append("broad Exception")

                    if not handler.body or all(isinstance(s, ast.Pass) for s in handler.body):
                        problems.append("empty except block")

                    if any(isinstance(s, ast.Return) for s in handler.body):
                        problems.append("return inside except")

                    if problems:
                        issues.append(
                            Issue(
                                rule_id=self.id,
                                title="Poor exception handling detected",
                                message=f"Poor exception handling: {', '.join(problems)}.",
                                severity=self.severity,
                                category=self.category,
                                file_path=str(file_path),
                                line=handler.lineno,
                                confidence=1.0,
                                explanation="Bare except and broad Exception catches hide bugs by silently swallowing errors. Empty handlers ignore exceptions entirely.",
                                suggestion="Catch specific exceptions, log the error, and handle or re-raise appropriately.",
                            )
                        )

        return issues


# ============================================================
# ====================== CODE QUALITY ========================
# ============================================================

class UnusedVariableRule(BaseRule):
    id = "PY-Q-001"
    name = "Unused Variable"
    description = "Detects variables that are assigned but never used."
    severity = Severity.MAJOR
    category = Category.QUALITY

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        assigned = set()
        used = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    assigned.add(node.id)
                elif isinstance(node.ctx, ast.Load):
                    used.add(node.id)

        unused = assigned - used

        return [
            Issue(
                rule_id=self.id,
                title=f"Unused variable '{var}'",
                message=f"Variable '{var}' is assigned but never used.",
                severity=self.severity,
                category=self.category,
                file_path=str(file_path),
                line=None,
                confidence=0.9,
                explanation="Unused variables indicate dead code, incomplete refactoring, or typos. They reduce readability and may mask bugs.",
                suggestion=f"Remove the variable '{var}' if it's not needed, or prefix with underscore (_) to indicate it's intentionally unused.",
            )
            for var in sorted(unused)
        ]


# ============================================================
# ============== ADDITIONAL SECURITY RULES ===================
# ============================================================


class SQLInjectionRule(BaseRule):
    id = "PY-S-005"
    name = "SQL Injection Risk"
    description = "Detects string formatting in SQL-like execution contexts."
    severity = Severity.CRITICAL
    category = Category.SECURITY

    _EXECUTE_METHODS = {"execute", "executemany", "raw", "execute_sql"}

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Match obj.execute(...) style calls
            if not isinstance(node.func, ast.Attribute):
                continue

            if node.func.attr not in self._EXECUTE_METHODS:
                continue

            if not node.args:
                continue

            arg = node.args[0]

            # Detect f-strings
            if isinstance(arg, ast.JoinedStr):
                issues.append(self._make_issue(file_path, node, "f-string"))

            # Detect string concatenation (BinOp with Add)
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                issues.append(self._make_issue(file_path, node, "string concatenation"))

            # Detect % formatting
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                issues.append(self._make_issue(file_path, node, "% formatting"))

            # Detect .format()
            elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                if arg.func.attr == "format":
                    issues.append(self._make_issue(file_path, node, ".format()"))

        return issues

    def _make_issue(self, file_path, node, method):
        return Issue(
            rule_id=self.id,
            title=f"SQL injection risk via {method}",
            message=f"SQL query built with {method} in .{node.func.attr}() call.",
            severity=self.severity,
            category=self.category,
            file_path=str(file_path),
            line=node.lineno,
            confidence=0.9,
            explanation="Building SQL queries with string formatting allows attackers to inject malicious SQL. This is the #1 web application vulnerability (OWASP A03).",
            suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        )


class InsecureImportRule(BaseRule):
    id = "PY-S-006"
    name = "Insecure Module Import"
    description = "Detects imports of modules with known security risks."
    severity = Severity.MAJOR
    category = Category.SECURITY

    _UNSAFE_MODULES = {
        "pickle": "Arbitrary code execution via deserialization",
        "marshal": "Arbitrary code execution via deserialization",
        "shelve": "Uses pickle internally — arbitrary code execution risk",
        "cPickle": "Arbitrary code execution via deserialization",
    }

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self._UNSAFE_MODULES:
                        issues.append(self._make_issue(file_path, node, alias.name))

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in self._UNSAFE_MODULES:
                    issues.append(self._make_issue(file_path, node, node.module))

                # yaml.load without Loader
                if node.module == "yaml":
                    for alias in node.names:
                        if alias.name == "load":
                            issues.append(
                                Issue(
                                    rule_id=self.id,
                                    title="Unsafe yaml.load import",
                                    message="yaml.load is imported — ensure Loader=SafeLoader is always used.",
                                    severity=Severity.MAJOR,
                                    category=self.category,
                                    file_path=str(file_path),
                                    line=node.lineno,
                                    confidence=0.8,
                                    explanation="yaml.load() without Loader=SafeLoader can execute arbitrary Python objects embedded in YAML.",
                                    suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                                )
                            )

        return issues

    def _make_issue(self, file_path, node, module_name):
        reason = self._UNSAFE_MODULES.get(module_name, "Security risk")
        return Issue(
            rule_id=self.id,
            title=f"Import of insecure module '{module_name}'",
            message=f"Import of '{module_name}': {reason}.",
            severity=self.severity,
            category=self.category,
            file_path=str(file_path),
            line=node.lineno,
            confidence=0.95,
            explanation=f"The '{module_name}' module can deserialize arbitrary Python objects, enabling remote code execution if untrusted data is loaded.",
            suggestion=f"Replace '{module_name}' with a safe alternative like json for serialization.",
        )


class OsSystemRule(BaseRule):
    id = "PY-S-007"
    name = "os.system/os.popen Usage"
    description = "Detects use of os.system() and os.popen() which enable shell injection."
    severity = Severity.CRITICAL
    category = Category.SECURITY

    _DANGEROUS_FUNCS = {"system", "popen"}

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr in self._DANGEROUS_FUNCS
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                ):
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title=f"Use of os.{node.func.attr}()",
                            message=f"os.{node.func.attr}() executes commands via the system shell.",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=node.lineno,
                            confidence=1.0,
                            explanation=f"os.{node.func.attr}() passes commands to the OS shell, enabling shell injection if any input is user-controlled.",
                            suggestion="Use subprocess.run() with shell=False and pass arguments as a list.",
                        )
                    )

        return issues


# ============================================================
# ================ PERFORMANCE RULES =========================
# ============================================================


class TimeSleepInAsyncRule(BaseRule):
    id = "PY-P-001"
    name = "time.sleep in Async Function"
    description = "Detects time.sleep() inside async functions, which blocks the event loop."
    severity = Severity.MAJOR
    category = Category.PERFORMANCE

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                for child in ast.walk(node):
                    if (
                        isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "sleep"
                        and isinstance(child.func.value, ast.Name)
                        and child.func.value.id == "time"
                    ):
                        issues.append(
                            Issue(
                                rule_id=self.id,
                                title=f"time.sleep() in async function '{node.name}'",
                                message=f"time.sleep() used inside async function '{node.name}'.",
                                severity=self.severity,
                                category=self.category,
                                file_path=str(file_path),
                                line=child.lineno,
                                confidence=1.0,
                                explanation="time.sleep() blocks the entire event loop, preventing all other async tasks from running. This defeats the purpose of async.",
                                suggestion="Use await asyncio.sleep() instead.",
                            )
                        )

        return issues


class NestedLoopRule(BaseRule):
    id = "PY-P-002"
    name = "Deeply Nested Loops"
    description = "Detects triply-nested loops which indicate O(n³) or worse complexity."
    severity = Severity.MAJOR
    category = Category.PERFORMANCE

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []
        self._check_nested(tree, file_path, 0, issues)
        return issues

    def _check_nested(self, node, file_path, depth, issues):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.For, ast.While)):
                new_depth = depth + 1
                if new_depth >= 3:
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title="Triply-nested loop detected",
                            message=f"Loop nested {new_depth} levels deep.",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=child.lineno,
                            confidence=0.85,
                            explanation="Triply-nested loops have O(n³) complexity. With large datasets, performance degrades rapidly.",
                            suggestion="Consider flattening with itertools.product(), using dict lookups, or restructuring the algorithm.",
                        )
                    )
                self._check_nested(child, file_path, new_depth, issues)
            else:
                self._check_nested(child, file_path, depth, issues)


class UnboundedComprehensionRule(BaseRule):
    id = "PY-P-003"
    name = "Unbounded Comprehension"
    description = "Detects list comprehensions over potentially large generators that may consume excessive memory."
    severity = Severity.MAJOR
    category = Category.PERFORMANCE

    _LARGE_SOURCES = {"range", "open", "readlines", "read"}

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ListComp):
                for gen in node.generators:
                    if isinstance(gen.iter, ast.Call):
                        func = gen.iter.func
                        func_name = None

                        if isinstance(func, ast.Name):
                            func_name = func.id
                        elif isinstance(func, ast.Attribute):
                            func_name = func.attr

                        if func_name in self._LARGE_SOURCES:
                            # range() with very large values
                            if func_name == "range" and gen.iter.args:
                                arg = gen.iter.args[-1]
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                                    if arg.value <= 10000:
                                        continue

                            issues.append(
                                Issue(
                                    rule_id=self.id,
                                    title=f"List comprehension over {func_name}()",
                                    message=f"List comprehension materializes all items from {func_name}() into memory.",
                                    severity=self.severity,
                                    category=self.category,
                                    file_path=str(file_path),
                                    line=node.lineno,
                                    confidence=0.7,
                                    explanation="List comprehensions eagerly evaluate the entire iterable into memory. For large data sources this can cause memory exhaustion.",
                                    suggestion="Use a generator expression instead: (x for x in source) or process items lazily with itertools.",
                                )
                            )

        return issues


# ============================================================
# ============= MAINTAINABILITY RULES ========================
# ============================================================


class LongFunctionRule(BaseRule):
    id = "PY-M-001"
    name = "Long Function"
    description = "Detects functions exceeding 50 lines, which are hard to understand and test."
    severity = Severity.MAJOR
    category = Category.MAINTAINABILITY

    MAX_LINES = 50

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.body:
                    continue

                start = node.lineno
                end = max(getattr(n, "end_lineno", start) for n in ast.walk(node) if hasattr(n, "end_lineno"))
                func_len = end - start + 1

                if func_len > self.MAX_LINES:
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title=f"Function '{node.name}' is {func_len} lines long",
                            message=f"Function '{node.name}' is {func_len} lines (limit: {self.MAX_LINES}).",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=node.lineno,
                            confidence=0.9,
                            explanation="Long functions are harder to read, test, and debug. They often indicate the function is doing too many things.",
                            suggestion=f"Extract helper functions to keep '{node.name}' under {self.MAX_LINES} lines. Follow the Single Responsibility Principle.",
                        )
                    )

        return issues


class DeepNestingRule(BaseRule):
    id = "PY-M-002"
    name = "Deep Nesting"
    description = "Detects code nesting deeper than 4 levels."
    severity = Severity.MAJOR
    category = Category.MAINTAINABILITY

    MAX_DEPTH = 4

    _NESTING_NODES = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.ExceptHandler)

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []
        self._walk(tree, file_path, 0, issues)
        return issues

    def _walk(self, node, file_path, depth, issues):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, self._NESTING_NODES):
                new_depth = depth + 1
                if new_depth > self.MAX_DEPTH:
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title=f"Code nested {new_depth} levels deep",
                            message=f"Nesting depth {new_depth} exceeds max {self.MAX_DEPTH}.",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=child.lineno,
                            confidence=0.85,
                            explanation="Deeply nested code is hard to follow and error-prone. It often indicates complex conditional logic that should be simplified.",
                            suggestion="Use early returns, guard clauses, or extract helper functions to reduce nesting.",
                        )
                    )
                self._walk(child, file_path, new_depth, issues)
            else:
                self._walk(child, file_path, depth, issues)


class TooManyParametersRule(BaseRule):
    id = "PY-M-003"
    name = "Too Many Parameters"
    description = "Detects functions with more than 7 parameters."
    severity = Severity.MAJOR
    category = Category.MAINTAINABILITY

    MAX_PARAMS = 7

    def check(self, file_path, content, tree):

        if tree is None:
            return []

        issues: List[Issue] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args

                param_count = (
                    len(args.args)
                    + len(args.posonlyargs)
                    + len(args.kwonlyargs)
                )

                # Exclude 'self' and 'cls'
                if args.args and args.args[0].arg in {"self", "cls"}:
                    param_count -= 1

                if param_count > self.MAX_PARAMS:
                    issues.append(
                        Issue(
                            rule_id=self.id,
                            title=f"Function '{node.name}' has {param_count} parameters",
                            message=f"Function '{node.name}' has {param_count} params (limit: {self.MAX_PARAMS}).",
                            severity=self.severity,
                            category=self.category,
                            file_path=str(file_path),
                            line=node.lineno,
                            confidence=0.9,
                            explanation="Functions with many parameters are hard to call correctly, test, and refactor. They often indicate the function is doing too many things.",
                            suggestion=f"Group related parameters into a dataclass or dictionary. Consider splitting '{node.name}' into smaller functions.",
                        )
                    )

        return issues