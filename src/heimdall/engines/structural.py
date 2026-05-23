from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from ..types import StructuralFinding, StructuralResult
from ..utils.scoring import clamp01


@dataclass(frozen=True)
class SinkSpec:
    rule_id: str
    title: str
    severity: float
    names: Tuple[str, ...]  # best-effort dotted call names (resolved via imports/attrs)


DEFAULT_SINKS: List[SinkSpec] = [
    SinkSpec("PY001", "Dynamic code execution", 0.95, ("eval", "exec", "compile")),
    SinkSpec("PY002", "OS command execution", 0.90, ("os.system", "subprocess.call", "subprocess.run", "subprocess.Popen")),
    SinkSpec("PY003", "Shell-enabled subprocess", 0.95, ("subprocess.run", "subprocess.Popen")),
    SinkSpec("PY004", "Unsafe deserialization", 0.90, ("pickle.loads", "pickle.load", "yaml.load")),
    SinkSpec("PY005", "Potential SSRF", 0.70, ("requests.get", "requests.post", "urllib.request.urlopen")),
    SinkSpec("PY006", "Potential SQL execution", 0.80, ("cursor.execute", "executemany", "execute")),
]


TAINT_SOURCES: Tuple[str, ...] = (
    "input",
    "sys.argv",
    "os.environ",
    "request.args",
    "request.form",
    "request.values",
    "request.get_json",
    "flask.request",
    "request.POST",    
    "request.GET",     
    "request.FILES",    
    "request.body",
)

SAFE_FUNCTIONS: Set[str] = {
    "int",
    "float",
    "html.escape",
    "str.replace",
}


def _dotted_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _is_constant_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_sanitizer_call(func: ast.AST, resolved_name: str) -> bool:
    # Direct name matches (best-effort resolved via imports).
    if resolved_name in SAFE_FUNCTIONS:
        return True

    # Method calls like user_data.replace(...) resolve to "<var>.replace" not "str.replace".
    if isinstance(func, ast.Attribute) and func.attr == "replace":
        return True

    # If imported as "escape" from html, resolver should map to "html.escape",
    # but keep a small fallback.
    if resolved_name.endswith(".escape") and ("html.escape" in SAFE_FUNCTIONS):
        return True

    return False


def _eval_const(node: ast.AST) -> Optional[object]:
    # Minimal constant-folder for DCE:
    # - uses ast.literal_eval when possible (safe evaluator)
    # - falls back to a tiny subset of numeric ops / comparisons
    if isinstance(node, ast.Constant):
        return node.value

    # Older compatibility (rare on modern Python)
    name_const = getattr(ast, "NameConstant", None)
    if name_const is not None and isinstance(node, name_const):
        return getattr(node, "value", None)

    # Prefer literal_eval for safe constant expressions.
    try:
        return ast.literal_eval(node)  # type: ignore[attr-defined]
    except Exception:
        pass

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        v = _eval_const(node.operand)
        if isinstance(v, bool):
            return not v
        return None

    if isinstance(node, ast.BinOp):
        left = _eval_const(node.left)
        right = _eval_const(node.right)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            try:
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, ast.Div):
                    return left / right
                if isinstance(node.op, ast.FloorDiv):
                    return left // right
                if isinstance(node.op, ast.Mod):
                    return left % right
                if isinstance(node.op, ast.Pow):
                    return left**right
            except Exception:
                return None
        return None

    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        left = _eval_const(node.left)
        right = _eval_const(node.comparators[0])
        if left is None or right is None:
            return None
        op = node.ops[0]
        try:
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            if isinstance(op, ast.Lt):
                return left < right
            if isinstance(op, ast.LtE):
                return left <= right
            if isinstance(op, ast.Gt):
                return left > right
            if isinstance(op, ast.GtE):
                return left >= right
            if isinstance(op, ast.Is):
                return left is right
            if isinstance(op, ast.IsNot):
                return left is not right
        except Exception:
            return None

    return None


def _const_bool(node: ast.AST) -> Optional[bool]:
    v = _eval_const(node)
    return v if isinstance(v, bool) else None


def _sink_name_matches(call_name: str, sink_name: str) -> bool:
    """
    Match sink names conservatively to avoid false positives like 'safe_execute' ending with 'execute'.

    - If sink_name is qualified (contains '.'), allow suffix matching (imports/aliases).
    - If sink_name is unqualified (no '.'), require exact match.
    """
    if not call_name:
        return False
    if "." in sink_name:
        return call_name == sink_name or call_name.endswith(sink_name)
    return call_name == sink_name


@dataclass(frozen=True)
class TraceStep:
    kind: str  # source/param/assign/prop/call/sink
    detail: str
    lineno: Optional[int] = None


@dataclass(frozen=True)
class TaintLabel:
    origin: str  # source:<name> or param:<idx>
    steps: Tuple[TraceStep, ...]

    def extend(self, kind: str, detail: str, lineno: Optional[int]) -> "TaintLabel":
        return TaintLabel(self.origin, self.steps + (TraceStep(kind, detail, lineno),))


@dataclass(frozen=True)
class SinkTemplate:
    param_index: int
    key: Optional[str]  # dict key requirement (field-sensitive), if any
    rule_id: str
    title: str
    severity: float
    sink_call: str
    sink_lineno: Optional[int]
    steps_from_param: Tuple[TraceStep, ...]  # begins with param step


@dataclass(frozen=True)
class FunctionSummary:
    return_params: Set[int]
    # If function returns a dict literal with string keys, keep key-specific taint labels.
    return_dict: Dict[str, Set[TaintLabel]]
    sink_templates: Tuple[SinkTemplate, ...]


class _Env:
    def __init__(self) -> None:
        # var -> taint labels OR (dict key -> taint labels)
        self.vars: Dict[str, Union[Set[TaintLabel], Dict[str, Set[TaintLabel]]]] = {}

    def set(self, name: str, labels: Set[TaintLabel]) -> None:
        # Assign scalar value: overwrite any dict-typed storage.
        if labels:
            self.vars[name] = set(labels)
        else:
            self.vars.pop(name, None)

    def get(self, name: str) -> Set[TaintLabel]:
        v = self.vars.get(name)
        if v is None:
            return set()
        if isinstance(v, set):
            return set(v)
        # dict referenced as a whole: conservative union of all keys
        out: Set[TaintLabel] = set()
        for ls in v.values():
            out |= set(ls)
        return out

    def set_dict_key(self, name: str, key: str, labels: Set[TaintLabel]) -> None:
        v = self.vars.get(name)
        if v is None or isinstance(v, set):
            d: Dict[str, Set[TaintLabel]] = {}
            self.vars[name] = d
        else:
            d = v

        if labels:
            d[key] = set(labels)
        else:
            d.pop(key, None)
            if not d:
                self.vars.pop(name, None)

    def get_dict_key(self, name: str, key: str) -> Set[TaintLabel]:
        v = self.vars.get(name)
        if v is None or isinstance(v, set):
            return set()
        return set(v.get(key, set()))

    def set_dict(self, name: str, mapping: Dict[str, Set[TaintLabel]]) -> None:
        if not mapping:
            self.vars.pop(name, None)
            return
        self.vars[name] = {k: set(v) for k, v in mapping.items()}

    def clear(self, name: str) -> None:
        self.vars.pop(name, None)


def _pick_best(labels: Set[TaintLabel]) -> Optional[TaintLabel]:
    best: Optional[TaintLabel] = None
    for lbl in labels:
        if best is None or len(lbl.steps) > len(best.steps):
            best = lbl
    return best


def _labels_to_path_strings(lbl: Optional[TaintLabel]) -> List[str]:
    if lbl is None:
        return []
    out: List[str] = []
    for st in lbl.steps:
        loc = f"@L{st.lineno}" if st.lineno else ""
        out.append(f"{st.kind}:{st.detail}{loc}")
    return out


class _Resolver:
    def __init__(self) -> None:
        self.aliases: Dict[str, str] = {}

    def on_import(self, node: ast.Import) -> None:
        for a in node.names:
            if a.asname:
                self.aliases[a.asname] = a.name
            else:
                head = a.name.split(".", 1)[0]
                self.aliases[head] = head

    def on_importfrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for a in node.names:
            local = a.asname or a.name
            self.aliases[local] = f"{mod}.{a.name}".strip(".")

    def resolve(self, func: ast.AST) -> str:
        raw = _dotted_name(func) or ""
        if not raw:
            return ""
        head, *rest = raw.split(".")
        if head in self.aliases:
            mapped = self.aliases[head]
            tail = ".".join(rest)
            return f"{mapped}.{tail}".strip(".") if tail else mapped
        return raw


class _Summarizer(ast.NodeVisitor):
    def __init__(self, *, known_functions: Set[str], summaries: Dict[str, FunctionSummary], sinks: List[SinkSpec]) -> None:
        self.known_functions = known_functions
        self.summaries = summaries
        self.sinks = sinks
        self.resolver = _Resolver()
        self.env = _Env()
        self.return_params: Set[int] = set()
        self.return_dict: Dict[str, Set[TaintLabel]] = {}
        self.sink_templates: List[SinkTemplate] = []
        self.param_name_to_index: Dict[str, int] = {}

    def _expr_labels(self, node: ast.AST) -> Set[TaintLabel]:
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Subscript):
            # Key-sensitive dict access: data["safe"]
            dotted = _dotted_name(node.value)
            if dotted in TAINT_SOURCES:
                return {TaintLabel(origin=f"source:{dotted}", steps=(TraceStep("source", dotted, getattr(node, "lineno", None)),))}
            if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                key = node.slice.value
                labels = self.env.get_dict_key(node.value.id, key)
                if labels:
                    return labels

                # If the base is a parameter (param:i) and we don't have key-specific info,
                # produce a symbolic field label (paramkey:i:key) so sink templates can require that key.
                base_labels = self.env.get(node.value.id)
                out: Set[TaintLabel] = set()
                for lbl in base_labels:
                    if lbl.origin.startswith("param:"):
                        idx = int(lbl.origin.split(":", 1)[1])
                        out.add(
                            TaintLabel(
                                origin=f"paramkey:{idx}:{key}",
                                steps=lbl.steps + (TraceStep("prop", f"subscript[{key!r}]", getattr(node, "lineno", None)),),
                            )
                        )
                return out
            # Unknown key/index: conservative.
            return self._expr_labels(node.value) | self._expr_labels(node.slice)
        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if dotted and dotted in TAINT_SOURCES:
                return {TaintLabel(origin=f"source:{dotted}", steps=(TraceStep("source", dotted, getattr(node, "lineno", None)),))}
            return self._expr_labels(node.value)
        if isinstance(node, ast.Call):
            call_name = self.resolver.resolve(node.func)
            if call_name in TAINT_SOURCES or any(call_name.endswith(s) for s in TAINT_SOURCES):
                return {TaintLabel(origin=f"source:{call_name}", steps=(TraceStep("source", call_name, getattr(node, "lineno", None)),))}

            # Sanitizers remove taint from their outputs.
            # If tainted data enters sanitizer args/receiver, output is treated as untainted.
            if _is_sanitizer_call(node.func, call_name):
                return set()

            # Local function call: return taint from summary.
            if isinstance(node.func, ast.Name) and node.func.id in self.known_functions:
                callee = node.func.id
                summ = self.summaries.get(callee)
                if summ:
                    out: Set[TaintLabel] = set()
                    for i, arg in enumerate(node.args):
                        if i in summ.return_params:
                            for lbl in self._expr_labels(arg):
                                out.add(lbl.extend("call", f"{callee}() return", getattr(node, "lineno", None)))
                    return out

                # Unknown summary yet: conservative.
                out: Set[TaintLabel] = set()
                for a in node.args:
                    for lbl in self._expr_labels(a):
                        out.add(lbl.extend("call", f"{callee}()", getattr(node, "lineno", None)))
                return out

            # Conservative: return taint if any arg is tainted.
            out: Set[TaintLabel] = set()
            for a in list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]:
                for lbl in self._expr_labels(a):
                    out.add(lbl.extend("call", call_name or "call", getattr(node, "lineno", None)))
            return out
        if isinstance(node, ast.JoinedStr):
            out: Set[TaintLabel] = set()
            for v in node.values:
                out |= self._expr_labels(v)
            if out:
                return {lbl.extend("prop", "f-string", getattr(node, "lineno", None)) for lbl in out}
            return set()
        if isinstance(node, ast.FormattedValue):
            return self._expr_labels(node.value)
        if isinstance(node, ast.BinOp):
            out = self._expr_labels(node.left) | self._expr_labels(node.right)
            if out:
                return {lbl.extend("prop", "binop", getattr(node, "lineno", None)) for lbl in out}
            return set()
        if isinstance(node, ast.BoolOp):
            out: Set[TaintLabel] = set()
            for v in node.values:
                out |= self._expr_labels(v)
            if out:
                return {lbl.extend("prop", "boolop", getattr(node, "lineno", None)) for lbl in out}
            return set()
        if isinstance(node, ast.Compare):
            out: Set[TaintLabel] = set()
            out |= self._expr_labels(node.left)
            for c in node.comparators:
                out |= self._expr_labels(c)
            if out:
                return {lbl.extend("prop", "compare", getattr(node, "lineno", None)) for lbl in out}
            return set()
        return set()

    def visit_Import(self, node: ast.Import) -> None:
        self.resolver.on_import(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.resolver.on_importfrom(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Special-case: assign from a local function returning a dict literal summary.
        call_return_dict: Optional[Dict[str, Set[TaintLabel]]] = None
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id in self.known_functions:
            callee = node.value.func.id
            summ = self.summaries.get(callee)
            if summ and summ.return_dict:
                call_return_dict = {}
                for k, ls in summ.return_dict.items():
                    merged: Set[TaintLabel] = set()
                    for lbl in ls:
                        merged.add(lbl.extend("call", f"{callee}() return[{k!r}]", getattr(node.value, "lineno", None)))
                    call_return_dict[k] = merged

        labels = self._expr_labels(node.value)
        if labels:
            labels = {lbl.extend("assign", "=", getattr(node, "lineno", None)) for lbl in labels}
        for t in node.targets:
            # Dict key assignment: data["poison"] = input()
            if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str):
                self.env.set_dict_key(t.value.id, t.slice.value, set(labels))
                continue
            if isinstance(t, ast.Name):
                if call_return_dict is not None:
                    self.env.set_dict(t.id, call_return_dict)
                    continue
                # If assigning a dict literal, split taint by keys when possible.
                if isinstance(node.value, ast.Dict):
                    mapping: Dict[str, Set[TaintLabel]] = {}
                    unknown: Set[TaintLabel] = set()
                    for k_node, v_node in zip(node.value.keys, node.value.values):
                        v_labels = self._expr_labels(v_node)
                        if v_labels:
                            v_labels = {lbl.extend("assign", "dict_value", getattr(node, "lineno", None)) for lbl in v_labels}
                        if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                            mapping[k_node.value] = set(v_labels)
                        else:
                            unknown |= set(v_labels)

                    if mapping:
                        self.env.set_dict(t.id, mapping)
                    else:
                        self.env.clear(t.id)

                    # If there are unknown/dynamic keys, fall back to conservative scalar taint.
                    if unknown:
                        self.env.set(t.id, unknown)
                else:
                    self.env.set(t.id, set(labels))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        labels = self._expr_labels(node.value) if node.value is not None else set()
        if labels:
            labels = {lbl.extend("assign", "=", getattr(node, "lineno", None)) for lbl in labels}
        if isinstance(node.target, ast.Subscript) and isinstance(node.target.value, ast.Name) and isinstance(node.target.slice, ast.Constant) and isinstance(node.target.slice.value, str):
            self.env.set_dict_key(node.target.value.id, node.target.slice.value, set(labels))
        elif isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id in self.known_functions:
                callee = node.value.func.id
                summ = self.summaries.get(callee)
                if summ and summ.return_dict:
                    call_return_dict = {}
                    for k, ls in summ.return_dict.items():
                        merged: Set[TaintLabel] = set()
                        for lbl in ls:
                            merged.add(lbl.extend("call", f"{callee}() return[{k!r}]", getattr(node.value, "lineno", None)))
                        call_return_dict[k] = merged
                    self.env.set_dict(node.target.id, call_return_dict)
                    self.generic_visit(node)
                    return
            if isinstance(node.value, ast.Dict):
                mapping: Dict[str, Set[TaintLabel]] = {}
                unknown: Set[TaintLabel] = set()
                for k_node, v_node in zip(node.value.keys, node.value.values):
                    v_labels = self._expr_labels(v_node)
                    if v_labels:
                        v_labels = {lbl.extend("assign", "dict_value", getattr(node, "lineno", None)) for lbl in v_labels}
                    if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                        mapping[k_node.value] = set(v_labels)
                    else:
                        unknown |= set(v_labels)
                if mapping:
                    self.env.set_dict(node.target.id, mapping)
                else:
                    self.env.clear(node.target.id)
                if unknown:
                    self.env.set(node.target.id, unknown)
            else:
                self.env.set(node.target.id, set(labels))
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        const = _const_bool(node.test)
        if const is False:
            # Dead body: skip, but still analyze else-branch if present.
            for stmt in node.orelse:
                self.visit(stmt)
            return
        if const is True:
            for stmt in node.body:
                self.visit(stmt)
            return
        # Unknown condition: conservative (analyze both).
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        return

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is None:
            return
        # Dict literal return: keep key-specific labels for interprocedural field-sensitive propagation.
        if isinstance(node.value, ast.Dict):
            mapping: Dict[str, Set[TaintLabel]] = {}
            for k_node, v_node in zip(node.value.keys, node.value.values):
                if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                    v_labels = self._expr_labels(v_node)
                    if v_labels:
                        v_labels = {lbl.extend("prop", f"return[{k_node.value!r}]", getattr(node, "lineno", None)) for lbl in v_labels}
                    mapping[k_node.value] = set(v_labels)
            if mapping:
                self.return_dict = mapping
            self.generic_visit(node)
            return
        for lbl in self._expr_labels(node.value):
            if lbl.origin.startswith("param:"):
                self.return_params.add(int(lbl.origin.split(":", 1)[1]))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self.resolver.resolve(node.func)

        # Pull callee sink templates into caller summary (interprocedural).
        if isinstance(node.func, ast.Name) and node.func.id in self.known_functions:
            callee = node.func.id
            summ = self.summaries.get(callee)
            if summ:
                for templ in summ.sink_templates:
                    if templ.param_index < len(node.args):
                        for lbl in self._expr_labels(node.args[templ.param_index]):
                            if lbl.origin.startswith("param:"):
                                caller_idx = int(lbl.origin.split(":", 1)[1])
                                steps = lbl.steps + (TraceStep("call", f"{callee}()", getattr(node, "lineno", None)),) + templ.steps_from_param[1:]
                                self.sink_templates.append(
                                    SinkTemplate(
                                        param_index=caller_idx,
                                        key=templ.key,
                                        rule_id=templ.rule_id,
                                        title=templ.title,
                                        severity=templ.severity,
                                        sink_call=templ.sink_call,
                                        sink_lineno=templ.sink_lineno,
                                        steps_from_param=steps,
                                    )
                                )

        # Record direct sinks reached inside this function (param-derived).
        any_tainted = False
        arg_labels: List[Set[TaintLabel]] = []
        for a in list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]:
            ls = self._expr_labels(a)
            arg_labels.append(ls)
            any_tainted = any_tainted or bool(ls)

        shell_true = False
        if call_name in ("subprocess.run", "subprocess.Popen"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True

        for spec in self.sinks:
            if spec.rule_id == "PY003":
                if call_name in spec.names and shell_true:
                    for ls in arg_labels:
                        for lbl in ls:
                            if lbl.origin.startswith("param:"):
                                idx = int(lbl.origin.split(":", 1)[1])
                                steps = lbl.steps + (TraceStep("sink", f"{call_name}(shell=True)", getattr(node, "lineno", None)),)
                                self.sink_templates.append(
                                    SinkTemplate(idx, None, spec.rule_id, spec.title, clamp01(spec.severity), f"{call_name}(shell=True)", getattr(node, "lineno", None), steps)
                                )
                continue

            if call_name and any(_sink_name_matches(call_name, n) for n in spec.names):
                for ls in arg_labels:
                    for lbl in ls:
                        key_req: Optional[str] = None
                        if lbl.origin.startswith("paramkey:"):
                            # paramkey:<idx>:<key>
                            _, idx_s, key_req = lbl.origin.split(":", 2)
                            idx = int(idx_s)
                        elif lbl.origin.startswith("param:"):
                            idx = int(lbl.origin.split(":", 1)[1])
                        else:
                            continue
                        sev = spec.severity + (0.10 if any_tainted else 0.0)
                        if call_name in ("os.system", "subprocess.run", "subprocess.call") and node.args and _is_constant_str(node.args[0]):
                            sev = max(0.20, sev - 0.35)
                        steps = lbl.steps + (TraceStep("sink", call_name, getattr(node, "lineno", None)),)
                        self.sink_templates.append(
                            SinkTemplate(idx, key_req, spec.rule_id, spec.title, clamp01(sev), call_name, getattr(node, "lineno", None), steps)
                        )
                break

        self.generic_visit(node)


class _Instantiator(ast.NodeVisitor):
    def __init__(self, *, known_functions: Set[str], summaries: Dict[str, FunctionSummary], sinks: List[SinkSpec]) -> None:
        self.known_functions = known_functions
        self.summaries = summaries
        self.sinks = sinks
        self.resolver = _Resolver()
        self.env = _Env()
        self.findings: List[StructuralFinding] = []

    def _expr_labels(self, node: ast.AST) -> Set[TaintLabel]:
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Subscript):
            dotted = _dotted_name(node.value)
            if dotted in TAINT_SOURCES:
                return {TaintLabel(origin=f"source:{dotted}", steps=(TraceStep("source", dotted, getattr(node, "lineno", None)),))}
            if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                return self.env.get_dict_key(node.value.id, node.slice.value)
            return self._expr_labels(node.value) | self._expr_labels(node.slice)
        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if dotted and dotted in TAINT_SOURCES:
                return {TaintLabel(origin=f"source:{dotted}", steps=(TraceStep("source", dotted, getattr(node, "lineno", None)),))}
            return self._expr_labels(node.value)
        if isinstance(node, ast.Call):
            call_name = self.resolver.resolve(node.func)
            if call_name in TAINT_SOURCES or any(call_name.endswith(s) for s in TAINT_SOURCES):
                return {TaintLabel(origin=f"source:{call_name}", steps=(TraceStep("source", call_name, getattr(node, "lineno", None)),))}

            # Sanitizers remove taint from their outputs.
            if _is_sanitizer_call(node.func, call_name):
                return set()

            if isinstance(node.func, ast.Name) and node.func.id in self.known_functions:
                callee = node.func.id
                summ = self.summaries.get(callee)

                # Instantiate sink templates inside callee.
                if summ:
                    for templ in summ.sink_templates:
                        if templ.param_index < len(node.args):
                            if templ.key is not None and isinstance(node.args[templ.param_index], ast.Name):
                                arg_labels = self.env.get_dict_key(node.args[templ.param_index].id, templ.key)
                            else:
                                arg_labels = self._expr_labels(node.args[templ.param_index])
                            for lbl in arg_labels:
                                merged = TaintLabel(lbl.origin, lbl.steps + (TraceStep("call", f"{callee}()", getattr(node, "lineno", None)),) + templ.steps_from_param[1:])
                                self._emit_template_finding(templ, merged, callsite_lineno=getattr(node, "lineno", None))

                # Return labels from summary.
                out: Set[TaintLabel] = set()
                if summ:
                    for i, arg in enumerate(node.args):
                        if i in summ.return_params:
                            for lbl in self._expr_labels(arg):
                                out.add(lbl.extend("call", f"{callee}() return", getattr(node, "lineno", None)))
                    # If callee returns a dict, conservatively union key labels for expression usage.
                    for ls in summ.return_dict.values():
                        for lbl in ls:
                            out.add(lbl.extend("call", f"{callee}() return", getattr(node, "lineno", None)))
                else:
                    for a in node.args:
                        for lbl in self._expr_labels(a):
                            out.add(lbl.extend("call", f"{callee}()", getattr(node, "lineno", None)))
                return out

            out: Set[TaintLabel] = set()
            for a in list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]:
                for lbl in self._expr_labels(a):
                    out.add(lbl.extend("call", call_name or "call", getattr(node, "lineno", None)))
            return out
        if isinstance(node, ast.JoinedStr):
            out: Set[TaintLabel] = set()
            for v in node.values:
                out |= self._expr_labels(v)
            if out:
                return {lbl.extend("prop", "f-string", getattr(node, "lineno", None)) for lbl in out}
            return set()
        if isinstance(node, ast.FormattedValue):
            return self._expr_labels(node.value)
        if isinstance(node, ast.BinOp):
            out = self._expr_labels(node.left) | self._expr_labels(node.right)
            if out:
                return {lbl.extend("prop", "binop", getattr(node, "lineno", None)) for lbl in out}
            return set()
        if isinstance(node, ast.BoolOp):
            out: Set[TaintLabel] = set()
            for v in node.values:
                out |= self._expr_labels(v)
            if out:
                return {lbl.extend("prop", "boolop", getattr(node, "lineno", None)) for lbl in out}
            return set()
        if isinstance(node, ast.Compare):
            out: Set[TaintLabel] = set()
            out |= self._expr_labels(node.left)
            for c in node.comparators:
                out |= self._expr_labels(c)
            if out:
                return {lbl.extend("prop", "compare", getattr(node, "lineno", None)) for lbl in out}
            return set()
        return set()

    def _emit_template_finding(self, templ: SinkTemplate, lbl: TaintLabel, *, callsite_lineno: Optional[int]) -> None:
        path = _labels_to_path_strings(lbl)
        msg = f"Tainted data reaches sink {templ.sink_call} across function boundaries."
        if callsite_lineno and templ.sink_lineno:
            msg += f" Callsite L{callsite_lineno} -> sink L{templ.sink_lineno}."
        if templ.key:
            msg += f" (field={templ.key!r})"
        self.findings.append(
            StructuralFinding(
                rule_id=templ.rule_id,
                title=templ.title,
                severity=clamp01(templ.severity),
                lineno=templ.sink_lineno,
                col_offset=None,
                message=msg,
                extra={"call": templ.sink_call, "tainted_args": True, "field": templ.key, "paths": [path]},
            )
        )

    def _add_direct_finding(self, *, spec: SinkSpec, node: ast.AST, message: str, path: List[str], severity: float) -> None:
        self.findings.append(
            StructuralFinding(
                rule_id=spec.rule_id,
                title=spec.title,
                severity=clamp01(severity),
                lineno=getattr(node, "lineno", None),
                col_offset=getattr(node, "col_offset", None),
                message=message,
                extra={"call": self.resolver.resolve(node.func) if isinstance(node, ast.Call) else "", "tainted_args": True, "paths": [path]},
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        self.resolver.on_import(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.resolver.on_importfrom(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Special-case: assign from a local function returning a dict literal summary.
        call_return_dict: Optional[Dict[str, Set[TaintLabel]]] = None
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id in self.known_functions:
            callee = node.value.func.id
            summ = self.summaries.get(callee)
            if summ and summ.return_dict:
                call_return_dict = {}
                for k, ls in summ.return_dict.items():
                    merged: Set[TaintLabel] = set()
                    for lbl in ls:
                        merged.add(lbl.extend("call", f"{callee}() return[{k!r}]", getattr(node.value, "lineno", None)))
                    call_return_dict[k] = merged

        labels = self._expr_labels(node.value)
        if labels:
            labels = {lbl.extend("assign", "=", getattr(node, "lineno", None)) for lbl in labels}
        for t in node.targets:
            if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str):
                self.env.set_dict_key(t.value.id, t.slice.value, set(labels))
                continue
            if isinstance(t, ast.Name):
                if call_return_dict is not None:
                    self.env.set_dict(t.id, call_return_dict)
                    continue
                if isinstance(node.value, ast.Dict):
                    mapping: Dict[str, Set[TaintLabel]] = {}
                    unknown: Set[TaintLabel] = set()
                    for k_node, v_node in zip(node.value.keys, node.value.values):
                        v_labels = self._expr_labels(v_node)
                        if v_labels:
                            v_labels = {lbl.extend("assign", "dict_value", getattr(node, "lineno", None)) for lbl in v_labels}
                        if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                            mapping[k_node.value] = set(v_labels)
                        else:
                            unknown |= set(v_labels)

                    if mapping:
                        self.env.set_dict(t.id, mapping)
                    else:
                        self.env.clear(t.id)

                    if unknown:
                        self.env.set(t.id, unknown)
                else:
                    self.env.set(t.id, set(labels))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        labels = self._expr_labels(node.value) if node.value is not None else set()
        if labels:
            labels = {lbl.extend("assign", "=", getattr(node, "lineno", None)) for lbl in labels}
        if isinstance(node.target, ast.Subscript) and isinstance(node.target.value, ast.Name) and isinstance(node.target.slice, ast.Constant) and isinstance(node.target.slice.value, str):
            self.env.set_dict_key(node.target.value.id, node.target.slice.value, set(labels))
        elif isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id in self.known_functions:
                callee = node.value.func.id
                summ = self.summaries.get(callee)
                if summ and summ.return_dict:
                    call_return_dict = {}
                    for k, ls in summ.return_dict.items():
                        merged: Set[TaintLabel] = set()
                        for lbl in ls:
                            merged.add(lbl.extend("call", f"{callee}() return[{k!r}]", getattr(node.value, "lineno", None)))
                        call_return_dict[k] = merged
                    self.env.set_dict(node.target.id, call_return_dict)
                    self.generic_visit(node)
                    return
            if isinstance(node.value, ast.Dict):
                mapping: Dict[str, Set[TaintLabel]] = {}
                unknown: Set[TaintLabel] = set()
                for k_node, v_node in zip(node.value.keys, node.value.values):
                    v_labels = self._expr_labels(v_node)
                    if v_labels:
                        v_labels = {lbl.extend("assign", "dict_value", getattr(node, "lineno", None)) for lbl in v_labels}
                    if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                        mapping[k_node.value] = set(v_labels)
                    else:
                        unknown |= set(v_labels)
                if mapping:
                    self.env.set_dict(node.target.id, mapping)
                else:
                    self.env.clear(node.target.id)
                if unknown:
                    self.env.set(node.target.id, unknown)
            else:
                self.env.set(node.target.id, set(labels))
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        const = _const_bool(node.test)
        if const is False:
            for stmt in node.orelse:
                self.visit(stmt)
            return
        if const is True:
            for stmt in node.body:
                self.visit(stmt)
            return
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        return

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # New scope for function locals (we still allow sources inside to taint locals).
        prev_env = self.env
        self.env = _Env()
        # Params start untainted in concrete execution, unless a caller passes tainted values.
        for a in node.args.posonlyargs + node.args.args:
            self.env.set(a.arg, set())
        for stmt in node.body:
            self.visit(stmt)
        self.env = prev_env

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self.resolver.resolve(node.func)
        args = list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]
        labels_by_arg = [self._expr_labels(a) for a in args]
        any_tainted = any(bool(s) for s in labels_by_arg)

        # If this is a local function call (even as a statement), instantiate callee sink templates.
        if isinstance(node.func, ast.Name) and node.func.id in self.known_functions:
            callee = node.func.id
            summ = self.summaries.get(callee)
            if summ:
                for templ in summ.sink_templates:
                    if templ.param_index < len(node.args):
                        if templ.key is not None and isinstance(node.args[templ.param_index], ast.Name):
                            arg_ls = self.env.get_dict_key(node.args[templ.param_index].id, templ.key)
                        else:
                            arg_ls = self._expr_labels(node.args[templ.param_index])
                        for lbl in arg_ls:
                            merged = TaintLabel(
                                lbl.origin,
                                lbl.steps + (TraceStep("call", f"{callee}()", getattr(node, "lineno", None)),) + templ.steps_from_param[1:],
                            )
                            self._emit_template_finding(templ, merged, callsite_lineno=getattr(node, "lineno", None))

        shell_true = False
        if call_name in ("subprocess.run", "subprocess.Popen"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True

        for spec in self.sinks:
            if spec.rule_id == "PY003":
                if call_name in spec.names and shell_true and any_tainted:
                    best = _pick_best(set().union(*labels_by_arg))
                    self._add_direct_finding(
                        spec=spec,
                        node=node,
                        message=f"Shell-enabled subprocess call detected: {call_name} (shell=True).",
                        path=_labels_to_path_strings(best) + [f"sink:{call_name}(shell=True)@L{getattr(node,'lineno',None)}"],
                        severity=spec.severity + 0.05,
                    )
                continue

            if call_name and any(_sink_name_matches(call_name, n) for n in spec.names):
                if not any_tainted:
                    break
                best = _pick_best(set().union(*labels_by_arg))
                sev = spec.severity + 0.10
                msg = f"Risky call detected: {call_name}. One or more arguments appear tainted by user-controlled input."
                if call_name in ("os.system", "subprocess.run", "subprocess.call") and node.args and _is_constant_str(node.args[0]):
                    sev = max(0.20, sev - 0.35)
                    msg += " Argument looks constant; severity reduced."
                self._add_direct_finding(spec=spec, node=node, message=msg, path=_labels_to_path_strings(best) + [f"sink:{call_name}@L{getattr(node,'lineno',None)}"], severity=sev)
                break

        self.generic_visit(node)


class StructuralEngine:
    """
    Heimdall Structural Engine (AST + Interprocedural Taint).

    What it does:
    - Identify Sources (input/request/sys.argv/os.environ...)
    - Track propagation across assignments/expressions
    - Summarize local functions (fixpoint) to propagate taint across calls
    - Emit findings with an explicit Source → ... → Sink path

    Intent:
    - Move beyond pattern matching: capture *logic* + *data flow* evidence.
    """

    def __init__(self, *, sinks: Optional[Iterable[SinkSpec]] = None) -> None:
        self.sinks = list(sinks) if sinks is not None else list(DEFAULT_SINKS)

    def analyze(self, code: str) -> StructuralResult:
        code = code or ""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return StructuralResult(
                score=0.10,
                findings=[
                    StructuralFinding(
                        rule_id="PY000",
                        title="Syntax error",
                        severity=0.10,
                        lineno=getattr(e, "lineno", None),
                        col_offset=getattr(e, "offset", None),
                        message=f"Unable to parse code with ast.parse: {e}",
                        extra={},
                    )
                ],
            )

        func_nodes: Dict[str, ast.FunctionDef] = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        known_functions = set(func_nodes.keys())

        summaries: Dict[str, FunctionSummary] = {n: FunctionSummary(return_params=set(), return_dict={}, sink_templates=tuple()) for n in known_functions}

        # Fixpoint: summarize functions until stable (bounded iterations).
        for _ in range(10):
            changed = False
            for name, fn in func_nodes.items():
                summarizer = _Summarizer(known_functions=known_functions, summaries=summaries, sinks=self.sinks)
                summarizer.param_name_to_index = {a.arg: i for i, a in enumerate(fn.args.posonlyargs + fn.args.args)}
                # Seed param labels
                summarizer.env = _Env()
                for i, a in enumerate(fn.args.posonlyargs + fn.args.args):
                    summarizer.env.set(a.arg, {TaintLabel(origin=f"param:{i}", steps=(TraceStep("param", a.arg, getattr(fn, "lineno", None)),))})
                for stmt in fn.body:
                    summarizer.visit(stmt)
                new_sum = FunctionSummary(
                    return_params=set(summarizer.return_params),
                    return_dict=dict(summarizer.return_dict),
                    sink_templates=tuple(summarizer.sink_templates),
                )
                old_sum = summaries.get(name)
                if (
                    old_sum is None
                    or old_sum.return_params != new_sum.return_params
                    or old_sum.return_dict != new_sum.return_dict
                    or old_sum.sink_templates != new_sum.sink_templates
                ):
                    summaries[name] = new_sum
                    changed = True
            if not changed:
                break

        inst = _Instantiator(known_functions=known_functions, summaries=summaries, sinks=self.sinks)
        inst.visit(tree)
        findings = inst.findings

        if not findings:
            return StructuralResult(score=0.0, findings=[])

        complement = 1.0
        for f in findings:
            complement *= (1.0 - clamp01(f.severity) * 0.85)
        score = clamp01(1.0 - complement)
        return StructuralResult(score=score, findings=findings)

