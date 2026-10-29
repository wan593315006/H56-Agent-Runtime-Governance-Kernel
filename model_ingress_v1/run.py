"""Adapter 编排：意图 -> 模型选择 -> 严格校验 -> 原 CLI -> 原版四核。

这是一条单向管道，没有任何回环：
    模型只能产出「一个已登记的场景编号」或两种合法终局；
    校验不过，就地停止，不 spawn 任何进程；
    校验通过，才把场景编号交给既不认识模型、也不接受任何模型的 demo.py。

为什么这样切分：模型若能看到事实/证据/判定，它就可能「生成结果」而不是
「选择场景」；这条管道让它在结构上做不到——它唯一能影响的字节是一个 id。

阶段 A（离线验证）不发起任何网络请求：测试整体替换 provider._post。
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:  # 作为包导入（python -m model_ingress_v1.run）
    from . import prompt as prompt_mod
    from . import registry as registry_mod
    from . import validate as validate_mod
    from .provider import ProviderError
except ImportError:  # 直接运行脚本（python model_ingress_v1/run.py）
    sys.path.insert(0, str(Path(__file__).absolute().parent.parent))
    from model_ingress_v1 import prompt as prompt_mod
    from model_ingress_v1 import registry as registry_mod
    from model_ingress_v1 import validate as validate_mod
    from model_ingress_v1.provider import ProviderError

PRODUCT = Path(__file__).absolute().parent.parent
DEMO = PRODUCT / "demo.py"
EVIDENCE_SCHEMA = "H56_MODEL_SELECTION_EVIDENCE_V3"
CLI_TIMEOUT = 300

RAW_BODY_FILE = "model_response_raw.bin"
RAW_BODY_META = "model_response_raw.json"
ERROR_BODY_FILE = "model_error_raw.bin"
REQUEST_BODY_FILE = "model_request_body.json"
EVIDENCE_JSON = "model_selection_evidence.json"

# 传给内核子进程时一律剔除。内核既不需要、也不该看见模型端点与凭据。
# 用前缀而非固定名单：将来新增的任何 H56_MODEL_* 变量自动被剔除（失败关闭）。
ENV_PREFIX = "H56_MODEL_"

# 前缀之外的具名变量。NEBIUS_API_KEY 不匹配上面的前缀，必须单独点名，
# 否则它会随默认继承进入 demo.py 及其派生的每一个 Python 进程。
ENV_EXTRA_REMOVE = ("NEBIUS_API_KEY",)
# 注意这份名单只能是「已知的默认名」。密钥变量名可切（--key-env）之后，
# 静态名单追不上调用方实际使用的名字，所以调用方必须把本次选中的名字经
# `key_env=` 传进来（见 _kernel_env 的 extra_names）。名单不是安全边界，
# 传参才是；只加名单项而不传参，等于没修。


class EvidenceDirExists(Exception):
    """证据目录已存在。拒绝写入，避免覆盖既有证据。"""

# demo.py 在 --cases 模式下仍无条件执行 7 条性质，其中三条会额外发起 CLI 进程。
# 这是原驱动器既有行为，不由本 Adapter 触发，也不受模型影响。
#
# 每条的 evaluations 按 demo.py 源码逐行核对（行号为施工时点的值）：
#   P2  :519/:520  oq_idem 会话，C01 v0，request_id="same_req" 连提两次
#   P4  :553/:560  oq_chain 会话，B01 v0 parent_req 先提，C01 v0 child_req 带父引用
#   P6  :589-594   view 复演 oq_chain 的「首条事件」—— 即 :553 提交的 B01 v0，
#                  不是 C01 v0。（:559 用 store._events()[0] 取 reference）
# 注意：P4/P6 用的 request_id 是 parent_req/child_req，与主线的 "r1" 不同，
# 因此它们产生的 assessment_id 与所选场景的记录不是同一条，不能混为一谈。
DRIVER_REGRESSION = (
    {"property": "P2", "name": "同输入重复提交幂等", "processes": 2,
     "evaluations": ["C01 v0 / request_id=same_req（第一次）",
                     "C01 v0 / request_id=same_req（第二次）"]},
    {"property": "P4", "name": "补证后独立重评挂父引用", "processes": 2,
     "evaluations": ["B01 v0 / request_id=parent_req",
                     "C01 v0 / request_id=child_req（parent_ref=B01 记录）"]},
    {"property": "P6", "name": "view 只读复演不重算内核", "processes": 1,
     "evaluations": ["view 复演 oq_chain 首条事件 = B01 v0 / parent_req"]},
)

# 只有传入 --compare-python 时，P3 才会再加 1 个进程。本 Adapter 固定不传，
# 所以预算是 5；一旦有人给 demo.py 加了该参数，这个数会变成 6。
DRIVER_REGRESSION_WITH_COMPARE = 6


def regression_processes_per_case():
    """demo.py --cases 下 P2/P4/P6 额外发起的进程数（按源码结构推导）。"""
    return sum(d["processes"] for d in DRIVER_REGRESSION)


def counting_block(native_calls, observed_cli):
    """进程/调用统计的唯一构造点。三个数字各自标明来源，绝不混放。

    上一版把 `total_code_derived = 1 + 5 = 6` 当作推导总量，其中那个 1 其实是
    观测值；`a2_summary` 里 `cli_processes_derived = 36` 同样把 6 个观测值算进
    了「推导」里。这里把三者彻底分开：

    - observed_cli         ：本 Adapter 实际 spawn 的进程数（观测）
    - regression_derived   ：P2/P4/P6 的进程数（源码结构推导，非观测）
    - arithmetic_sum       ：两者之和（算术，不是任何人的观测）

    `observed_cli` 必须由调用方给出实测值。早前版本写成
    `observed = 1 if observed_cli is None else observed_cli`，于是落盘的
    `adapter_spawned_cli.value == 1` 虽然事实上正确，却是**写死的**，
    却标着 source=adapter_observed —— 常量冒充观测。现在没有默认值，
    不传就构造不出来。
    """
    derived = regression_processes_per_case()
    observed = observed_cli
    return {
        "adapter_spawned_cli": {
            "value": observed,
            "source": "adapter_observed",
            "meaning": ("本次调用中本 Adapter 实际发起的 demo.py 进程数。"
                        "由 spawn 包装器逐个自增计数得出，不是常量。"),
        },
        "driver_extra": {
            "value": derived,
            "source": "structural_declaration",
            "meaning": ("demo.py --cases 模式下 P2/P4/P6 额外发起的进程数，"
                        "按 demo.py 源码结构推导，不是逐进程观测；"
                        "evidence 中不存在这些进程的 PID 或命令行。"),
        },
        "arithmetic_sum": {
            "value": observed + derived,
            "source": "arithmetic",
            "meaning": ("adapter_spawned_cli + driver_extra 的算术结果。"
                        "它不是观测值：加数里只有一个来自观测，另一个来自推导。"
                        "引用时必须写成「观测 X + 推导 Y」，不得单独引用这个和。"),
        },
        "native_calls": {
            "value": native_calls,
            "source": "kernel_reported",
            "meaning": ("内核对四核的原生调用次数，由内核自己算出并写入记录；"
                        "本 Adapter 未独立计数，无法用进程观测复核。"),
        },
        "regression_evaluations_derived": {
            "value": derived,
            "source": "structural_declaration",
            "meaning": ("P2/P4/P6 各自的评估次数与进程数相同（每进程一次评估），"
                        "同属推导值，不可与 native_calls 相加。"),
        },
        "observed_total_available": False,
        "observed_total_note": ("若要得到观测总量，须由外层在 spawn 点计数；"
                                "A2 驱动（tests/a2_integration.py）即以此方式给出 "
                                "cli_processes_observed。本字段恒为 False，"
                                "表示单次 Adapter 调用本身不提供观测总量。"),
    }


def _sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def default_evidence_dir(stamp=None, label="rp1"):
    """证据目录在产品根之外，绝不写 evidence/**。

    名字里带 pid 与时间戳，且由 prepare_evidence_dir 以 exist_ok=False 创建：
    两次运行不可能落到同一个目录，因此不存在「覆盖上一次证据」的路径。
    """
    stamp = stamp or time.strftime("%Y%m%dT%H%M%S")
    return Path("C:/h56_release_evidence") / ("%s_%s_p%d" % (label, stamp, os.getpid()))


def prepare_evidence_dir(path):
    """新建独占目录。已存在即抛错，绝不复用、绝不覆盖。"""
    p = Path(path)
    if p.exists():
        raise EvidenceDirExists("证据目录已存在，拒绝覆盖：%s" % p)
    p.mkdir(parents=True, exist_ok=False)
    return p


def _kernel_env(environ=None, extra_names=()):
    """返回 (净化后的环境, 被剔除的变量名列表)。只记名字，绝不记值。

    这是「凭据不得继承到不需要它的 CLI 子进程」的实现点。默认的
    subprocess.run 会完整继承父进程环境，于是 H56_MODEL_API_KEY 会出现在
    demo.py 及其派生的每个 Python 进程里 —— 那些进程一个字节都不需要它。

    `extra_names` 是「本次实际使用的密钥变量名」。密钥变量名可切之后
    （`--key-env NVIDIA_API_KEY` 之类），静态名单 ENV_EXTRA_REMOVE 覆盖不到
    这些名字，而环境继承不看名字、照传不误。所以：**谁选的槽位，谁负责把
    名字传下来**。不传时只有前缀与静态名单生效 —— 这是默认路径的原行为，
    不是「已经安全」。
    """
    env = dict(os.environ if environ is None else environ)
    extra = set(ENV_EXTRA_REMOVE)
    for n in (extra_names or ()):
        if isinstance(n, str) and n:
            extra.add(n)
    removed = sorted(k for k in env
                     if k.startswith(ENV_PREFIX) or k in extra)
    for k in removed:
        env.pop(k, None)
    return env, removed


def _empty_evidence(intent, prov_model_id, registry_sha):
    return {
        "schema": EVIDENCE_SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "intent": {"text": intent, "sha256": _sha256_text(intent)},
        "call": None,
        "correlation_id": None,
        "request_contract": None,
        "request_body": {
            "file": None, "bytes": None, "sha256": None, "present": None,
            "sha256_recomputable_from_disk": False,
            "note": ("实际发出的请求体字节（不含鉴权头，故可原样留档）。"
                     "有了它，才能核对模型看到的输入就是本 Adapter 构造的输入，"
                     "而不是靠读代码推断。传输失败时同样留档。"),
        },
        "raw_body": {
            "file": None, "bytes": None,
            "sha256_recomputable_from_disk": False,
            "note": ("模型响应原始字节单独落盘；linkage.model_response_sha256 "
                     "可由该文件独立重算，不依赖本程序自报。"),
        },
        "raw_error_body": {
            "file": None, "bytes": None, "sha256": None, "http_status": None,
            "note": ("端点返回非 200 时的原始响应体。参数被拒时它是唯一的解释材料，"
                     "不得丢弃。"),
        },
        "adapter": {
            "decision": None, "code": None, "scenario_id": None,
            "model_decision": None, "reason": None, "confidence": None,
            "registry_sha256": registry_sha, "mapping": None,
            "requested_model_id": prov_model_id,
            "checks_passed": [],
            # 取值必须是这五个之一，且每条路径都要写，不能留 None：
            #   REJECTED_BY_TRANSPORT            传输失败（含 400/401/超时/跳转拒绝）
            #   REJECTED_BY_VALIDATION           响应没通过严格校验
            #   LEGAL_TERMINAL_<NOT_APPLICABLE|NEED_CLARIFICATION>
            #   MODEL_ERROR_SELECTED_WHERE_FORBIDDEN  合同禁止碰核心，模型却判了 SELECT
            #   SELECT_KERNEL_EXECUTED           合法 SELECT，内核已实际执行
            # 模板里必须有，否则证据结构会随走哪条路径而漂移，
            # 复核者只能靠"这个键不存在"来猜结论。
            "outcome": None,
        },
        "kernel": {
            "invoked": False, "exit_code": None, "demo_exit_code": None,
            "expected_cli_exit": None, "exit_code_matches": None,
            "kind": None, "value": None,
            "semantic_sha256": None, "record_path": None,
            "authority_granted": None, "execution_permitted": None,
            "candidate_planning_only": None, "native_calls": None,
            "selected_scenario": None, "driver_regression": None,
            "call_counting": None, "env_sanitized": None,
            # True 表示「请求合同禁止碰核心，内核一次都没启动」。
            # 与 invoked=False 分开记：invoked=False 可能是没走 SELECT，
            # 也可能是被合同拦下，两种事实不能共用一个字段。
            "suppressed_by_contract": False,
        },
        "linkage": {
            "model_response_sha256": None,
            "kernel_stdout_sha256": None,
            "kernel_returned_result": False,
            "kernel_produced_record": False,
            "chain": "model_response -> adapter_decision -> case_id/variant -> kernel_stdout",
            "chain_note": ("model_response_sha256 由本程序赋值。原始响应字节已单独存为 "
                           "model_response_raw.bin，因此该哈希可由磁盘独立重算，"
                           "无需信任本程序的赋值。"),
        },
        "notes": [],
    }


def _persist_request_body(evidence_dir, ev, body):
    """把实际发出的请求体落盘，并写回 ev["request_body"]。

    成功与失败都要调。失败那次最需要取证：参数被拒时，你要能证明
    「我发的就是这串字节」，而不是事后从代码里推断「应该发的是这串」。
    """
    if not body:
        ev["request_body"]["present"] = False
        ev["request_body"]["note"] = (
            "本次调用没有可留档的请求体（provider 未产生，例如固定 Mock）。"
            "此时无法核对模型看到的输入，只能核对响应侧。")
        return ev["request_body"]
    (Path(evidence_dir) / REQUEST_BODY_FILE).write_bytes(body)
    ev["request_body"].update({
        "file": REQUEST_BODY_FILE,
        "bytes": len(body),
        "sha256": _sha256_bytes(body),
        "sha256_recomputable_from_disk": True,
        "present": True,
        "note": ("实际发出的请求体字节（已剔除鉴权头）。"
                 "模型是否被引导，只能靠这份字节判断，不能靠读 prompt.py 推断。"),
    })
    return ev["request_body"]


def _spawn_kernel(python, scenario_id, evidence_dir, spawn, timeout,
                  expected_cli_exit=None, key_env=None):
    """只在校验通过且是 SELECT 时调用。返回 (kernel 段, stdout 字节, stderr 字节)。"""
    run_dir = evidence_dir / "run"
    report_path = run_dir / "report.json"
    cmd = [str(python), str(DEMO), "--cases", scenario_id,
           "--python", str(python),
           "--json", str(report_path),
           "--work-dir", str(run_dir), "--keep"]
    # 凭据不继承：内核既不需要 H56_MODEL_*，也不需要本次选用的那把密钥。
    # key_env 就是「本次选用的名字」，不传只剩默认名单 —— 见 _kernel_env 的说明。
    child_env, removed_env = _kernel_env(extra_names=((key_env,) if key_env else ()))
    # 真数一次：包装 spawn 逐个自增，计数由调用动作产生，不是字面量。
    spawned = {"n": 0}

    def _counting_spawn(*a, **kw):
        spawned["n"] += 1
        return spawn(*a, **kw)

    t0 = time.time()
    proc = _counting_spawn(cmd, capture_output=True, timeout=timeout,
                           cwd=str(PRODUCT), env=child_env)
    elapsed = round(time.time() - t0, 2)
    stdout_raw = proc.stdout if isinstance(proc.stdout, bytes) else (proc.stdout or "").encode()
    stderr_raw = proc.stderr if isinstance(proc.stderr, bytes) else (proc.stderr or "").encode()

    report = {}
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            report = {}

    rows = report.get("rows") or []
    row = rows[0] if rows else {}
    props = [{"id": p.get("id"), "name": p.get("name"), "status": p.get("status")}
             for p in (report.get("properties") or [])]

    # 退出码验收：CLI 退出码必须是整数，且等于登记表给出的期望值。
    # 把数值字段当布尔用（`assertTrue(exit_code)`）会把 0 判成失败、把 20 判成通过，
    # 所以这里显式记录类型与比较结果，供调用方用 `is True` / `is False` 断言。
    exit_code = row.get("exit")
    exit_type_ok = isinstance(exit_code, int) and not isinstance(exit_code, bool)
    if expected_cli_exit is None:
        exit_matches = None
        exit_verdict = "NO_EXPECTATION"
    elif not exit_type_ok:
        exit_matches = False
        exit_verdict = "NOT_AN_INT"
    elif exit_code == expected_cli_exit:
        exit_matches = True
        exit_verdict = "MATCH"
    else:
        exit_matches = False
        exit_verdict = "MISMATCH"

    regression_declared = sum(d["processes"] for d in DRIVER_REGRESSION)
    kernel = {
        "invoked": True,
        # exit_code 是 CLI 自己的退出码（内核真实退出码）；
        # demo_exit_code 是驱动器 demo.py 的退出码。两者不是一回事，
        # 混成一个字段会让复核者无法判断「这个 0 是谁的 0」。
        "exit_code": exit_code,
        "demo_exit_code": proc.returncode,
        "expected_cli_exit": expected_cli_exit,
        "exit_code_matches": exit_matches,
        "exit_acceptance": {
            "verdict": exit_verdict,
            "observed": exit_code,
            "observed_type": type(exit_code).__name__,
            "expected": expected_cli_exit,
            "expected_source": "model_ingress_v1/registry.json:expected_cli_exit",
            "rule": "CLI 退出码必须是 int（非 bool），且逐案例等于登记表中的期望值；不接受把数值当布尔。",
        },
        "elapsed_seconds": elapsed,
        "kind": row.get("kind"),
        "value": row.get("value"),
        "semantic_sha256": row.get("semantic_sha256"),
        "record_path": (str(report.get("work_dir")) if row.get("semantic_sha256") else None),
        "authority_granted": row.get("authority_granted"),
        "execution_permitted": row.get("execution_permitted"),
        "candidate_planning_only": row.get("candidate_planning_only"),
        "native_calls": row.get("native_calls"),
        "decision_id": row.get("decision_id"),
        "assessment_id": row.get("assessment_id"),
        "input_sha256": row.get("input_sha256"),
        "variant_note": row.get("variant_note"),
        "stop_status": row.get("stop_status"),
        "stop_stage": row.get("stop_stage"),
        "properties": props,
        "env_sanitized": {
            "removed_names": removed_env,
            "removed_count": len(removed_env),
            "values_recorded": False,
            "key_env_targeted": key_env,
            "rule": ("剔除 H56_MODEL_* 前缀、ENV_EXTRA_REMOVE 静态名单，"
                     "以及本次实际使用的密钥变量名（key_env_targeted）。"),
            "note": ("传给内核子进程的环境已按上述规则剔除；此处只记变量名，"
                     "不记任何值。key_env_targeted=None 表示调用方没指定，"
                     "此时只剔除前缀与静态名单里的默认名。"),
        },
        "call_counting": counting_block(row.get("native_calls"), spawned["n"]),
        "selected_scenario": {
            "scenario_id": scenario_id,
            "rows_returned": len(rows),
            "row_key": row.get("key"),
        },
        "driver_regression": {
            "note": ("demo.py 在 --cases 模式下仍无条件执行 7 条性质；其中 P2/P4/P6 "
                     "会额外发起 5 个 CLI 进程（传 --compare-python 时为 6 个，"
                     "本 Adapter 固定不传）。它们不向 report.rows 追加行，"
                     "也不计入所选场景的评估记录。"),
            "declared_processes": regression_declared,
            "declared_processes_if_compare_python": DRIVER_REGRESSION_WITH_COMPARE,
            "declared_detail": [dict(d) for d in DRIVER_REGRESSION],
            "observed_rows_from_regression": len(rows) - 1 if rows else 0,
            "attribution": "structural_declaration",
            "attribution_meaning": (
                "这 5 个进程是按 demo.py 源码结构声明的，不是本 Adapter 逐进程观测到的；"
                "evidence 中不存在 PID / 命令行 / 逐进程退出码（语义记录禁止这类键）。"
                "独立复核只能回到 demo.py 的 run_case 调用点核对。"),
            "shares_case_with_selected": row.get("key") in ("B01v0", "C01v0"),
            "shares_assessment_with_selected": False,
            "assessment_note": (
                "P4/P6 使用的 request_id（parent_req/child_req）与主线 'r1' 不同，"
                "产生的 assessment_id 与所选场景不是同一条记录，二者不可互相当证据。"),
        },
    }
    return kernel, stdout_raw, stderr_raw


def _provider_origin(prov):
    """记录本次响应的产出实现落在哪里。

    A3 复核指出：如果 provider 的实现在产品树之外，这条 evidence 就无法
    仅凭产品树复现。与其让复核者去猜，不如在证据里直接写出来。
    """
    cls = type(prov)
    impl = f"{cls.__module__}.{cls.__qualname__}"
    mod = sys.modules.get(cls.__module__)
    path = getattr(mod, "__file__", None)
    if not path:
        return {"impl": impl, "in_product_tree": False, "file": None}
    p = Path(path).absolute()
    try:
        p.relative_to(PRODUCT)
        inside = True
    except ValueError:
        inside = False
    return {"impl": impl, "in_product_tree": inside,
            "file": str(p),
            "reproducible_from_product_tree": inside}


def run(intent, prov, python=None, evidence_dir=None, registry_path=None,
        spawn=None, timeout=CLI_TIMEOUT, correlation_id=None,
        suppress_kernel_if_select=False, key_env=None):
    """完整走一遍。返回 evidence dict（同时落盘）。

    证据目录必须是新建的独占目录：已存在即抛 EvidenceDirExists，绝不覆盖。

    suppress_kernel_if_select：给「域外意图负对照」这类请求用。置 True 时，
    即使模型判出合法 SELECT，也**不得**启动内核 —— 因为这条请求的合同就是
    「不许碰核心」。默认 False，通用 Adapter 的合法 SELECT 语义不受影响。

    key_env：本次实际使用的密钥**变量名**（不是值）。它只用于一件事——
    启动内核前把该变量从子进程环境里剔除。取值的槽位由调用方决定（阶段 B
    用 --key-env 决定），本函数不读它的值，也不校验它的存在。
    """
    python = python or sys.executable
    evidence_dir = Path(evidence_dir) if evidence_dir else default_evidence_dir()
    spawn = spawn or subprocess.run
    prepare_evidence_dir(evidence_dir)

    scenarios = registry_mod.load(registry_path)
    reg_sha = registry_mod.registry_sha256(registry_path)
    ev = _empty_evidence(intent, prov.model_id, reg_sha)
    ev["correlation_id"] = correlation_id
    ev["request_contract"] = {
        "suppress_kernel_if_select": bool(suppress_kernel_if_select),
        "note": ("True 表示本条请求无论模型给出什么，都不许启动内核；"
                 "若模型仍返回合法 SELECT，按「真实模型错误」记录并终止，"
                 "而不是先启动内核再宣布零调用。"),
    }

    # 1. 请求模型
    try:
        call = prov.complete(prompt_mod.build(intent, scenarios),
                             correlation_id=correlation_id)
    except ProviderError as exc:
        ev["call"] = {
            "provider": getattr(exc, "provider", None),
            "correlation_id": getattr(exc, "correlation_id", correlation_id),
            "approved_origin": getattr(exc, "origin", None),
            "model_id": getattr(prov, "model_id", None),
            "attempts": getattr(exc, "attempts", 1),
            "http_status": getattr(exc, "http_status", None),
            "transport_error": exc.detail,
            "request_body_sha256": getattr(exc, "request_body_sha256", None),
            "provider_impl": _provider_origin(prov),
        }
        ev["adapter"]["decision"] = "REJECTED"
        ev["adapter"]["outcome"] = "REJECTED_BY_TRANSPORT"
        ev["adapter"]["code"] = exc.code
        ev["adapter"]["detail"] = exc.detail
        ev["adapter"]["attempts"] = getattr(exc, "attempts", 1)
        ev["notes"].append("传输失败即终止：未重试、未 fallback、未调用 CLI。")
        # 失败也要留请求体：这是"我发的就是这串字节"的唯一证据。
        _persist_request_body(evidence_dir, ev, getattr(exc, "request_body", b""))
        err_raw = getattr(exc, "raw", b"") or b""
        if err_raw:
            # 参数被拒 / 端点报错时，响应体是唯一能说明原因的材料，必须留档。
            (evidence_dir / ERROR_BODY_FILE).write_bytes(err_raw)
            ev["raw_error_body"] = {
                "file": ERROR_BODY_FILE,
                "bytes": len(err_raw),
                "sha256": _sha256_bytes(err_raw),
                "http_status": getattr(exc, "http_status", None),
                "note": ("非 200 的原始响应体。它不含本程序的任何凭据，可原样复核。"),
            }
        else:
            ev["raw_error_body"]["note"] = (
                "本次失败没有响应体（超时 / 连接失败 / 跳转被拒都会如此）。"
                "此时只有请求侧证据可取。")
        _write(evidence_dir, ev)
        return ev

    # 原始字节先落盘，再解析。顺序要紧：先有字节，后有判断，
    # 这样 linkage 里的哈希永远可以从磁盘重算，而不是只能相信本程序。
    req_body = call.get("request_body") or b""
    _persist_request_body(evidence_dir, ev, req_body)
    raw_body = call.get("body") or b""
    (evidence_dir / RAW_BODY_FILE).write_bytes(raw_body)
    ev["raw_body"] = {
        "file": RAW_BODY_FILE,
        "bytes": len(raw_body),
        "sha256": _sha256_bytes(raw_body),
        "sha256_recomputable_from_disk": True,
        "note": ("模型响应原始字节；sha256 即 linkage.model_response_sha256 的独立重算源。"),
    }
    ev["linkage"]["model_response_sha256"] = _sha256_bytes(raw_body)
    (evidence_dir / RAW_BODY_META).write_text(
        json.dumps({
            "provider": call.get("provider"),
            "endpoint_host": call.get("endpoint_host"),
            "approved_origin": call.get("approved_origin"),
            "model_id": call.get("model_id"),
            "request_type": call.get("request_type"),
            "attempts": call.get("attempts"),
            "http_status": call.get("http_status"),
            "request_sha256": call.get("request_sha256"),
            "request_body_file": REQUEST_BODY_FILE if req_body else None,
            "request_body_sha256": call.get("request_body_sha256"),
            "request_params": call.get("request_params"),
            "thinking": call.get("thinking"),
            "finish_reason": call.get("finish_reason"),
            "content_chars": call.get("content_chars"),
            "reasoning_field": call.get("reasoning_field"),
            "reasoning_chars": call.get("reasoning_chars"),
            "response_id": call.get("response_id"),
            "response_sha256": call.get("response_sha256"),
            "raw_body_file": RAW_BODY_FILE,
            "raw_body_bytes": len(raw_body),
        }, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    ev["call"] = {k: v for k, v in call.items()
                  if k not in ("body", "request_body")}
    ev["call"]["provider_impl"] = _provider_origin(prov)
    if not ev["call"]["provider_impl"].get("in_product_tree"):
        ev["notes"].append(
            "provider 实现在产品树之外：本 evidence 不能仅凭 C:\\h56 复现，"
            "必须同时取得该实现文件。")

    # 2. 严格校验
    verdict = validate_mod.validate_response(
        call["body"], prov.model_id, registry_mod.ids(registry_path))
    ev["adapter"].update({
        "decision": verdict["decision"],
        "code": verdict["code"],
        "scenario_id": verdict["scenario_id"],
        "model_decision": verdict["model_decision"],
        "reason": verdict["reason"],
        "confidence": verdict["confidence"],
        "checks_passed": verdict["checks_passed"],
        "detail": verdict["detail"],
    })
    if verdict["authority_pattern"]:
        ev["adapter"]["authority_pattern"] = verdict["authority_pattern"]
        ev["notes"].append("越权表述被拦截，按安全事件记录。")

    if verdict["decision"] != "ACCEPTED":
        ev["adapter"]["outcome"] = "REJECTED_BY_VALIDATION"
        ev["notes"].append("校验未通过：未调用 CLI，未产生任何内核结果。")
        _write(evidence_dir, ev)
        return ev

    if verdict["model_decision"] != "SELECT":
        ev["adapter"]["outcome"] = "LEGAL_TERMINAL_%s" % verdict["model_decision"]
        ev["notes"].append(
            f"{verdict['model_decision']} 是合法终局：不调用 CLI，不记为失败。")
        _write(evidence_dir, ev)
        return ev

    # 请求合同禁止本条请求碰核心（域外意图负对照即此类）。
    # 判在这里而不是判在 spawn 之后：一旦启动内核，就已经违反了合同，
    # 事后再宣布「零调用」是自欺。
    if suppress_kernel_if_select:
        ev["adapter"]["outcome"] = "MODEL_ERROR_SELECTED_WHERE_FORBIDDEN"
        ev["kernel"]["invoked"] = False
        ev["kernel"]["suppressed_by_contract"] = True
        ev["linkage"]["kernel_returned_result"] = False
        ev["linkage"]["kernel_produced_record"] = False
        ev["notes"].append(
            "本条请求的合同是不许碰核心，模型却仍判出合法 SELECT（%s）。"
            "按真实模型错误记录并终止：内核一次都没启动，不是在启动之后宣布零调用。"
            % verdict["scenario_id"])
        _write(evidence_dir, ev)
        return ev

    # 3. 只有走到这里才碰产品
    rec = registry_mod.resolve(verdict["scenario_id"], registry_path)
    ev["adapter"]["mapping"] = {"case_id": rec["case_id"],
                                "variant": rec["variant"],
                                "registered_outcome": rec["registered_outcome"],
                                "expected_cli_exit": rec.get("expected_cli_exit")}
    kernel, out_raw, err_raw = _spawn_kernel(
        python, verdict["scenario_id"], evidence_dir, spawn, timeout,
        expected_cli_exit=rec.get("expected_cli_exit"), key_env=key_env)
    ev["adapter"]["outcome"] = "SELECT_KERNEL_EXECUTED"
    ev["kernel"] = kernel
    ev["linkage"]["kernel_stdout_sha256"] = _sha256_bytes(out_raw)
    ev["linkage"]["kernel_stderr_sha256"] = _sha256_bytes(err_raw)
    ev["linkage"]["kernel_returned_result"] = kernel.get("kind") is not None
    ev["linkage"]["kernel_produced_record"] = kernel.get("semantic_sha256") is not None

    # 4. 子进程原始输出单独留存（A3 外层复核用）
    (evidence_dir / "kernel_stdout.txt").write_bytes(out_raw)
    (evidence_dir / "kernel_stderr.txt").write_bytes(err_raw)
    _write(evidence_dir, ev)
    return ev


def _write(evidence_dir, ev):
    p = Path(evidence_dir) / EVIDENCE_JSON
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(ev, ensure_ascii=False, indent=2, sort_keys=True),
                   encoding="utf-8")
    tmp.replace(p)
