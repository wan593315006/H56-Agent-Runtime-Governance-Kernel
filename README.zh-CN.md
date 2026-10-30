> Candidate edition: the current assembled version is documented in [README.md](README.md), [RECOVERY_GUIDE.md](RECOVERY_GUIDE.md), [DEMO_GUIDE.md](DEMO_GUIDE.md) and [ARCHITECTURE.md](ARCHITECTURE.md). The Chinese text below preserves the earlier offline-edition notes; use the English candidate guides for the current model integration and recovery steps.

# H56 — 离线候选资格判定引擎

一个确定性的离线**候选资格判定**引擎：输入某环境的证据封套，跑完整四核原生推导链
（`K0 → K1 → C1 → C2`），输出一条**不可变、哈希钉住**的判定记录——同一条记录换一台机器、
换一个 Python 版本重算，语义摘要逐字节相同。

它只回答一个问题：*这个候选是「有条件可准入」、「被阻断」，还是「证据仍然不足」？*
并且**永不**授予权限、永不放行执行。

> English version: [README.md](README.md)

---

## 30 秒上手

只需要 **Python 3.9+** 与标准库。不用 pip、不用联网、不用 Docker、不用云。

```bash
git clone <本仓库> h56
cd h56
python -B demo.py
```

预期结尾：

```
[1] 结局与冻结基线一致        PASS  6/6
[2] 同输入重复提交幂等        PASS
[3] 跨 Python 版本字节一致    跳过（加 --compare-python）
[4] 补证后独立重评挂父引用    PASS
[5] 已封存记录字节不变        PASS
[6] view 只读复演不重算内核   PASS
[7] 授权边界未被越过          PASS

结果：PASS_WITH_SKIPS —— 6 项通过，1 项跳过
```

默认跑的是**六案例演示主线**，不是「挑几个快的」。这六条输入证据互不相同，覆盖引擎能给出的全部结局：

| 案例 | 结局 | 证据被改动的地方 |
|---|---|---|
| `B06v0` | REJECTED `ENV_INPUT_REJECTED` | 某字段的知识态被改写为自相矛盾的组合 |
| `A01v0` | DECIDED `INFEASIBLE` | `app_container=true`、`integrity_rid=4096` |
| `B05v0` | DECIDED `NEED_MORE_EVIDENCE` | 移除 `supporting_attestation` |
| `B01v0` | DECIDED `DEFER` | `outer_job_clear` 标记为 UNKNOWN |
| `B07v1` | DECIDED `FEASIBLE` | `outer_job_clear.observed_at` 前移 |
| `C01v0` | DECIDED `FEASIBLE` | 无改动（基准信封） |

每次运行都会打印每条案例的输入摘要与**具体到字段的改动**，因此「操作真的施加了」是可以核对的，
不需要读者相信一句声明。

跑全量并对比第二个解释器：

```bash
python -B demo.py --all --compare-python /另一个/python
python -B run_tests.py       # 单元测试 30 项
```

或者用浏览器驱动同一套演示（单页、零依赖、只监听 `127.0.0.1`）：

```bash
python -B ui/serve.py --compare-python /另一个/python
# → http://127.0.0.1:8765
```

页面会在**真实子进程**里执行 `demo.py --all`（不是回放录像）。顶部把**行数**与**有效覆盖**
分开呈现：56 行给出 42 DECIDED / 14 REJECTED，但其中只有 26 行的输入证据是互不相同的，
另外 30 行是同一信封的重复运行，按回归基线计，不按独立能力计。随后是三个可折叠面板：
判定详情、拒绝路径、证据链（每个文件可按 sha256 打开原始字节）。

---

## 权威树 —— 哪些结果算交付证据

只有在源码身份与**本仓库**冻结版本一致的工作树上执行的运行才计入交付证据。构建机上的冻结
副本与源码身份经核验一致的干净克隆属于同一棵树。文件系统路径本身不是权威。

| 树 | 状态 | 效果 |
|---|---|---|
| 本仓库 | **AUTHORITY_TREE** | 本 README 引用的每个数字都可在此复现 |
| `separation_workspace_v1/`（2026-10-26 分层重构，未随仓库交付） | **NOT_ON_AUTHORITY_TREE** | 该树上此前的全部结论均不作为交付证据——包括「25/25 选择器全绿」「19 PASS / 6 ERROR」「`_bounded` 修复」 |

那些结论对**那棵树**可能仍然成立，但它们不是本交付物的证据，两个方向都不能转移。
该重构未被采纳的原因是冻结时它并未完成：`runtime_windows` 的 51 个模块里有 22 个从未搬迁、
5 处 import 仍跨树指向、18 对同名文件字节已不一致（例如
`offline_qualification_v1/contracts.py`，少 1,439 字节）。在一棵树上通过测试，
不能说明另一棵树也是好的。

---

## 它到底做了什么

每个案件依次经过四步：

1. **校验来源身份** —— 每个原生模块在**被导入之前**先按 139 条 `SOURCE_MANIFEST.json`
   逐项校验哈希；由自定义 import finder 拦下未登记模块、`.pyc` 回退与 `sys.path` 遮蔽。
2. **推导状态** —— `K0` 构造规范事实与来源，`K1` 编译并校验状态快照。
3. **解析能力** —— `C1` 构造能力目录与定义，`C2` 结合状态、目录与上下文做可行性投影。
4. **封存记录** —— 规范 JSON 记录 + 语义摘要；记录只可追加，后续运行必须不改变其字节。

通过输入/来源门禁并产生记录的评估执行 **22 次原生核心调用**，每一次都带输入摘要与输出摘要
入账。拒绝路径会在写记录前停止，不得表述为完成了 22 次调用。

## 实测结果

用 `python -B demo.py --all --compare-python <py>` 可复算全部性质，包括可选的跨版本性质；未提供第二
解释器时，性质 3 必须报告为 `SKIP`，而不是跨版本通过。

| 衡量项 | 结果 |
|---|---|
| 合成案件 / 行数 | **31 / 56** |
| 被判定的行数 | **42**（见下方有效覆盖） |
| 设计内拒绝的行数 | **14**，覆盖 5 类原因码 |
| **有效覆盖：互不相同的输入** | **56 行中 26 条**；其余 **30 行重复同一信封** |
| **有效覆盖：去重后的结局分布** | FEASIBLE **2**、INFEASIBLE **5**、DEFER **4**、NEED_MORE_EVIDENCE **1**、REJECTED **14** |
| 每次已记录评估的原生调用 | **22**；拒绝路径不是 22 次调用 |
| `semantic_sha256` 跨 3.9.13 与 3.13.12 | **仅 C01；提供第二解释器时逐字节相同** |
| 单元测试 | **30 项双解释器全通过** |
| 导入前钉住哈希的来源成员 | **139** |
| 仓库规模 | 244 文件、0 语法错误 |

**42 / 14 要按回归行数读，不能读成 56 项独立能力。** 56 行里有 30 行的证据字节与 `C01v0`
完全相同——它们的变体键没有被 fixture 构造器消费，实际施加的输入就是基准信封，相同的
`semantic_sha256` 已经证明了这一点。保留这 30 行是为了让任何核心改动都以基线 diff 的形式暴露；
它们不计入有效覆盖。真正携带不同证据的只有 26 行，其中达到 `FEASIBLE` 的只有 **2 条**：
`C01v0`（基准）与 `B07v1`（真实变换）。

那 14 条拒绝**不是失败**，是拒斥路径在工作：`ENV_TASK_SCOPE_MISMATCH`、
`ENV_TIME_INVALID_OR_FUTURE`、`ENV_INPUT_REJECTED`、`ENV_EVIDENCE_CONFLICT`、
`ENV_SOURCE_OR_VERSION_MISMATCH`。一个不会拒绝的判定引擎没有价值，所以它们是正式结果。

## 边界：它明确做不到什么

引擎在设计上就没有行动能力。每次投影都断言：

```python
authority_granted      is False
execution_permitted    is False
candidate_planning_only is True
```

没有写入器、没有派发器、不 spawn、不联网、不碰凭据。判定是**规划输入**，不是授权。
这条限制写在代码里，并由演示的第 7 项性质断言，不只是文档承诺。

## 已知限制与暂缓项

这些写在这里，而不是等读者自己发现。没有任何一项被当作已完成能力呈现。

| 限制 | 状态 |
|---|---|
| 任务描述是 fixture 文件，不是模型输出 | `contracts.py` 把 `task_kind`/`origin`/`origin_record_ref` 钉死为合成字面量，其他取值一律拒绝。接真实模型会被引擎自己的合同拒掉。 |
| 证据等级为 `SYNTHETIC_ONLY`，环境角色为 `SIMULATED_OPERATOR_METADATA_HOST` | 由 `semantic_guard` 与 `seal()` 强制；`CURRENT_HOST` / `REAL_HOST` 按名拒绝。 |
| 不执行任何业务动作 | `business_action_calls` 恒为 0 并被硬断言。这是设计边界，不是未完成功能。 |
| 56 行里 30 行是信封重复 | 保留为回归行，不计入有效覆盖。 |
| 跨版本字节一致只证到 `C01` | 不外推到全部案例。 |
| 任务队列前门（`windows_frontdoor_v1_20261024`） | 占位实现：`kernel_port.py` 恒抛 `WINDOWS_CORE_RUNTIME_ADAPTER_NOT_RELEASED`，`native_calls=0`。真正可用的引擎路径是 `offline_qualification_v1/cli.py`。 |
| `X02v0` reparse point 覆盖 | 只测叶子判定函数，没有构造真实 reparse point。 |
| `X01` 绝对路径探针返回未类型化错误 | `C:\other\secret` 能过 `_root()`，随后以 `OPERATION_FAILED` 失败且不带 `stage` 键。登记为已知分类缺口。 |

本交付**明确不做**：完整故障注入、全部路径与 ACL 变体、完整并发矩阵、系统级不可篡改证明、
基于 Docker 的历史取证、任何 OS 级迁移。

## 目录

```text
demo.py                            一键演示 + 7 项自检
run_tests.py                       单元测试入口（注入必需的测试根）
ui/serve.py                        本地服务：真实执行 demo.py 并转发进度
ui/index.html                      单页 UI（零依赖，只监听 127.0.0.1）
ui/VIDEO_SCRIPT.md                 3 分钟备份录像脚本
offline_qualification_v1/          产品本体
  cli.py                           操作者入口：evaluate | view
  contracts.py                     规范编码、摘要、拒绝码
  records.py                       只可追加的记录存储
  assessment.py                    评估流水线
  core_bridge.py                   校验过的原生来源加载器 + 调用追踪
  SOURCE_MANIFEST.json             139 条哈希钉住的运行成员
  fixtures/cases.json              31 案件 / 56 变体
  tests/                           30 项测试
runtime_windows/                   Windows 来源/环境身份辅助
runtime_binding_v1_20261024/       母体副本、原版四核、双领域资产
```

## 必须知道的约束

- **克隆路径要短。** 最深相对路径 217 字符，绝对路径须留在 Windows 传统 260 字符上限内。
  `C:\h56demo` 安全；深层 `~/Documents/GitHub/...` 克隆会**静默丢文件**。必要时开
  `git config core.longpaths true`。如果 `python -B demo.py` 报无法导入
  `offline_qualification_v1`，先怀疑克隆路径而不是包本身，并用
  `git ls-files | wc -l` 核对——必须是 **244**。
- **`.gitattributes` 钉住 `* -text`。** 任何换行符转换都会改变文件字节，让 139 条清单哈希
  全部失效。不要移除。
- **按仓库字节策略检查 CRLF 差异。** 使用
  `git -c core.whitespace=cr-at-eol diff --check`；不要为了消除默认行尾警告而批量转换冻结文件。
- **运行输出必须在产品根之外**，否则 `cli.py` 以 `RUN_ROOT_OVERLAP` 拒绝。`demo.py`
  默认使用系统临时目录。
- **`TEST_ROOT` 必须显式注入** —— `test_records.py` 有意不提供环境变量或默认回退。
  请用 `run_tests.py`。

## 本仓库不包含什么

| 排除项 | 原因 |
|---|---|
| `evidence/`（11,295 文件 / 199 MB） | 只读历史归档，按摘要引用，运行不需要 |
| `separation_workspace_v1/` | 未完成的分层重构，已被本树取代 |
| `ar_pure_driver` 纯度闸门 | 在本机逻辑上不可满足（要求 `st_nlink == 1`，而 `ADVAPI32.dll` 违反） |
| `windows_frontdoor_v1` 任务队列 | 回报 `native_calls=0` 的占位入口；真正的引擎是 `offline_qualification_v1/cli.py` |
| `runtime_binding_v1_20261024/offline/source-lock.json` | 含本机私有路径，运行路径不消费它 |

## 状态

私有开发包。上述正确性性质可从干净克隆复现。发布、外部 API 联调、真实宿主执行
**均不**由本仓库授权。
