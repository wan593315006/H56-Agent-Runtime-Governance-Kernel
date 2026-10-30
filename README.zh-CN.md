# H56 — 面向智能体的通用 OS 治理内核

H56 将**事实与历史、动态状态、能力合同和候选资格计算**连接为可追溯的计算链。原版 `K0 → K1 → C1 → C2` 四核依据输入证据、当前状态和适用约束计算结果，并保存原因、来源身份与调用轨迹。

环境资格与受控任务准入是本次选取的代表性演示。领域规则通过版本化资产和适配层接入通用内核，CLI、UI、审计查看、关联重评和真实模型协同入口提供操作与集成方式。

[观看英文演示视频](https://youtu.be/Gxr5SzG3OMg) · [English README](README.md) · [演示指南](DEMO_GUIDE.md) · [恢复指南](RECOVERY_GUIDE.md) · [技术架构](ARCHITECTURE.md)

## H56 解决什么问题

智能体提出任务时，环境事实可能缺失，外部前提可能未知，状态也可能已经变化。H56 将这些条件纳入资格计算，分别给出可行、不可行、延后或需要补充证据的结果；输入校验在相应阶段返回明确的拒绝码。

评估记录关联输入、约束、来源和计算过程。补充证据后，系统生成带父引用的新评估，保留此前的记录。候选资格与执行授权采用独立职责，便于规划器、操作者及其他智能体系统消费评估结果。

## 核心与配套能力

| 组件 | 计算职责 |
| --- | --- |
| **K0 — 事实与历史** | 规范事实身份、来源与只追加历史。 |
| **K1 — 状态推导** | 在固定版本上下文中，由历史构建并校验状态快照。 |
| **C1 — 能力合同** | 能力定义、目录完整性与声明约束。 |
| **C2 — 候选可行性** | 结合状态、能力和上下文计算资格与排除原因。 |

围绕四核，H56 提供：

- **输入与来源核验**：检查证据结构、资产身份与注册源码字节。
- **CLI 与本地 UI**：运行案例，查看结果、原因码和已登记产物。
- **审计与只读查看**：关联封存记录、声明、事件日志和语义摘要。
- **补证重评**：建立新旧评估的父子关联，保留历史记录。
- **受控模型接入**：校验模型提案，将场景选择映射到实际输入构造路径。
- **请求范围与预算管理**：在显式配置的云端运行中检查端点、目录、授权、范围和用量。
- **源码交付与恢复**：通过 Git 或 ZIP、完整清单和现有自检入口恢复主要运行能力。

## 下载与启动

使用 **Windows 10/11、Python 3.9.13**。离线应用与检查使用 Python 标准库，无需安装应用依赖或配置 API Key。选择短目录，并将环境与运行产物放在仓库之外。

Git 克隆路线：

```powershell
git -c core.autocrlf=false -c core.longpaths=true clone '<repository-url>' C:\h56demo
Set-Location C:\h56demo
python -B verify_pack.py --expected-commit '<full-release-commit>'
python -B demo.py
```

`<full-release-commit>` 使用发布说明给出的完整提交号。包校验器检查 Git 身份、工作树、完整文件成员、SHA-256 以及 139 项计算闭包。

ZIP 路线：解压至实际运行目录，使用发布附件单独提供的 `RELEASE_MANIFEST.json` 摘要：

```powershell
Set-Location C:\h56demo
python -B verify_pack.py --expected-manifest-sha256 '<published-manifest-sha256>'
python -B demo.py
```

本地 UI：

```powershell
python -B ui/serve.py --no-browser
```

在同一台机器打开 **http://127.0.0.1:8765**。页面按钮通过实际子进程执行 `demo.py --all`，显示结果、拒绝原因和证据查看入口。端口被占用时可用 `--port 8792`，浏览器地址使用对应端口。

完整环境配置、输出保留、模型配置及排障见 [恢复指南](RECOVERY_GUIDE.md)。仓库本身是可恢复运行载体，离线路线自包含。

## 六案例演示

默认演示构造六条不同的合成证据输入，覆盖输入拒绝和四类计算结局：

| 案例 | 输入变化 | 结果 |
| --- | --- | --- |
| `B06v0` | 字段声明 UNKNOWN，同时仍给出具体值 | `REJECTED / ENV_INPUT_REJECTED` |
| `A01v0` | `app_container=true`、`integrity_rid=4096` | `INFEASIBLE` |
| `B05v0` | 移除 `supporting_attestation` | `NEED_MORE_EVIDENCE` |
| `B01v0` | `outer_job_clear` 标记 UNKNOWN | `DEFER` |
| `B07v1` | 将 `outer_job_clear.observed_at` 前移 | `FEASIBLE` |
| `C01v0` | 基准信封 | `FEASIBLE` |

每行显示输入摘要与字段变化。通过门禁并产生记录的主评估执行 22 次具名原生调用，分布为 K0 6、K1 4、C1 6、C2 6。拒绝案例在对应校验阶段返回原因码，其评估产物列表为空。

默认输出为 **`PASS_WITH_SKIPS`**：6 项性质通过，可选的跨解释器比较跳过。提供第二解释器后，性质 3 执行 C01 的跨版本对照；按当次回执显示 PASS 或其他状态。

```powershell
python -B demo.py --all
# 可选：将路径替换为已安装的第二解释器
python -B demo.py --compare-python 'C:\path\to\second\python.exe'
```

## 真实 Nebius/NVIDIA 模型协同

已记录的真实推理使用 **Nebius Token Factory** 与 **`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`**。模型根据用户意图提出已登记场景，Adapter 校验并映射到对应输入，再由原版四核计算资格。

| 请求 | 模型响应 | H56 结果 |
| --- | --- | --- |
| R1 | `SELECT / S-C01` | 主评估 `FEASIBLE`，22 条原生调用轨迹。 |
| R5 | `SELECT / S-A01` | 主评估 `INFEASIBLE`，22 条轨迹及容器、完整性、策略原因码。 |
| R7 | `NOT_APPLICABLE` | 合法终局，Adapter 按该响应结束，内核保持未启动状态。 |

R1 与 R5/R7 来自两批执行。模型响应来自云端推理；评估输入来自受控合成场景。固定响应测试和真实模型请求分别标识，驱动附加的性质测试与所选场景的主评估分别统计。

新云端请求使用操作者自己的凭据和显式范围、预算及计划。具体步骤见 [可选真实模型接入](RECOVERY_GUIDE.md#optional-live-model-integration)。安装与离线 UI 使用本地计算路线。

## 评估记录、重评与权限分工

评估记录包含输入身份、来源绑定、状态、能力上下文、候选结果、原因码和 `mapping_trace`。语义摘要覆盖调用轨迹；绑定方法条目的摘要范围及上下文关联见 [技术架构](ARCHITECTURE.md#the-four-cores)。

性质 4、5 使用父子评估验证关联重评：父评估为 DEFER，补充材料后的子评估为 FEASIBLE，子记录引用父记录，原产物与声明保持原字节。这组性质测试与模型请求示例分别呈现。

本次资格演示的封存结果保持以下字段：

```python
candidate_planning_only is True
authority_granted      is False
execution_permitted    is False
business_action_calls  == 0
```

资格计算产出规划层结果与审计记录，执行授权由独立职责处理。`SYNTHETIC_ONLY` 与 `SIMULATED_OPERATOR_METADATA_HOST` 标识本次演示的数据来源和环境角色。

## 验证与覆盖

```powershell
python -B run_tests.py
python -B -m ui.test_release_guards
```

产品套件为 **30 项**，UI 发布守卫为 **12 项**。已有验收记录分别使用 Python 3.9.13 和 3.13.12；新环境按实际解释器和运行回执记录结果。固定响应的六场景 A2 通过真实 Adapter、CLI、四核和记录存储验证提案消费，命令见 [演示指南](DEMO_GUIDE.md#5-fixed-response-adapter-integration)。

全量回归包含 **31 个案件、56 行、26 条不同输入**。基准输入出现 31 次，其余 25 条输入各出现一次。30 行重复用于回归比对，独立输入按构造后的证据字节统计。

| 去重后的输入结果 | 数量 |
| --- | ---: |
| FEASIBLE | 2 |
| INFEASIBLE | 5 |
| DEFER | 4 |
| NEED_MORE_EVIDENCE | 1 |
| REJECTED | 14 |

14 条拒绝分布在输入、时间、证据冲突、任务范围及来源版本校验，返回对应原因码。UI 同时展示回归行数与不同输入数量。

当前候选包含 **132 个 Python 文件**：124 个与开发工作树对应文件逐字节一致，7 个包含已说明的可移植性或入口安全调整，另有独立的 `verify_pack.py`。原版 **139 项计算闭包**保持原字节，合计 **582,506 B**。完整公开成员由 `RELEASE_MANIFEST.json` 和 `PACKAGE_MANIFEST.json` 定义，具体比对范围见 [来源对照](metadata/SOURCE_COMPARISON.json)。

<details>
<summary>路径校验用例的技术口径</summary>

- X02v0 的具名测试覆盖 `_check_stat` 元数据判定；文件系统重解析点属于单独的测试层级。
- X01 外部缺失目录探针会以 `OPERATION_FAILED` 返回，payload 不含 `stage`。检查该路径时按实际响应字段定位原因。

</details>

## 来源、赛期更新与发展方向

H56 源于此前五体运行域的通用 OS 与本地多智能体研发积累，涉及任务协调、运行状态、能力约束、健康检查、状态记忆和变更历史。

赛期工作形成并集成四核独立组件，将其连接到结构化输入合同、资产与来源核验、CLI/UI、封存记录和补证重评，并新增受控模型 Adapter、Provider 与真实 Nebius/NVIDIA 协同。源码历史记录了 9 月 K0/K1、10 月初 C1/C2、10 月下旬独立交付及模型接线的演进，详见 [研发时间线](ARCHITECTURE.md#development-timeline)。

后续开发方向：

- 通过版本化事实、状态映射与能力合同接入更多领域。
- 扩展模型提案接口，保持提案、证据校验和资格计算的清晰分工。
- 改善多智能体与外部工具对评估结果、关联决策的消费方式。
- 改善规则编写、证据查看、配置与可移植部署体验。

## 运行目录与文件

| 路径 | 用途 |
| --- | --- |
| `demo.py`、`run_tests.py` | 一键演示、性质检查与产品测试。 |
| `offline_qualification_v1/` | 资格合同、资产、四核桥接、记录与 CLI。 |
| `runtime_binding_v1_20261024/engineering/vendor/` | 固定来源的原版四核、Profile 与关联源码。 |
| `runtime_windows/` | 来源身份与支撑合同、辅助模块。 |
| `model_ingress_v1/` | Provider、Adapter、登记表、计划驱动与固定响应测试。 |
| `ui/` | 本地操作界面、发布守卫与备用取景说明。 |
| `verify_pack.py` | 完整包、Git/ZIP 身份与计算闭包核验。 |

使用短运行目录，保留 `.gitattributes` 的字节策略。环境、输出、原始视频和私有回执存放在仓库外；应用命令带 `-B`，使校验后的文件成员保持稳定。留存评估时使用恢复指南中的绝对路径、独占运行目录和 `--keep`。产品测试通过 `run_tests.py` 配置临时测试根。

公开包包含运行所需源码、资产、公开来源锁、界面和说明文档；凭据、私有来源侧车、母体归档及历史运行材料保存在仓库外。离线恢复直接消费包内依赖，操作顺序与故障排查见 [恢复指南](RECOVERY_GUIDE.md)。

## 许可证与知识产权说明

H56 采用 [MIT License](LICENSE)，版权署名为万根。独立的 [IP_NOTICE.md](IP_NOTICE.md) 说明相关专利申请与主体关系，并保持 MIT 正文的授权范围。发布状态由 [PACKAGE_STATUS.json](PACKAGE_STATUS.json) 记录。该文件只记录冻结时的快照；最终公开授权由外部裁决绑定到具体提交与发行摘要，不由包内字段自证。
