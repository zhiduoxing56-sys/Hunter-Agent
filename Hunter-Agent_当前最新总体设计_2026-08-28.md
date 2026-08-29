# Hunter-Agent 当前最新总体设计

> 
> 目标：构建面向渗透测试、漏洞挖掘、应急响应/数字取证、逆向分析四类真实网络安全任务的通用自主决策智能体。核心路线不是重新实现四套安全系统，而是把成熟开源安全智能体与安全工具作为“专业能力后端”，由 Hunter-Agent 统一理解任务、路由能力、执行控制、验证结果、记录世界状态并进行再规划。

---

## 1. 当前项目定位

Hunter-Agent 的最终定位不是“一个大模型 + 一堆命令”，也不是“把多个开源项目源码强行揉成一个仓库”，而是一个**分层、多智能体、可验证、可审计的通用网络安全自主决策系统**。

核心原则：

1. **集成优先，不重复造轮子。** 四类核心能力尽量直接复用目前表现强、工程成熟、开源可用的专业项目。
2. **Hunter 负责决策，专业项目负责专业执行。** Hunter 不接管每个上游项目的内部实现。
3. **所有异构项目通过 Adapter 统一。** 上游可以是 CLI、Python SDK、Docker、REST API、MCP，只要经过适配器后对 Hunter 暴露统一接口即可。
4. **确定性处理在前，大模型决策在后。** 文件识别、哈希、解压、安全检查、目标识别等能确定完成的工作不交给 LLM 猜。
5. **所有结论必须经过验证层。** 专业 Agent 的输出只是“候选结果”，最终是否完成任务由独立 Verifier 根据证据和成功条件判断。
6. **所有执行都进入世界状态与审计日志。** 便于失败恢复、策略切换、复现实验和比赛展示。

---

# 2. 总体架构

当前建议采用“三层主架构 + 双领域子监督器 + 一个全局监督器”。

```text
用户自然语言 / 文件 / 日志 / 证据 / 网络目标
                    │
                    ▼
┌────────────────────────────────────────────┐
│ 第 1 层：任务翻译与安全过滤层              │
│ Deterministic Parsing & Safety Gateway     │
│                                            │
│ 输入识别 → 安全解压 → 文件分析 → 哈希计算 │
│ → 内容预处理 → 目标识别 → TaskSpec        │
└────────────────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────┐
│ 第 2 层：多智能体决策与执行层              │
│ Multi-Agent Decision & Execution           │
│                                            │
│             Hunter Global Supervisor       │
│                    │                       │
│          ┌─────────┴─────────┐             │
│          ▼                   ▼             │
│ Offensive Supervisor   Analysis Supervisor │
│   渗透 + 漏洞挖掘        DFIR + 逆向        │
│          │                   │             │
│   PentestGPT            TRUDI / Find Evil  │
│   FuzzingBrain          Kong               │
│          │                   │             │
│          └────── Tool / Semgrep ───────────┘
└────────────────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────┐
│ 第 3 层：验证、记忆与闭环层                │
│ Semantic Verification & World State        │
│                                            │
│ 证据检查 → 语义验证 → 成败判定 → 事实生成 │
│ → 世界状态更新 → 失败反馈 → 再规划         │
└────────────────────────────────────────────┘
```

---


# 4. 第 1 层：任务翻译与安全过滤层

这一层的原则是：**能用确定性代码完成的事情，不交给 LLM。**

## 4.1 输入类型

Hunter 需要支持至少以下输入：

- 自然语言任务
- 文件 / 压缩包
- 源码仓库 / 工程目录
- 二进制程序 / 固件
- 日志 / 磁盘镜像 / 内存镜像
- IP / 域名 / URL / 网络目标
- 其他证据材料

## 4.2 确定性预处理流程

建议流程：

```text
输入
 ↓
安全解压 / 路径检查
 ↓
文件类型识别
 ↓
哈希计算（SHA-256 等）
 ↓
内容预处理 / 元信息提取
 ↓
目标识别与领域初判
 ↓
TaskSpec
```

### 安全解压

用于防止路径穿越、恶意链接、异常压缩包等问题。

### 文件分析

确定：

- ELF / PE / Mach-O
- 源代码项目
- pcap
- EVTX
- memory image
- disk image
- 文本日志
- 压缩包
- 固件等

### 哈希

对输入证据生成稳定标识，用于：

- 审计
- 去重
- 证据关联
- 任务恢复

### 内容预处理

只提取基本信息，不在这一层做复杂安全结论。

---

# 5. 统一任务合同 TaskSpec

四个智能体不应该直接接收完全不同格式的用户输入。Hunter 先生成统一 `TaskSpec`，再由 Adapter 翻译成各上游项目需要的参数。

建议核心字段：

```python
@dataclass
class TaskSpec:
    task_id: str
    domain: str
    target: str
    goal: str

    timeout: int = 1800
    budget: float | None = None
    workspace: str | None = None

    scope: dict = field(default_factory=dict)
    success_conditions: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
```

## 5.1 domain

建议支持：

```text
pentest
vulnerability_research
dfir
reverse
```

后续允许：

```text
hybrid
```

表示一个任务需要多个专业 Agent 联动。

## 5.2 Scope

Scope 必须包含：

- 允许访问的目标
- 允许读取的文件路径
- 允许使用的环境
- 资源预算
- 时间预算
- 禁止动作

## 5.3 Success Conditions

这是整个闭环的关键。

例如：

### 渗透测试

- 获得目标 flag 并通过 `submit_flag`
- 获得指定权限
- 证明目标服务可被利用

### 漏洞挖掘

- 产生可动态复现的 PoV
- Sanitizer 确认 crash
- 漏洞触发路径成立

### DFIR

- 结论存在证据链
- 关键 IOC 可回溯至原始证据
- 调查问题得到回答

### 逆向

- 成功识别关键函数 / 行为
- 输出证据位置或反汇编依据
- 完成指定逆向目标

---

# 6. 第 2 层：Hunter 多智能体决策与执行层

## 6.1 Hunter Global Supervisor

全局监督器只负责全局层面的事情：

1. 理解 TaskSpec
2. 判断使用哪个领域子监督器
3. 对混合任务进行跨领域拆分
4. 分配全局预算
5. 跟踪阶段进度
6. 接收各子系统结果
7. 把结果送给 Semantic Verifier
8. 根据验证结果决定是否继续

它不应该亲自完成复杂渗透、Fuzzing、取证或逆向操作。

---

# 7. 前两域：Offensive Supervisor

负责：

1. 渗透测试
2. 漏洞挖掘

当前路线：

```text
Offensive Supervisor
        │
 ┌──────┴──────┐
 │             │
PentestGPT   FuzzingBrain
 │             │
渗透测试      漏洞发现 / PoV / Patch
```

---

# 8. 渗透测试智能体：PentestGPT

当前项目已经选择以 PentestGPT 框架作为渗透测试基线，并已经推进到 AutoPenBench 的真实评测适配。

## 8.1 当前已有能力

目前 Hunter-Agent 的渗透部分已经包括：

- PentestGPT 框架作为上游
- DeepSeek 模型适配
- AutoPenBench Adapter
- 真实 Docker Kali
- 真实目标机
- `execute_bash`
- SSH
- 文件写入
- `submit_flag`
- 评测只认可 `submitted-answers.jsonl` 中真正提交的 flag

这意味着已经从“Agent 能不能调用工具”进入“Agent 能不能在真实基准里完成任务”的阶段。

## 8.2 下一步重点

不建议再重写 PentestGPT，而是把工作集中到：

- 每条攻击路径预算控制
- 路径失败后的策略切换
- 标签/任务目标与当前路径一致性
- 剩余预算保护
- AutoPenBench 正式实验

### 路径预算思想

例如总工具预算 20：

- 高优先级标签路径（如 RCE）保留足够预算
- 单一未经验证假设最多消耗有限 tool turns
- 必须为验证与策略切换保留预算

建议规则：

- 同一漏洞假设连续 2–3 次没有新增证据：停止该路径。
- 当前路径与任务标签/目标冲突：立即降级。
- 剩余预算低于一定比例：禁止重复测试，必须转向未验证的高优先级路径或最终验证。

---

# 9. 漏洞挖掘智能体：FuzzingBrain

当前漏洞挖掘方向首选集成：

**All You Need Is a Fuzzing Brain / FuzzingBrain**

其当前公开项目定位是 LLM-powered autonomous vulnerability discovery and patching system，构建在 OSS-Fuzz 之上，并通过 Suspicious-Point（SP）推理与 coverage-guided fuzzing 结合进行漏洞发现、PoV 构造、动态验证与补丁生成。

## 9.1 适合作为 Hunter 漏洞挖掘后端的原因

- 本身就是完整的漏洞发现 Agent 系统
- 与 OSS-Fuzz 深度结合
- 结果强调动态验证，而非只生成猜测
- 可以输出 PoV
- 可以输出 patch
- 支持 CLI
- 支持 REST API
- 支持 MCP server
- 支持 Docker

因此它非常适合被 Hunter 当作“独立能力服务”。

## 9.2 推荐接入方式

优先级：

```text
MCP / REST API
    > CLI subprocess
    > Python 内部 API
    > 直接修改源码
```

初期为了快速稳定，可以先使用：

```text
Hunter
  ↓
FuzzingBrainAdapter
  ↓
FuzzingBrain CLI / Docker
  ↓
results/report.json + PoV + patches
```

后续如需长驻服务，再切换为 REST/MCP。

## 9.3 Hunter 不需要接管的内容

FuzzingBrain 自己负责：

- 构建 fuzzer
- OSS-Fuzz 调度
- suspicious point generation
- PoV 构造
- crash 验证
- patch proposal

Hunter 只负责：

- 判断什么时候调用它
- 给它目标、预算、任务类型
- 统一解析结果
- 交给最终 Semantic Verifier

---

# 10. 后两域：Analysis Supervisor

由后两域负责人独立开发。

```text
Analysis Supervisor
        │
 ┌──────┴──────┐
 │             │
TRUDI/寻恶    Kong
 │             │
DFIR          Reverse Engineering
```

它不仅负责二选一，后续还要支持 DFIR 与逆向互相调用。

---

# 11. 应急响应 / 寻恶智能体：TRUDI / Find Evil 路线

目前适合作为后两域 DFIR 核心参考/集成对象的是 TRUDI（Threat Response Unit for Digital Investigation）这一类自主 DFIR Agent。

其公开设计强调：

- 基于 SANS SIFT Workstation
- 磁盘取证
- 内存取证
- Windows artifact parsing
- IOC enrichment
- YARA hunting
- 结构化 analyst report
- 全执行审计轨迹
- 独立 reasoning / adversarial review
- MCP 工具边界

## 11.1 对 Hunter 的意义

TRUDI 已经把大量 DFIR 工具封装成 MCP 工具，因此它适合通过独立进程/MCP 接入，而不是直接 import 其全部内部代码。

建议结构：

```text
Hunter Analysis Supervisor
          ↓
      TRUDIAdapter
          ↓
        MCP Client
          ↓
      TRUDI MCP Server
          ↓
Volatility / Sleuth Kit / YARA / EZ Tools / ...
```

## 11.2 Hunter 侧重点

Hunter 不需要重新实现 Volatility、YARA、Sleuth Kit 等工具能力，而是重点做：

- Case/TaskSpec 转换
- Evidence path 管理
- 工具调用边界
- 结果归一化
- 跨 Agent 协作
- 最终验证

---

# 12. 逆向分析智能体：Kong

Kong 作为逆向分析专业 Agent，建议同样作为独立上游项目保留，不把它内部模块拆散混入 Hunter。

## 12.1 第一阶段目标

只要求实现：

```text
Hunter
 ↓
KongAdapter
 ↓
Kong
 ↓
原始分析结果
 ↓
AgentResult
```

先保证真实链路可运行，再做复杂跨 Agent 调度。

## 12.2 推荐运行方式

根据 Kong 官方实际入口选择：

- CLI → subprocess
- Python API → 隔离运行后调用
- Docker → 容器
- 服务接口 → HTTP/MCP

如果 CLI 足够稳定，初期优先 subprocess，因为安全项目依赖较复杂，进程隔离比直接 import 更稳。

---

# 13. DFIR 与逆向的跨 Agent 联动

后两域真正能体现 Hunter 价值的不是“有两个 Agent”，而是它们可以互相提供上下文。

## 13.1 DFIR → Reverse

例如：

```text
TRUDI 在磁盘 / 内存中发现可疑 evil.exe
              ↓
Analysis Supervisor
              ↓
Kong 分析该二进制
              ↓
得到 C2、持久化方式、关键字符串、函数行为
              ↓
回写 World State
              ↓
TRUDI 按新 IOC 继续搜索证据
```

## 13.2 Reverse → DFIR

例如：

```text
Kong 分析恶意样本
 ↓
发现注册表路径 / 域名 / DLL / mutex / service name
 ↓
Analysis Supervisor
 ↓
TRUDI 在磁盘、内存和日志中寻找对应证据
```

这比单独展示两个安全 Agent 更符合“通用自主决策智能体”的定位。

---

# 14. Semgrep 在最新设计中的定位

Semgrep 不建议作为第五个“领域智能体”，而应该作为**跨领域确定性代码安全分析能力**。

Semgrep 是成熟的静态分析工具，支持多种语言，可用于查找 bug、安全缺陷、编码规则问题，并提供 CLI；当前 Semgrep 也提供 MCP Server，可供 AI coding assistant / Agent 直接调用。

## 14.1 为什么 Hunter 需要 Semgrep

LLM Agent 做代码分析存在两个问题：

- 成本高
- 很容易在大代码库中漏掉机械性、模式化问题

Semgrep 可以先做低成本、高覆盖的静态筛选，再把重点位置交给 FuzzingBrain 或 Hunter Agent 深度分析。

因此它非常适合成为：

```text
确定性安全工具层 / Tool Skill
```

而不是独立总 Agent。

## 14.2 推荐放置位置

```text
                  Hunter Supervisor
                         │
              Domain Router / Skills
                         │
       ┌─────────────────┼──────────────────┐
       │                 │                  │
   Semgrep           FuzzingBrain          Kong
静态代码预扫描       深度漏洞挖掘          逆向分析
```

## 14.3 在漏洞挖掘中的用法

```text
源码仓库
 ↓
Semgrep 快速静态扫描
 ↓
候选高风险位置 / sink / source / rule hit
 ↓
写入 World State
 ↓
FuzzingBrain 深入验证
 ↓
PoV / crash / patch
```

这种组合可以减少 FuzzingBrain 在完全无方向状态下的搜索成本。

## 14.4 在逆向/恶意代码分析中的辅助位置

如果目标同时包含源码、脚本、配置、插件或解包后的代码，Semgrep 可以对这些文本/源码部分进行确定性规则扫描；二进制本体仍交给 Kong/Ghidra/radare2 等逆向能力。

## 14.5 接入方式

Semgrep 当前支持：

```text
CLI
MCP Server
```

Hunter 初期可直接做 `SemgrepAdapter`：

```text
Hunter
 ↓
SemgrepAdapter
 ↓
semgrep CLI
 ↓
JSON findings
 ↓
World State
```

后续统一 Agent Tool Protocol 时可以切换到 MCP。

---

# 15. Adapter：异构开源项目的统一接入层

这是 Hunter 当前工程上最关键的设计。

每个开源项目启动方式不同：

- Python
- shell script
- CLI
- Docker
- REST API
- MCP server
- 需要 `.env`
- 需要数据库
- 需要不同系统依赖

不能把这些差异暴露给 Hunter Supervisor。

统一定义：

```python
class AgentAdapter:
    def healthcheck(self):
        raise NotImplementedError

    def prepare(self, task):
        raise NotImplementedError

    def run(self, task):
        raise NotImplementedError

    def collect(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError
```

专业项目只需要实现这个生命周期。

---

# 16. 四种标准接入模式

## 16.1 REST / MCP

长期最佳方案。

适合：

- 长驻服务
- 多 Agent
- 独立依赖环境
- 未来前端/分布式部署

## 16.2 CLI / subprocess

短期最实用。

适合：

- 成熟命令行项目
- 不想侵入源码
- 希望快速稳定集成

## 16.3 Docker

安全项目非常推荐。

优点：

- 依赖隔离
- 易复现
- 不污染 Hunter 主环境

## 16.4 Python SDK

仅当上游提供稳定公开 SDK 时使用。

缺点是安全项目经常存在 Python、Torch、Agent SDK、系统工具版本冲突，因此不建议为了“看起来集成更深”而强制直接 import。

---

# 17. Manifest：统一启动与配置

Adapter 负责逻辑，Manifest 负责描述“这个上游项目到底怎么运行”。

例如：

```yaml
name: fuzzingbrain
mode: subprocess
workdir: third_party/fuzzingbrain

start:
  command:
    - ./FuzzingBrain.sh
    - --budget
    - "{budget}"
    - "{target}"

result:
  type: file
  path: "workspace/*/results/report.json"

timeout: 3600
```

Semgrep：

```yaml
name: semgrep
mode: subprocess

start:
  command:
    - semgrep
    - --json
    - --config
    - auto
    - "{target}"

result:
  type: stdout_json
```

这样 Hunter 核心不需要知道不同上游项目的启动细节。

---

# 18. third_party 代码管理

不建议 copy-paste 上游源码。

推荐：

```text
Hunter-Agent/
├── hunter/
├── integrations/
├── third_party/
├── configs/
├── runs/
└── tests/
```

`third_party/` 中保存上游项目，优先使用 Git submodule 锁定版本：

```text
third_party/
├── pentestgpt/
├── fuzzingbrain/
├── kong/
└── trudi/
```

Semgrep 如果直接使用系统 CLI 或 Docker，则不一定作为 submodule 放入仓库。

---

# 19. 统一输出 AgentResult

所有专业 Agent 的原始输出必须转成统一结构。

建议：

```python
@dataclass
class AgentResult:
    task_id: str
    agent: str
    status: str

    summary: str
    findings: list
    artifacts: list
    evidence: list

    raw_output: dict
    metrics: dict
```

统一状态：

```text
pending
running
success
failed
timeout
partial
```

注意：这里的 `success` 最好表示“专业 Agent 自己报告完成”，最终全局任务是否真正成功仍由 Semantic Verifier 决定。

---

# 20. Execution Controller：统一执行控制层

所有 Adapter 都不能无限制执行。

执行控制层负责：

- 工具调用预算
- Token/LLM 预算
- 运行时间
- CPU / 内存限制
- Docker 限制
- 工作目录隔离
- Scope 校验
- 异常捕获
- 超时终止
- 重试策略
- 日志采集

这样 PentestGPT、FuzzingBrain、TRUDI、Kong、Semgrep 即使内部机制完全不同，仍然受到 Hunter 的统一控制。

---

# 21. 第 3 层：Semantic Verifier

Hunter 不应该直接相信专业 Agent 的一句“任务完成”。

建议独立出验证层：

```text
AgentResult
 ↓
Evidence Check
 ↓
Success Condition Check
 ↓
Semantic Verification
 ↓
Success / Failure / Partial
 ↓
World State Update
```

## 21.1 为什么一定要独立

否则会出现：

- Pentest Agent 说拿到了权限，但实际没有完成评测目标
- 漏洞 Agent 说发现漏洞，但 PoV 无法复现
- DFIR Agent 写出攻击归因，但证据不完整
- Reverse Agent 给出函数语义，但没有反汇编依据

Verifier 的任务是检查“证据是否真的满足 TaskSpec 的成功条件”。

## 21.2 验证类型

### Deterministic Verification

能程序化验证的优先程序化：

- flag 是否被评测系统接受
- PoV 是否复现
- crash 是否出现
- 文件是否真实生成
- hash 是否一致
- patch 后测试是否通过

### Semantic Verification

无法完全程序化的再由模型辅助判断：

- DFIR 结论是否被证据支撑
- 逆向分析结论是否和反汇编/调用链一致
- 多 Agent 结果是否互相矛盾

---

# 22. World State：世界状态与记忆

Hunter 的记忆不是简单聊天历史，而应该是结构化世界状态。

建议至少保存：

## Facts

已经被验证的事实。

例如：

```text
port 80 is open
sample hash = ...
process evil.exe existed at time T
PoV triggers ASAN crash
```

## Questions

仍未回答的问题。

```text
How did the attacker obtain initial access?
Does this binary communicate with domain X?
```

## Hypotheses

当前假设。

```text
possible RCE
possible registry persistence
possible packed malware
```

## Evidence Store

每个结论对应证据。

## History

执行历史、使用过的工具、失败路径。

---

# 23. 失败反馈与再规划

当前设计最重要的闭环：

```text
Planner / Supervisor
 ↓
Agent / Tool Execution
 ↓
Verifier
 ↓
失败
 ↓
失败原因写入 World State
 ↓
Supervisor 重新规划
```

失败不能简单等于“再运行同一条命令”。

应区分：

- 工具错误
- 环境错误
- 假设错误
- 证据不足
- 成功条件未满足
- 预算耗尽
- 路径重复无进展

这样才能避免 Agent 陷入循环。

---

# 24. 统一 Run 目录与审计

建议任何一次任务都形成独立目录：

```text
runs/
└── <task_id>/
    ├── task.json
    ├── events.jsonl
    ├── result.json
    ├── world_state.json
    ├── artifacts/
    └── logs/
```

## events.jsonl

记录：

- supervisor decision
- router decision
- adapter start/stop
- tool call
- tool result
- verification result
- strategy switch
- budget update

这既是可审计性，也是最后答辩展示的重要材料。

---

# 25. 当前推荐目录结构

```text
Hunter-Agent/
│
├── hunter/
│   ├── contracts.py
│   ├── supervisor/
│   │   ├── global_supervisor.py
│   │   ├── offensive_supervisor.py
│   │   └── analysis_supervisor.py
│   ├── router/
│   ├── verifier/
│   ├── world_state/
│   ├── runtime/
│   └── safety/
│
├── integrations/
│   ├── pentestgpt/
│   │   ├── adapter.py
│   │   ├── manifest.yaml
│   │   └── parser.py
│   ├── fuzzingbrain/
│   │   ├── adapter.py
│   │   ├── manifest.yaml
│   │   └── parser.py
│   ├── trudi/
│   │   ├── adapter.py
│   │   ├── manifest.yaml
│   │   └── parser.py
│   ├── kong/
│   │   ├── adapter.py
│   │   ├── manifest.yaml
│   │   └── parser.py
│   └── semgrep/
│       ├── adapter.py
│       ├── manifest.yaml
│       └── parser.py
│
├── third_party/
│   ├── pentestgpt/
│   ├── fuzzingbrain/
│   ├── trudi/
│   └── kong/
│
├── configs/
├── runs/
├── tests/
└── docs/
```

---

# 26. 两个人如何并行开发

最重要的是不要让两个人同时修改同一个核心调度文件。

开发前共同冻结以下 5 项：

1. `TaskSpec`
2. `AgentResult`
3. `AgentAdapter` 生命周期
4. `runs/<task_id>/` 目录规范
5. 状态枚举与事件日志格式

然后：

## 开发者 A

```text
Offensive Supervisor
├── PentestGPTAdapter
└── FuzzingBrainAdapter
```

## 开发者 B

```text
Analysis Supervisor
├── TRUDIAdapter
└── KongAdapter
```

Semgrep 是公共 Tool，可由其中一人实现后两边共用。

最后只需新增：

```text
Global Supervisor
```

把两个子监督器接起来。

---

# 27. 当前最现实的实现顺序

不要先写一个复杂的 LLM Planner。

## 阶段 1：单 Agent 可调用

完成：

```text
Hunter → PentestGPT
Hunter → FuzzingBrain
Hunter → TRUDI
Hunter → Kong
Hunter → Semgrep
```

每条链都必须输出标准 AgentResult。

## 阶段 2：两个领域子监督器

完成：

```text
Offensive Supervisor
Analysis Supervisor
```

第一版甚至可以只按 `task.domain` 硬路由。

## 阶段 3：确定性工具辅助

加入 Semgrep 等工具，让 Supervisor 能先低成本获取线索。

## 阶段 4：跨 Agent 联动

重点验证：

```text
Semgrep → FuzzingBrain
TRUDI → Kong
Kong → TRUDI
```

## 阶段 5：Semantic Verifier

把“Agent 自报成功”改成“证据满足 Success Conditions 才成功”。

## 阶段 6：Global Supervisor

把两个子系统统一。

## 阶段 7：智能规划与动态策略切换

再增加：

- LLM task decomposition
- domain score
- dynamic routing
- budget-aware replanning
- world-state-driven planning

避免在基础链路没通前就陷入复杂 Agent 框架调试。

---

# 28. 当前已经完成 / 已经确定的部分

截至 2026-08-28，目前可视为已经确定或已经具备基线的部分：

## 已确定总体路线

- 四类能力：渗透、漏洞挖掘、DFIR、逆向
- 集成成熟开源专业系统，而不是四套能力全部自研
- Adapter + Manifest 作为统一接入边界
- 两个领域子监督器 + 一个全局监督器
- Semantic Verifier + World State 形成闭环

## 渗透

- PentestGPT 路线确定
- 已有真实 AutoPenBench Adapter
- 真实 Docker Kali / 目标环境
- DeepSeek 模型适配
- submit_flag 真实验收

## 漏洞挖掘

- FuzzingBrain 是当前重点集成候选
- 推荐以 CLI/Docker 起步，后续可切 REST/MCP

## DFIR

- 寻恶 / TRUDI 类型自主 DFIR Agent 作为重点路线
- 推荐优先 MCP 接入

## 逆向

- Kong 作为当前重点专业逆向 Agent
- 第一目标是做 Adapter，先跑通单任务链路

## Semgrep

- 定位为跨领域静态代码安全工具，而非第五个总 Agent
- 可通过 CLI 或 MCP 接入
- 优先作为漏洞挖掘前置筛选器

---

# 29. 当前尚未完成的关键部分

需要明确：以下是“设计已确定但还需工程实现/验证”的部分：

1. FuzzingBrainAdapter 的正式 Hunter 集成
2. KongAdapter 的正式 Hunter 集成
3. TRUDI/寻恶 Adapter 的正式 Hunter 集成
4. SemgrepAdapter
5. Analysis Supervisor
6. Offensive Supervisor 与漏洞挖掘侧完整联动
7. Semantic Verifier 的统一实现
8. World State 数据结构
9. Global Supervisor
10. 跨域真实基准实验

因此当前不要把架构设计误认为已经全部实现。

---

# 30. 最近最优先任务

## 后两域负责人

建议马上按以下顺序：

```text
1. 冻结 TaskSpec / AgentResult / Adapter
2. 手工跑通 Kong 官方示例
3. 写 KongAdapter
4. Hunter → Kong smoke test
5. 手工跑通 TRUDI / 寻恶官方案例
6. 写 TRUDIAdapter
7. Hunter → TRUDI smoke test
8. 写 Analysis Supervisor
9. 做一次 TRUDI → Kong 或 Kong → TRUDI 联动
10. 接入 World State / Verifier
```

验收标准示例：

```bash
python -m hunter.run --domain reverse --target sample.bin
```

最终必须生成：

```text
runs/<task_id>/result.json
```

而不是只在终端看到“模型好像分析了”。

## 前两域负责人

继续：

```text
PentestGPT AutoPenBench 正式测评
       +
FuzzingBrainAdapter
       +
Offensive Supervisor
```

---

# 31. 最终作品应该展示什么

Hunter-Agent 最终答辩不应只展示四个按钮分别调用四个项目，而应展示：

### 1. 统一自然语言入口

用户不用知道底层到底是 PentestGPT、FuzzingBrain、TRUDI 还是 Kong。

### 2. 自动领域识别与任务拆解

Hunter 把输入转成 TaskSpec 并选择能力。

### 3. 多 Agent 协作

例如：

```text
源码 → Semgrep → FuzzingBrain → PoV → Verifier
```

或者：

```text
主机证据 → TRUDI → 可疑样本 → Kong → 新 IOC → TRUDI → 报告
```

### 4. 动态失败恢复

验证失败后不是停止，而是把失败原因写入世界状态并再规划。

### 5. 可解释 / 可审计

前端能够显示：

- 为什么选择这个 Agent
- 执行过什么工具
- 得到了什么证据
- 为什么认为成功/失败
- 哪一次发生了策略切换

---

# 32. 当前设计的一句话总结

**Hunter-Agent = 一个统一安全任务翻译器 + 一个层级化多智能体监督与路由系统 + PentestGPT / FuzzingBrain / TRUDI / Kong 等专业开源能力后端 + Semgrep 等确定性工具 + 独立 Semantic Verifier + World State 记忆与失败再规划闭环。**

四个专业系统不是 Hunter 的四份复制代码，而是四个“可插拔专业能力”；Hunter 真正统一的是任务合同、调度、预算、执行控制、证据、验证、记忆与跨 Agent 协作。

---

# 33. 当前建议冻结的最终技术路线

```text
输入层
自然语言 / 源码 / 二进制 / 日志 / 证据 / 网络目标
  ↓
确定性翻译与安全过滤
  ↓
TaskSpec
  ↓
Hunter Global Supervisor
  ↓
┌───────────────────────────┬───────────────────────────┐
│ Offensive Supervisor      │ Analysis Supervisor       │
│                           │                           │
│ PentestGPT                │ TRUDI / 寻恶              │
│ FuzzingBrain              │ Kong                      │
│ Semgrep / security tools  │ Semgrep / reverse tools   │
└───────────────────────────┴───────────────────────────┘
  ↓
统一 AgentResult
  ↓
Semantic Verifier
  ↓
Success / Failure / Partial
  ↓
World State
  ↓
失败反馈 / 新事实 / 新问题 / 新假设
  ↓
重新规划
```

