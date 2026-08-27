# Day 1 CAI Baseline 验证设计

## 背景与目标

验证经 SHA256 校验的 CAI Community 0.5.10 公开源码与已配置的
deepseek/deepseek-chat 是否能在无破坏、无外部目标的约束下运行四类专业
Agent，以及 SDK 原生 handoff 路径。

## 现状与约束

- 不修改 	hird_party/cai_framework-0.5.10 上游源码。
- 不使用 mock、fake model 或直接调用内部函数伪造 Agent 成功。
- 测试固定关闭 tracing 与 YOLO，限制 max_turns 和超时。
- 仅以模型文本任务和本机无副作用工具验证；不扫描或访问外部目标。

## 方案对比

### 方案一：单一综合脚本

- 优点：执行命令少。
- 缺点：专业 Agent 的构造、导入、模型调用和 handoff 故障难以定位。

### 方案二：每类独立 smoke 加独立 handoff smoke（采用）

- 优点：每项证据、异常与日志可独立验收；最符合 Day 1 的逐项退出标准。
- 缺点：会新增多个小测试文件。

### 方案三：仅静态导入检查

- 优点：不消耗 API 调用。
- 缺点：不能证明真实 provider、Agent 运行或 handoff，不能满足验收。

## 详细设计

### 架构与组件

	ests_real/day1/ 提供一个共享的安全运行辅助模块，及 Reverse、Red/Pentest、
DFIR/IR、Vulnerability Research 与 handoff 五个独立脚本。脚本使用 CAI 0.5.10
公开导出 API 构造 Agent 和 OpenAIChatCompletionsModel，读取已配置的 DeepSeek
环境变量。

### 数据流

每个 smoke 记录环境安全值、构造出的 Agent、工具加载信息、真实模型响应和异常。
标准输出同时写到 rtifacts/day1/，报告仅引用这些原始结果。handoff 测试将由
初始 Agent 通过 SDK 原生 handoffs 配置，将 ELF 分类问题交给 Reverse specialist，
并从结果 items 记录转换事件和最终 Agent。

