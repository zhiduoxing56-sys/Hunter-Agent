"""Small display helpers kept separate from frozen protocol contracts."""

from __future__ import annotations

from typing import Any

EVENT_LABELS: dict[str, str] = {
    "input_received": "文件接收",
    "scope_checked": "输入范围检查",
    "input_custodied": "安全托管",
    "hash_computed": "SHA-256",
    "file_type_detected": "文件类型识别",
    "metadata_extracted": "文件元数据提取",
    "archive_extract_started": "安全解压开始",
    "archive_extract_finished": "安全解压完成",
    "domain_scored": "领域自动判断",
    "taskspec_created": "TaskSpec 创建",
    "layer1_completed": "Layer 1 完成",
    "task_created": "Analysis Supervisor 路由",
    "task_prepared": "专业后端准备",
    "verification_result": "托管证据完整性复验",
    "adapter_started": "专业分析开始",
    "tool_called": "后端分析中",
    "tool_result": "后端分析返回",
    "artifact_created": "分析产物生成",
    "evidence_created": "证据记录生成",
    "adapter_finished": "专业分析完成",
    "task_finished": "结果生成",
    "error": "执行失败",
}


def event_labels_payload() -> dict[str, Any]:
    return {"labels": EVENT_LABELS}
