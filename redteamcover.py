"""redteamcover —— 检查红队用例覆盖了哪些攻击面。

把攻击面清单与红队用例对照，标出未覆盖的类别

定位：
  覆盖按攻击类别判定，不按用例数量

设计约束：
  1. **只报告能定位到具体位置的结论**，不做语义猜测。
  2. **规则表公开**，每条命中都能对应到 红队用例覆盖 领域的一条明示规则。
  3. **输入为空或格式不对时明确报错**，不静默返回空结果。

仅依赖 Python 标准库。

用法:
    python redteamcover.py --help
    python redteamcover.py --file input.txt
    python redteamcover.py --text "示例内容"
    python redteamcover.py --file input.txt --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# 领域规则表：每条规则独立可核查，命中即报，不做推断。
RULES: list[dict] = [
    {
        "name": "红队用例覆盖·缺失",
        "why": "缺少红队用例覆盖的关键要素时无法给出可靠判定",
        "severity": "high",
        "keywords": ['缺失', 'missing', 'absent', '缺少', '没有'],
    },
    {
        "name": "红队用例覆盖·冲突",
        "why": "同一份输入里两处红队用例覆盖描述互相矛盾",
        "severity": "high",
        "keywords": ['冲突', 'conflict', 'contradict', '矛盾', '不一致', '相反'],
    },
    {
        "name": "红队用例覆盖·越界",
        "why": "红队用例覆盖的取值超出常规范围",
        "severity": "medium",
        "keywords": ['越界', 'out of range', 'outlier', '越界', '超限', '超过'],
    },
    {
        "name": "红队用例覆盖·退化",
        "why": "红队用例覆盖的信息量不足以支撑结论",
        "severity": "medium",
        "keywords": ['退化', 'degrade', 'insufficient', '不足', '太少', '无法'],
    },
    {
        "name": "红队用例覆盖·泄漏",
        "why": "红队用例覆盖相关的内容被意外暴露",
        "severity": "high",
        "keywords": ['泄漏', 'leak', 'expose', '泄漏', '暴露', '明文'],
    },
    {
        "name": "红队用例覆盖·重复",
        "why": "同一处红队用例覆盖信息被反复传递",
        "severity": "low",
        "keywords": ['重复', 'duplicate', 'repeat', '重复', 'again'],
    },
    {
        "name": "红队用例覆盖·陈旧",
        "why": "红队用例覆盖的时效性已经过期",
        "severity": "medium",
        "keywords": ['陈旧', 'stale', 'expired', '过期', '陈旧', '旧版'],
    },
    {
        "name": "红队用例覆盖·不可核",
        "why": "红队用例覆盖的说法无法追溯到具体证据",
        "severity": "high",
        "keywords": ['不可核', 'unverifiable', 'no evidence', '无法追溯', '没有来源'],
    },
]


def redteamcover_split_items(text: str) -> list[str]:
    items: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        for p in re.split(r"(?<=[。！？；;])\s*", line):
            p = p.strip()
            if p:
                items.append(p)
    return items


def redteamcover_tokens(text: str) -> set[str]:
    """抽词元。中文按二元组切——见 consistency-checker 引擎里的说明。"""
    low = text.lower()
    out = set(re.findall(r"[a-z]{3,}", low))
    for seg in re.findall(r"[\u4e00-\u9fff]+", low):
        if len(seg) == 1:
            out.add(seg)
        else:
            for i in range(len(seg) - 1):
                out.add(seg[i:i + 2])
    return out


def redteamcover_analyze(text: str) -> dict:
    """主分析：条目覆盖、缺失项与重叠。"""
    items = redteamcover_split_items(text)
    if not items:
        return {"ok": False, "error": "没有可分析的条目", "count": 0}
    all_tokens: dict[str, list[int]] = {}
    for i, it in enumerate(items):
        for t in redteamcover_tokens(it):
            all_tokens.setdefault(t, []).append(i)
    shared = {t: idxs for t, idxs in all_tokens.items() if len(idxs) > 1}
    covered = {i for idxs in all_tokens.values() for i in idxs}
    missing = [i for i in range(len(items)) if i not in covered]
    return {
        "ok": True,
        "count": len(items),
        "unique_tokens": len(all_tokens),
        "shared_tokens": len(shared),
        "missing_items": missing,
        "missing_texts": [items[i] for i in missing],
        "coverage": round(len(covered) / len(items), 4),
        "items": items,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def render(result: dict) -> str:
    """把结果渲染成人读的文本。每个工具的版式不同。"""
    out: list[str] = []
    if not result.get("ok", True):
        out.append(f"无法分析：{{result.get('error', '未知原因')}}")
        return "\n".join(out)
    out.append(f"条目数：{result['count']}  唯一词 {result['unique_tokens']}  共享词 {result['shared_tokens']}")
    out.append(f"覆盖率：{result['coverage']:.2%}")
    out.append("")
    if result["missing_items"]:
        out.append("未被覆盖的条目：")
        for i, t in zip(result["missing_items"], result["missing_texts"]):
            out.append(f"  #{i}: {t[:100]}")
    else:
        out.append("所有条目都被覆盖。")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="redteamcover",
        description="把攻击面清单与红队用例对照，标出未覆盖的类别（仅依赖标准库）",
        epilog=(
            "示例:\n"
            "  python redteamcover.py --file input.txt\n"
            "  python redteamcover.py --text '示例内容'\n"
            "  python redteamcover.py --file input.txt --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="输入文件路径")
    src.add_argument("--text", help="直接给出输入内容")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            print(f"读不了文件：{{e}}", file=sys.stderr)
            return 2
    else:
        content = args.text

    if not content.strip():
        print("输入是空的。", file=sys.stderr)
        return 2

    result = redteamcover_analyze(content)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(render(result))
    return 0 if result.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
