深度挖掘最后 1 轮。判断是否收敛, 给出最终 high 清单.

## 强制收敛条件 (任一满足即收敛)

- 当前 high 目标数 < 3
- 本轮 new URL 数 < 5
- 已超 3 轮
- session 已登录 > 5 次

## Round 2 决策摘要

{round2_summary}

## 累计 high 清单

{accumulated_high}

## 累计候选数

{candidate_count}

## 输出 JSON

```json
{{
  "converged": true|false,
  "final_high_list": ["/api/users/{N}", "/admin"],
  "must_probe": ["/login"],
  "summary": "深度挖掘整体结论 (100 字以内, 包含: 挖到几条 high / 跳过了什么 / 建议 Phase ④ 重点测哪些)"
}}
```