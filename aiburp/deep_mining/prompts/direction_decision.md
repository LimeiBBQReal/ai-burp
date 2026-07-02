深度挖掘第 2 轮。基于 Round 1 的发现决定:

1. **继续与否**: 是否值得继续挖 (yes/no + 理由)
2. **方向**: 如果继续, 挖哪个方向 (新 URL / 隐藏参数 / 第三方 JS / 登录后接口)
3. **收敛条件**: 触发任一即停止
   - 连续 2 轮没新 high 目标
   - 本轮 new URL 数 < 5 (已收敛)
   - 已超 3 轮
   - session 已登录 > 5 次 (防账号锁定)

## Round 1 决策摘要

{round1_summary}

## Round 1 新挖出的资产

{new_assets}

## 当前 high 清单

{current_high}

## 当前候选数

{candidate_count}

## 输出 JSON

```json
{{
  "continue": true|false,
  "next_direction": "新 URL | 隐藏参数 | 第三方 JS | 登录后接口 | 停止",
  "rationale": "为什么这个方向 (一句话)",
  "stop_reason": null|"converged|low_value|max_rounds|account_lock_risk"
}}
```