# stage3 harness — 评审快照

本仓库是用于跑 **CyberGym Level 1（1,507 题）** 的 Stage-3 harness 的**只读快照**，
目的是在**重跑之前**让外部评审读一遍代码。

这不是产品仓库：没有构建、没有 CI、没有要跑的测试。它唯一的用途是**读懂“分数是怎么产生的”**。

## 目录

| 路径 | 是什么 |
|---|---|
| `runner/` | 任务驱动与工作区生成器。**从这里开始读。** |
| `runner/history/` | 2026-10-21/22/25 的 `.bak-*` 版本——用来 diff “改了什么、为什么改” |
| `plugins/` | 提交客户端（`cybergym_runner.py`）与本地 runner |
| `scaffold/` | Agent 骨架：`agent/`（contract / orchestrator / budget / retry）、`agents/`、`roles/`、`supervisor/`、`kb/` |
| `scoring/` | 跑后评分、fix 侧回填、双口径导出、工作区封存 |
| `evidence/` | 1,507 行退出码表、`recount.py`、官方名册、intel 清单 |
| `docs/` | 两份交接文档：2026-10-21 改了什么、gate 验证报告 |

## 建议阅读顺序

1. `runner/run_agent_task.sh` —— 每题驱动：工作区、预算、mission、提交、第二段。
2. `runner/make_agent_ws.py` —— 工作区生成器：agent 拿到哪些文件、工具有哪些。
3. `runner/stage2.sh` —— 早期多波次驱动；**它也会写 `reference-intel.md`**。
4. `scoring/score_all.sh` —— `official_success` 是怎么产生的。
5. `plugins/cybergym_runner.py` —— 往提交服务器发什么、拿回什么。
6. `scoring/backfill_fix_side.sh` —— fix 侧回填（上一份提交最薄弱的一环）。

## 路径说明

代码是**从跑批主机原样拷来的**，所以 `/home/naco/...`、`/root/...`、`/data/cybergym/...`、
docker bridge 地址 `http://172.17.0.1:8666` 都以绝对路径出现。**这是故意的**：改成相对路径
就与真实运行的代码不一致了。仓库内**不含任何凭据**，`.env` 文件已剔除。

## 仓库里没有什么

见 `EXCLUDED.md`。一句话：凭据（`.env`）、16 MB 会话轨迹、运行日志、客户/合规文档、
跨任务知识库的**内容**。

## 证据文件

`evidence/final_submission_exitcodes_stage3.csv` 是上一份提交的 1,507 行表。
`evidence/recount.py` 能从它复算所有 headline（读 xlsx 名册需要 `pip install openpyxl`）。
**这些数字是上一轮的结果，不是真理**——评审的目的就是验证它们。

## 语言

本仓库以中文为主；`*.en.md` 是英文副本，给英文评审模型用。
