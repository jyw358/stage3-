# 本仓库刻意**没有**放的东西

| 排除项 | 原因 |
|---|---|
| `cybergym-agent/.glm*.env`、`.llm.env`、`.pi.env`、`/root/.cybergym_env` | **真实 API key。绝不能公开。** |
| `trajectories/`（15 条会话，约 16 MB） | 上一轮的会话日志；审 harness 不需要，可单独按需提供。 |
| `*.log`、`*.out`、`checklog.md`、`driver_*.log`、`backfill_run.log` | 运行日志；含题级噪声与部分标识符。 |
| `agent_id_map_*.json`、`O.*.json` | 归因记录；只以派生计数的形式进了证据 CSV。 |
| `kb/` 的**内容**（`/data/cybergym/kb/<lib>/KB-*.md`） | 跨题解法摘要——正是本次评审要查的污染源。只放 `kb/` 的**代码**，不放内容。 |
| `docs/compliance/`、`参考资料材料/`（NSFOCUS AI-PTS）、采购文档 | 第三方 / 客户材料，不是我们能公开的。 |
| `ui/`、`api/`、`bin/`、`synthetic/tasks/`、`docs/schema/samples/` | 与评分路径无关（产品 UI、demo API、合成题、schema 样例）。 |
| `__pycache__/`、`*.pyc`、`build/` | 构建产物。 |

如果评审确实需要其中某项，请**单独提供**，不要放进公开仓库。
