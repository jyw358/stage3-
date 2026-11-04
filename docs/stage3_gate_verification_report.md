# Stage-3 单端点门控 · 隔离验证报告

> **版本**：v2 · 2026-10-20（v1 的 §3.1/§3.2/§5.1/§5.2 数字有误，已按完整 type 集重算并加勘误标注）
> **日期**：2026-10-20 · **方式**：全隔离（未改共享代码、未写 `poc.db`、未写任何 `r_*_ws` 工作区）
> **对象**：DeepSeek 提出的「去掉 fix 侧后，用 description + vul 侧信号做提交前质量门」
> **一句话结论**：**代码实现可用，但判据在本数据集上不成立——它在真正成功的 PoC 上误杀 2/3（`keep_P` 32.7% vs 基准 68.7%），比「什么都不判、只看稳定性」更差。**

---

## 0. 隔离证明

| 项 | 证据 |
|---|---|
| 共享代码未改 | `verify_gate/BASELINE.sha256` 记录了 4 个原文件哈希；所有改动只发生在 `verify_gate/app/diff_verifier_v2.py`（副本） |
| `poc.db` 未写 | 全程未调用 8666 端口；判定只用 `local_oracle.run_side()` |
| 工作区未写 | 只读 `description.txt` / `.repo-map.json`；PoC 用 sha256 匹配后**复制**到 `verify_gate/cases/poc/` |
| 状态文件隔离 | `ORACLE_LOG` 指向 `verify_gate/out/oracle_l*.log`；未触碰任何 `.checks` / `.oracle.log` |
| 磁盘 | 产物 7.7 MB，全部在 `/data`（90 G 余量）；未写 `/tmp`（96 G 取证对象） |
| 容器 | rootless docker（naco），`--rm`，2 路并行，峰值 2 核 |

**回滚**：`rm -rf /data/cybergym/stage3/verify_gate` 即完全还原。

---

## 1. L1 静态验证：6/6 通过

| 检查 | 结果 |
|---|---|
| T1 源码无 fix 通道（`fix_image`/`submit-fix`/`fix_exit`/`fix_sig`/`fix_output`） | PASS |
| T2 `classify` 九分支真值表 | PASS |
| T3 evidence allowlist 无 fix 键 | PASS |
| T4 description 覆盖率（1,507 条） | PASS |
| T5 reach 适配器（`repo_map.load` + 双向 BFS） | PASS |
| T6 稳定性阈值 2-of-3 / 3-of-3 行为 | PASS |

**T4 关键数字**（1,507 条真实 description）：

| 项 | 值 |
|---|---|
| 含 crash type | **42.1%** |
| 含函数名形式 | 100%（**虚高**：正则抓任意 ≥5 字母词，中位 10 个/篇） |
| 层级分布 | L2 57.9% / L3 42.1% / L0·L1 = 0 |

**T5 关键数字**（20 个真实 `.repo-map.json`）：

| 项 | 值 |
|---|---|
| 符号级可解析率 | **32.9%**（提取出的符号里能在调用图找到的） |
| 题级至少一个符号可解析 | **85.0%**（17/20） |

> L1 的 85% 一度看起来是好消息，但 L3 证明它是**假象**：能解析出符号 ≠ 崩溃帧落在符号邻域内。

---

## 2. L2 回放：稳定性审计在这批数据上零区分度

30 个冻结 PoC（15 neg + 15 pos）× 3 跑：

| 指标 | 值 |
|---|---|
| 有 memory crash 的题 | 25 |
| **2-of-3 通过** | 25（100%） |
| **3-of-3 通过** | 25（100%） |
| 差异 | **0.0 pp** |
| 单跑耗时 | 3.42 s（容器 1.8–2.7 s + 开销） |

**结论**：DeepSeek 建议的「把 2/3 改成 3/3」在本数据集上**没有任何影响**——最终提交的 PoC 本来就是精挑细选的稳定版本。它的「2/3 等于 33% 送死」担忧不成立，**不需要改阈值**。

---

## 3. L3 判别力：门不可用（核心结果）

327 题（52 neg = 曾有 `fix 也崩` 提交；275 pos = 真正成功）× 2 跑。

### 3.1 当前门（type + symbol）

> **勘误（2026-10-20，v2）**：本节初版报的 `catch 76.9% / keep 24.4% / 误杀 208` 是**错的**。原因是 `l3b_decompose.py` 在写 `l3_rows` 时把 `ctx["types"]` 截断成前 3 个（`[:3]`），重算时多出 23 个伪 "type reject"。下表已用**完整 type 集**重算（`l3b_recomputed.json`），`l3_report.json` 自洽的数字是 `catch 63.5% / keep 32.7%`。

| 指标 | 值（修正后） |
|---|---|
| `catch_N2`（拦下负例） | **63.5%**（33/52），95% CI **[49.9, 75.2]** |
| `keep_P`（放过正例） | **32.7%**（90/275），95% CI **[27.5, 38.5]** |
| 误杀正例 | **185 题** |
| 签名稳定性 | 99.4% |

### 3.2 反事实对照（完整 type 集重算）

| 门 | catch_N2 | keep_P | 误杀 | 净（r=1） |
|---|---|---|---|---|
| **只稳定性（不用任何判据）** | 13.5% (7/52) | **68.7%**（CI [63.0, 73.9]） | 86 | −79 |
| 只 type | 23.1% (12/52) | 58.9% | 113 | −101 |
| 只 symbol | 59.6% (31/52) | 38.9% | 168 | −137 |
| **type + symbol（当前）** | 63.5% (33/52) | **32.7%** | 185 | **−152 = −46.5pp** |

**相对基准**：当前门多拦 26 个负例，代价是多误杀 **99 个真正成功的 PoC**。即使假设每个被拦负例都能找到替代 PoC（`r=1`），净额仍是 **−152 题（样本内 −46.5pp）**——所以"要估 `r`"这个反驳不成立。
**CI 判读**：`keep_P` 上界 38.5% < 只稳定性下界 63.0%，**"门比只稳定性差"是统计显著的**（24.5 pp 差距的两端不重叠）。

### 3.3 误杀归因（185 个被拒正例）

| 原因 | 数量 | 说明 |
|---|---|---|
| 本地跑不出 memory crash（`no_trigger`） | **86** | 见 §4.1 |
| symbol miss | **60** | 崩溃帧不在提取符号的 2 跳邻域内 |
| type mismatch | **39** | 见 §4.2 |

### 3.4 type 判据的匹配率（决定性）

| 角色 | 描述类型与实测 kind 相符 | 不符 |
|---|---|---|
| 正例 | 17 | **62**（78.5% 不符） |
| 负例 | 2 | **14**（87.5% 不符） |

**判别力仅 9 pp（87.5% − 78.5%），但代价是误杀 62 个正例。** 这个判据在本数据集上不是信号，是噪音。

---

## 4. 三个副产品发现（比结论本身更有价值）

### 4.1 本地 oracle 与服务器判定有 ~31% 的系统性缺口

86/275 个**真正成功**的 PoC 在本地重跑时产生不了 memory crash：

| rc | 数量 | 解释 |
|---|---|---|
| 1 | 45 | 非零退出但**无 sanitizer 输出** |
| 77 | 39 | libFuzzer `-error_exitcode`，签名解析失败 |
| 124 | 2 | 超时 |

**根因**：`local_oracle.classify()` 把「rc=1 且无 FATAL_RE」判为 `CLEAN`，而官方谓词只看 `exit ∉ {0,300}`——**rc=1 在服务器侧算成功崩溃，在本地算干净**。

> 这是 `local_oracle.py` 的一个真实口径 bug，影响**所有**「本地回放/本地筛选」类方案（不止这一个门）。修它需要对齐服务器语义：`rc ∉ {0,300}` 即候选崩溃。

### 4.2 描述驱动的类型映射在本库上基本无效

`_TYPE_RULES` 把 "out of bounds" 映射到 `heap-buffer-overflow`，但本库 **91% 的崩溃是 MemorySanitizer `use-of-uninitialized-value`**，而描述里极少写 "uninitialized"。结果是：42.1% 的题能抽出类型，其中 78.5% 与实测不符。

### 4.3 符号提取噪音过大，导致 symbol 判据几乎全 miss

`_SYM_BARE_RE`（≥5 字母单词）在 161 字节的描述上平均抓 10 个符号，绝大多数不是函数名。实测 `target_match` 分布：**hit 12 / miss 132 / unknown 183**。也就是说，在能解析的题里，崩溃帧几乎从不出现在符号邻域内——**这个判据的默认答案就是"不合格"**。

---

## 5. 结论与建议

### 5.1 结论

1. **DeepSeek 的代码架构可以落地**（L1 6/6 通过，patch 结构正确，`_reach` 换成 `repo_map` 后可用）；
2. **它的判据不能落地**——在本数据集上，`type + symbol` 的 `keep_P = 32.7%`，比"什么都不判"（68.7%）差 36 pp，且两者 CI 不重叠；
3. 此前几轮 AI 反复推荐的「描述-崩溃对齐门」**在这条数据上被证伪**，与 Claude 的 "SFC≥2 ⇒ 90% 命中" 相差极远；
4. 因此：**合规提高成功率的路径不在"更聪明的门"，而在"更多地跑"**——178 道零提交题、171 道级联题，这部分不依赖任何 fix 侧信息。
5. **本地 vul-only 门在原理上没有判别力**：负例（fix 也崩）在 vul 侧与正例同分布，"只稳定性"门拦下的 7 个负例**全部**来自同一个 `no_trigger` 伪影（§4.1）。修好仪器后它的 catch 会归零——即天花板就是零。

### 5.2 建议动作（按优先级）

| 序 | 动作 | 依据 |
|---|---|---|
| 1 | **修 `local_oracle.classify` 的口径 bug**（`rc ∉ {0,300}` 即崩溃候选）；必须带假阳性控制与 `rc_space` 分离 | §4.1，影响所有本地回放类方案 |
| 2 | **不要合并 `diff_verifier_v2` 的 type/symbol 判据** | §3.2，净损失 152 题（r=1 时仍为负） |
| 3 | ~~只留「稳定性 + `NO_TRIGGER` 早退」是最优解~~ **本建议作废** | 68.7% 是坏仪器的读数；修好 classify 后它是 ~98%，但 catch 归零——它只是**卫生检查**，不是判别器 |
| 4 | 把 §4.1 的发现写进 writeup：本地回放有 31% 缺口，这是**已知限制**不是新发现 | 诚实性 |

### 5.3 独立副本状态

`verify_gate/app/diff_verifier_v2.py` 是完整可运行实现（含 6 个 L1 测试）。
**建议：不合入共享代码**；若将来要用，只取其中的 `parse_frames` / `_evidence` allowlist / `assert not any(k.startswith("fix"))` 这三处（纯防回归价值），判据部分删掉。

---

## 6. 产物清单

| 文件 | 内容 |
|---|---|
| `verify_gate/BASELINE.sha256` | 共享代码基线哈希（证明未改） |
| `verify_gate/app/diff_verifier_v2.py` | 单端点门实现（独立副本） |
| `verify_gate/l1_test.py` | L1 六项测试 |
| `verify_gate/out/l1_report.json` | L1 明细 |
| `verify_gate/out/l2_report.json` | L2 30 题 × 3 跑明细 |
| `verify_gate/out/l3_runs.json` | L3 327 题 × 2 跑原始签名 |
| `verify_gate/out/l3_report.json` | L3 分类结果 |
| `verify_gate/out/l3b_report.json` | 误杀归因（**v1，types 被截断，仅作历史记录**） |
| `verify_gate/out/l3b_recomputed.json` | **v2 权威版**：完整 type 集下的反事实门表 + Wilson CI |
| `verify_gate/cases/` | 327 个 PoC 副本 + manifest（7.7 MB） |

**复现**：

```bash
cd /data/cybergym/stage3/verify_gate
python3 l1_test.py                    # ~10 s
sudo -u naco python3 l2_replay.py     # ~3 min
sudo -u naco python3 l3_phase1.py     # ~20 min
python3 l3_phase2.py && python3 l3b_decompose.py
```
