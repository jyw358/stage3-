"""轻量知识库存储(T2.6):SQLite FTS5 全文检索 + 可插拔向量插槽。

规模纪律:200-300 条起步(计划 v3.1 T2.6,严格 2-3 人日);增量/版本管理归 P6 S6。
条目字段对齐评标 9.1.②:漏洞名称/受影响组件/攻击条件/修复方案。
检索:BM25 全文(当前)+ embedding 列(插槽:设置 KB_EMBED_ENDPOINT 后启用,否则跳过)。
"""
import json
import os
import re
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
  id TEXT PRIMARY KEY,           -- KB-VEH-001 / KB-MEM-001 / KB-CTX-<task>
  name TEXT NOT NULL,            -- 漏洞/知识名称
  component TEXT,                -- 受影响组件(协议/模块/产品)
  attack_conditions TEXT,        -- 攻击/触发条件
  fix TEXT,                      -- 修复方案
  cve TEXT,                      -- CVE 编号(可为空;不虚构)
  tags TEXT,                     -- 逗号分隔标签
  source TEXT,                   -- vehicle | memory | task-meta | public
  created_at REAL
);
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
  id UNINDEXED, name, component, attack_conditions, fix, tags,
  tokenize='unicode61');
"""


class KB:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(SCHEMA)

    def add(self, **e) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?,?,?,?,?)",
            (e["id"], e["name"], e.get("component", ""), e.get("attack_conditions", ""),
             e.get("fix", ""), e.get("cve", ""), e.get("tags", ""),
             e.get("source", "public"), e.get("created_at", time.time())))
        self.conn.execute(
            "INSERT OR REPLACE INTO entries_fts (id,name,component,attack_conditions,fix,tags) "
            "VALUES (?,?,?,?,?,?)",
            (e["id"], e["name"], e.get("component", ""), e.get("attack_conditions", ""),
             e.get("fix", ""), e.get("tags", "")))
        self.conn.commit()

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def query(self, q: str, limit: int = 5, source: str | None = None) -> list:
        """BM25 全文检索;中文按 2-gram 切分入查询(FTS5 unicode61 不分中文词)。"""
        terms = _terms(q)
        if not terms:
            return []
        match = " OR ".join(f'"{t}"' for t in terms)
        sql = ("SELECT e.id, e.name, e.component, e.attack_conditions, e.fix, e.cve, "
               "bm25(entries_fts) AS score "
               "FROM entries_fts f JOIN entries e ON e.id = f.id "
               f"WHERE entries_fts MATCH ? ")
        args = [match]
        if source:
            sql += "AND e.source = ? "
            args.append(source)
        sql += "ORDER BY score LIMIT ?"
        args.append(limit)
        rows = self.conn.execute(sql, args).fetchall()
        return [{"id": r[0], "name": r[1], "component": r[2],
                 "attack_conditions": r[3], "fix": r[4], "cve": r[5],
                 "score": round(r[6], 3)} for r in rows]


def _terms(q: str, max_terms: int = 8) -> list:
    """英文词 + 中文 bigram,去停用词。"""
    q = re.sub(r"[^\w\u4e00-\u9fff]+", " ", q)
    out = []
    for tok in q.split():
        if re.fullmatch(r"[A-Za-z0-9_.-]{2,}", tok):
            out.append(tok.lower())
        else:                                   # 中文 bigram
            s = re.sub(r"[^\u4e00-\u9fff]", "", tok)
            out += [s[i:i + 2] for i in range(len(s) - 1)] or ([s] if s else [])
    return out[:max_terms]
