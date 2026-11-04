#!/usr/bin/env python3
"""知识库种子数据(T2.6 首批)。原则:不虚构 CVE 编号;真实事件只写公认事实。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from kb.store import KB

MEM = [
 ("heap-buffer-overflow", "堆缓冲区越界(读/写)", "malloc 分配 n 字节后按未校验长度 memcpy/strcpy 超出边界",
  "长度校验置于拷贝前(剩余空间>=需求);拷贝改用带界函数 memcpy_s/显式 min(len, remain)", "heap,oob,asan"),
 ("stack-buffer-overflow", "栈缓冲区溢出", "固定栈缓冲 + 未截断的 strcpy/sprintf/递归深栈",
  "改 snprintf/strncpy 显式界;栈数组改堆+长度校验;-fstack-protector 缓解", "stack,overflow"),
 ("use-after-free", "释放后使用(UAF)", "free 后指针仍被读写(无置空/延迟重用窗口)",
  "free 后立即置空;引用计数/所有权明确;ASAN 检测", "uaf,asan"),
 ("double-free", "双重释放", "同一指针两次 free(错误路径重复清理)",
  "free 后置空;错误路径统一出口; ownership 唯一", "uaf"),
 ("integer-overflow-alloc", "整数溢出致小分配", "size = a+b 溢出回绕 → 小缓冲装大数据 → 堆溢出",
  "size 计算用宽类型+上界检查;分配前校验乘法结果", "integer,alloc"),
 ("off-by-one", "边界差一(off-by-one)", "循环条件 <= 而非 <;NUL 结尾多写一字节",
  "边界条件用 <;预留终止符空间;模糊测试校准", "boundary"),
 ("format-string", "格式化字符串漏洞", "用户输入直达 printf 族首参 %n/%s 任意读写",
  "printf(\"%s\", input);-Wformat-security;禁 %n", "format"),
 ("null-deref", "空指针解引用(解析器常见)", "malloc 失败/缺字段未判空即用",
  "判空+错误路径;输入 schema 校验前置", "null"),
]

VEH = [
 ("can-bus-off-dos", "CAN 总线 Bus-Off 拒绝服务", "CAN 总线:高频发送最高优先级帧使竞争节点进入 error-passive/bus-off,ECU 失联",
  "总线负载监控+异常计数熔断;网关限速;错误帧隔离(2015 Jeep 攻击链环节,公认事实)", "can,dos"),
 ("can-id-spoofing", "CAN 报文伪造/欺骗", "CAN 无认证:注入合法 ID 帧(如解锁/刹车控制)即可命令 ECU",
  "SecOC(MAC+新鲜度计数);关键报文端到端认证;网关白名单", "can,spoof"),
 ("can-replay", "CAN 报文重放", "录制合法会话报文后原样重放(如解锁帧)",
  "新鲜度计数/时间戳;会话绑定随机数", "can,replay"),
 ("uds-0x27-bruteforce", "UDS 安全访问暴力破解(0x27)", "UDS 0x27 种子-密钥:密钥空间小/无失败锁定,可离线暴力",
  "密钥空间>=足够熵;失败 N 次延时锁定;0x27 升级 0x29 证书认证", "uds,auth"),
 ("uds-0x29-cert", "UDS 0x29 认证缺陷", "证书校验缺失/过期不拒/固定信任链",
  "双向认证;证书链与有效期强校验;防回滚", "uds,auth"),
 ("uds-session-hijack", "UDS 会话切换时序劫持(0x10)", "扩展会话超时窗口内注入 0x22/0x2E 越权读写 DID",
  "会话-安全状态强绑定;超时收紧;写操作二次认证", "uds,session"),
 ("uds-did-fuzz", "UDS DID 读/写模糊测试(0x22/0x2E)", "对 DID 与子索引做变异输入,暴露越界读/崩溃(诊断栈历史高危面)",
  "DID 表白名单+长度校验;模糊测试回归;负响应规范化", "uds,fuzz"),
 ("uds-0x31-routine", "UDS 例程控制滥用(0x31)", "自检/擦除例程未鉴权即可触发,影响 flash/自毁逻辑",
  "例程白名单;高危例程要求安全会话+确认", "uds"),
 ("uds-0x36-flash", "UDS 刷写链无签名(0x34-0x37)", "请求下载-传输-完成链未验签,可刷任意固件",
  "固件签名校验(下载前);防回滚版本检查", "uds,flash,ota"),
 ("isotp-multiframe-overflow", "ISO-TP 多帧组装溢出", "首帧声明长度>接收缓冲,后续帧越界写(经典车载 Telematics 漏洞形态)",
  "首帧长度 vs 缓冲上界校验;分片重组带界;超时丢弃", "isotp,overflow"),
 ("isotp-flowcontrol-dos", "ISO-TP 流控拒绝服务", "不回 FC 或恶意 FC 窗口,阻塞/灌爆接收方",
  "流控超时释放;并发连接上限", "isotp,dos"),
 ("doip-routing-activation", "DoIP 路由激活暴力破解", "13400 路由激活无锁定机制,可枚举激活码建立诊断通道",
  "激活失败锁定/限速;VIN+证书绑定;网络分段", "doip,auth"),
 ("doip-alive-check-spoof", "DoIP 存活检查欺骗", "伪造 alive 应答维持非法连接",
  "双向认证握手;连接表老化", "doip"),
 ("canfd-dlc-misuse", "CAN FD DLC/BRS 误用", "BRS 位或 DLC>8 处理不一致致解析错位(兼容层)",
  "统一 DLC 编码处理;BRS 一致性测试", "canfd"),
 ("lin-checksum-bypass", "LIN 校验和绕过", "增强校验配置不一致,可注入主从帧",
  "校验类型协商固定;主节点校验后执行", "lin"),
 ("someip-sd-fuzz", "SOME/IP-SD 服务发现模糊", "SD 报文字段变异触发栈崩溃/服务劫持",
  "TTL/选项长度校验;模糊回归", "someip,fuzz"),
 ("someip-length-confusion", "SOME/IP 长度字段混淆", "header length 与 UDP 长度不一致致越界解析",
  "长度一致性强校验;拒绝超额声明", "someip"),
 ("ota-update-nosign", "OTA 升级包签名缺失", "升级包可被中间人替换(公认为 2015 Jeep 远程链核心环节)",
  "端到端签名+版本防回滚+A/B 分区校验", "ota,update"),
 ("secoc-freshness-replay", "SecOC 新鲜度计数重放", "新鲜度计数同步窗口过宽可重放认证帧",
  "计数器同步收紧;丢失计数重新同步受认证保护", "secoc,replay"),
 ("xcp-unprotected-write", "XCP 标定写未保护", "DAQ/标定通道开放可改运行参数",
  "XCP 会话鉴权;量产关闭调试协议", "xcp,calibration"),
 ("gateway-id-translation", "网关 ID 转换表错配", "路由表把报文转发到未预期总线/ID,扩大攻击面",
  "转换表配置审计;未知 ID 丢弃", "gateway"),
 ("j1939-address-claim", "J1939 地址声明欺骗", "伪造地址声明抢占比地址冒充节点",
  "地址声明仲裁校验;源地址白名单", "j1939"),
 ("obd-physical-access", "OBD-II 物理接入面", "物理接入即可进入诊断会话(停车场攻击前提)",
  "物理接入后仍要求 0x27/0x29;敏感 DID 二次保护", "obd,physical"),
 ("mqtt-topic-injection", "车云 MQTT 主题注入", "遥测通道主题通配/未鉴权,可注入命令主题",
  "按车辆粒度 ACL;证书双向认证", "mqtt,cloud"),
]


def seed(path="/data/cybergym/kb/kb.sqlite"):
    kb = KB(path)
    for i, (slug, name, cond, fix, tags) in enumerate(MEM, 1):
        kb.add(id=f"KB-MEM-{i:03d}", name=name, component="C/C++ 内存安全",
               attack_conditions=cond, fix=fix, tags=tags, source="memory")
    for i, (slug, name, cond, fix, tags) in enumerate(VEH, 1):
        kb.add(id=f"KB-VEH-{i:03d}", name=name, component=slug.split("-")[0].upper(),
               attack_conditions=cond, fix=fix, tags=tags, source="vehicle")
    # 题库元数据(合成题集;P2 后半可批量导入真题元数据)
    import json
    mf = Path(__file__).resolve().parent.parent / "synthetic" / "manifest.json"
    if mf.exists():
        for i, e in enumerate(json.loads(mf.read_text(encoding="utf-8")), 1):
            kb.add(id=f"KB-CTX-{i:03d}", name=f"题库:{e['task_id']}({e.get('expected_type','?')})",
                   component="synthetic", attack_conditions=Path(e["description"]).read_text(
                       encoding="utf-8")[:200], fix="参考 expected_type 与差分验证口径",
                   tags="task,meta", source="task-meta")
    print(f"[seed] entries={kb.count()} -> {path}")


if __name__ == "__main__":
    seed()
