# 离线审查和比较

`scripts/audit_rules.py` 仅用 Python 3.9+ 标准库读取文件，将 JSON 输出到标准输出。它不访问网络、不运行代理、不修改任何文件。把输出重定向到文件也属于调用者的写操作，应遵守目标项目的目录与授权要求。

## 审查

```sh
python3 -B scripts/audit_rules.py /path/to/rules
python3 -B scripts/audit_rules.py /path/to/rules --tlds /path/to/iana-tlds.txt
```

目录默认递归读取 `*.list`；可用 `--pattern '*.txt'` 指定其他classical文本后缀，或传单个文件。不要直接传YAML/MRS/SRS。报告包含文件哈希、每条启用规则的原行号、禁用模板、精确重复、域名后缀覆盖、IP网段相交及需要人工检查的内容。

可选 `--tlds` 是调用者已保存的 IANA 官方文本清单；脚本不自动下载。未提供时，报告明确标记TLD未核对，而不是声称全部有效。内部名称只标为复核项。

简单规则支持 DOMAIN、DOMAIN-SUFFIX、IP-CIDR、IP-CIDR6。其他类型保留原文并标记为“辅助脚本未解析”，不宣称规则非法。域名形状警示及IP族别名警示也不替代目标内核的加载检查。

## 纯重排比较

```sh
python3 -B scripts/audit_rules.py /path/to/before --compare /path/to/after
```

比较文件集合、每文件启用规则多重集合和未启用模板。复杂规则被移动，或混合域名/IP文件在无no-resolve条件下发生规则序列变化，会要求人工复核，不自动给出安全通过结论。

脚本不代替分类决策，也不从标题猜测常用度；类别内的长度排序可使用以下明确的键：

```python
(len(value), value.lower(), rule_type, original_line)
```

在生成预览时，为每条输入建立原行到新行的映射，并核对每个类别使用此键；不要只对输出再调用相同排序器就宣称匹配语义已验证。

## 已批准的语义变化

通过 `--approved-changes /path/to/approved.json` 指定明确原文，不使用模糊“忽略所有变化”的开关：

```json
{
  "Example.list": {
    "remove": ["DOMAIN-SUFFIX,old.example"],
    "add": ["DOMAIN-SUFFIX,new.example"]
  }
}
```

键是相对规则根目录的文件路径；目录分隔符统一为 `/`。替换是明确的remove+add；跨文件迁移必须分别列出两边。允许清单需要真正对应发生的变化，多余/不存在的批准项也会报错，防止过期清单被静默采用。

未启用模板不在此放行范围：若用户要改模板，应另审其语法及消费方式，不能以“已批准规则变化”自动启用模板。

普通审查成功返回退出码0；比较不通过、发现需要人工处理的顺序风险或输入/批准清单错误时返回2。报告仍说明具体原因。预期失败用例不等于程序运行故障。

## 已知边界

- 文本参数形状检查不是完整的 Mihomo/Clash 编译器；不同内核和转换器的合法语法可能不同。
- 后缀覆盖只针对读取到的简单规则，不包含未获取的远端规则集、DNS解析后的域名/IP交集或业务频率推断。
- findings达到 `--max-findings` 上限时显式标记截断；不应据不完整报告宣布“没有其他问题”。
- 传入真实配置时，审查报告也应留在任务的授权范围内；本技能仓库只收通用示例，不收个人快照。
