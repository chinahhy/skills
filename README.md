# skills

可移植的 Agent Skills。技能使用标准 `SKILL.md`（YAML 元信息 + Markdown）和相对路径，不绑定某个模型、桌面应用、GitHub 连接器或设备。

## 当前技能

| 技能 | 用途 |
| --- | --- |
| [proxy-ruleset-organizer](skills/proxy-ruleset-organizer/SKILL.md) | 审查、分类、重排 Mihomo / Clash 文本规则集；核对语义、重复与覆盖，生成可审阅预览，并在得到相应授权后发布。 |

## 移植和使用

支持 [Agent Skills 标准](https://agentskills.io/specification) 的工具：将整个 `skills/proxy-ruleset-organizer/` 文件夹复制到该工具配置的技能目录，保留目录结构。发现目录和调用方式以目标工具自身说明为准，不需要修改技能正文中的路径。

不支持原生 Skills 的 Agent：让它读取 `SKILL.md`，并按其中链接读取需要的参考文件。可以使用下面的提示：

```text
读取 skills/proxy-ruleset-organizer/SKILL.md 并按其流程处理我指定的规则目录。
先只读审查，给出分类和重排预览。未获授权前不修改源文件或发布。
```

技能指令本身只需要 Markdown 阅读能力。可选的离线辅助脚本需要 Python 3.9+，仅使用标准库，不访问网络、不写入源文件、不发布、不安装依赖：

```sh
python3 -B skills/proxy-ruleset-organizer/scripts/audit_rules.py /path/to/rules
python3 -B skills/proxy-ruleset-organizer/scripts/audit_rules.py /path/to/before --compare /path/to/after
```

输出为 JSON；第二种调用还检查规则内容、文件边界和禁用模板是否保留。已明确批准的增删可通过 `--approved-changes` 提供，格式见[核验说明](skills/proxy-ruleset-organizer/references/verification.md)。脚本不替代目标代理内核的实际解析或业务验证。

## 约定

- 整理、语义修复、发布和设备部署是不同操作范围；技能不会把其中一项授权扩展为其他操作。
- 分类内先按域名/CIDR字符长度排序，同长度再按 a-z；不会把字典序当成第一排序条件。
- 不把 GFWList 收录、域名能解析或某次 HTTP 失败等同于某个地区全部线路无法直连。
- 仓库只保存通用技能、匿名示例和测试，不保存真实订阅、设备配置、密钥或会话记录。

## 开发验证

```sh
python3 -B -m unittest discover -s tests -v
```

测试覆盖域名后缀边界、精确重复/覆盖区分、IPv4/IPv6重叠、修饰符保留、复杂规则保守处理、模板保持以及显式批准的规则增删。
