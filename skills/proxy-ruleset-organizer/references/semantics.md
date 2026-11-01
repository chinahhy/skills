# 匹配语义与分类示例

## 域名边界

```text
DOMAIN-SUFFIX,example.com
```

匹配 `example.com`、`a.example.com`、`b.a.example.com`；不匹配 `notexample.com`、`example.com.other.net`。`DOMAIN,a.example.com` 只匹配该主机名，不能为了压缩条数改成父域后缀。

若同一 classical 文件中已经存在 `DOMAIN-SUFFIX,example.com`，它通常覆盖其中的简单 `DOMAIN,a.example.com` 和 `DOMAIN-SUFFIX,a.example.com`；确认消费方式和等价性后可建议去掉冗余。跨文件可能采用不同策略或顺序，不能据覆盖就删文件或移动规则。

独享主域的全部子域确实都应走同一策略时，可以保留主域。共享平台中的 `project.storage.example.net` 不应随意缩成 `example.net`，否则会包含其他租户和业务。可注册主域不一定只有两个标签，例如 `example.co.uk`；不要把 `co.uk` 当作一个用户的主域。

## 长度是第一排序条件

同一类别、同一层级的输入：

```text
DOMAIN-SUFFIX,bb.example
DOMAIN-SUFFIX,z.example
DOMAIN-SUFFIX,aa.example
```

正确排序：

```text
DOMAIN-SUFFIX,z.example
DOMAIN-SUFFIX,aa.example
DOMAIN-SUFFIX,bb.example
```

`z.example` 更短，因此排在字母更靠前的 aa/bb 前；长度相同时才比较字典序。不同服务类别之间先遵守已经明确的分类次序，不把所有规则打散成全文件字母表。

## 不能从子目顺序推导外层优先级

```text
# broad.list
DOMAIN-SUFFIX,example.net

# service.list
DOMAIN-SUFFIX,attachments.storage.example.net
```

如果外层先匹配 broad 再匹配 service，移动 service.list 内的行无法改变前者先命中的结果。可在明确授权后调整具体例外的位置或缩小广泛规则；不要无意交换所有 RULE-SET。

## 解析行为

classical 中的目标IP规则可能触发DNS。带 no-resolve 的规则会跳过主动解析，但仍可匹配此前已经取得的目标IP。把无 no-resolve 的IP规则提前，可能在原本域名规则就能终止的位置增加DNS请求；匹配集合看似相同仍不等于行为等价。

`IP-CIDR6` 在 Mihomo 中是 IP-CIDR 的别名；其他转换器可能要求名称与地址族严格一致。审查要基于实际内核和消费者，不将辅助脚本自己的约束当成整个生态的语法规范。

注释中的 AND、端口、关键词示例不是启用规则。保持注释及警示上下文，不能因整理去掉注释符或将其交给不支持的编译器。

## 证据层级

| 观察 | 可以说明 | 不能单独说明 |
| --- | --- | --- |
| 内核加载成功 | 在该版本和配置下可解析 | 域名用途正确、实际命中 |
| 官方应用/刮削源码出现URL | 某版本的依赖或可选来源 | 用户实例启用了它、地区封锁 |
| GFWList等清单收录 | 清单维护者报告需要代理 | 每个运营商、协议、时间都不能直连 |
| 某地一次HTTPS失败 | 该次请求失败 | 一定是网络封锁、域名永久失效 |
| 使用代理成功 | 该次代理路径可用 | 原始直连路径失败原因 |
| IANA清单无某TLD | 当前公共根区不包含它 | 内部DNS/hosts名称必然无用途 |

只读取同问题有关的权威来源和实际消费者，给出不确定性；不要为了归类而对每个域名的归属作无依据断言。

## 官方参考

- [Mihomo 路由规则、优先级与 no-resolve](https://wiki.metacubex.one/config/rules/)
- [Mihomo 规则集合内容与不同 behavior](https://wiki.metacubex.one/config/rule-providers/content/)
- [IANA 当前公共顶级域名清单](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
- [Public Suffix List 的目的与边界](https://publicsuffix.org/learn/)

文档和规则格式会变化，正式处理时核对目标版本，不把本文件当作某个版本的完整语法规范。
