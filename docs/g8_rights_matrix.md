# G8 字段级权利矩阵 v1.0

> 2026-07-13 ｜ 依据:Polymarket Terms of Use(生效 2026-07-06,SHA `27828b62…04efd0`,归档 `phase_b2/05_rights/`,主循环第一手逐行阅读,行号 L8/L9/L46/L71/L77/L82/L83/L96)+ OpenRouter Terms(2026-07-06 版,round5/6 核验)+ 美国版权局 fair-use 逐案原则。
> 本矩阵不是法律意见;默认 fail-closed:无明确 ALLOW 依据的字段一律 RESTRICT。
> 机器摘要由 `tools/make_g8_evidence.py` 生成并绑定当前 manifest/input-lock 哈希。

## 采集侧结论(前提)

个人零售学术用户经公开文档化 API 的读取是条款默许通道(L82 的书面许可门槛只设给 Capital Market Client 与 market data distributor;L9 受限辖区限制只及 Technology Features/交易)。采集纪律:限速、UA 署名、字节级归档、不绕任何访问控制。

## 字段级发布矩阵(14 字段)

| # | 字段 | 来源/所有者 | 发布模式 | 依据 |
|---|---|---|---|---|
| 1 | 我方 forecast 值与承诺哈希 | 自产 | **ALLOW** | 自有作品 |
| 2 | 我方 transcript(商议文本) | 自产(经 LLM) | **ALLOW**(逐模型条款复核后) | OpenRouter output 权利依 Model Terms;发布前逐模型登记 |
| 3 | 我方 credit 值/rank/ratio | 自产 | **ALLOW** | 自有派生 |
| 4 | 我方分数与分析输出 | 自产 | **ALLOW** | 自有派生 |
| 5 | market_id / condition_id / event_id | Polymarket | **ALLOW** | 标识符,非 Data 实质内容;重抓脚本的必要引用 |
| 6 | 我方时间戳账本(retrieved_at/observed_at 等) | 自产 | **ALLOW** | 自有观测记录 |
| 7 | 重抓脚本(refetch scripts) | 自产 | **ALLOW** | 代码,自有作品;使用者自担条款 |
| 8 | 市场价格(raw) | Polymarket | **RESTRICT** | L82"Data"含 raw;L83 再分发至 CMC 需书面许可,公开=必达 CMC |
| 9 | 市场价格(derived/aggregated/anonymized 任何形态) | Polymarket | **RESTRICT** | L82 明文覆盖全形态——"聚合即安全"不成立 |
| 10 | 结算结果字段(outcome/umaResolutionStatus) | Polymarket/UMA | **RESTRICT**(逐题 fair-use 短引可个案评估) | 属 Data;版权局无安全字数公式 |
| 11 | 问题全文(question text)批量 | Polymarket | **RESTRICT**(发布仅 slug/id+链接) | L96 个人许可不含数据集再分发 |
| 12 | 证据包正文(新闻等第三方内容) | 各出版方 | **RESTRICT**(hash+URL+个案短引) | 第三方版权;fair use 逐案 |
| 13 | 模型/provider 配置与路由收据 | 自产+provider 条款 | **ALLOW**(配置)/RESTRICT(含 provider 专有响应头逐项核) | OpenRouter 条款 |
| 14 | 原始 API 响应字节归档 | Polymarket | **RESTRICT**(仅本地保存,永不发布) | 同 #8-#11 |

**计数:ALLOW=8,RESTRICT=6,合计 14(#13 主模式为 ALLOW,其 provider 专有头子项另行逐项核)。**

## 干净路径

价格/结算/问题文本的公开发布唯一干净路径 = 向 Polymarket 取得书面许可(信件草案待用户批准发送);获得前,论文工件层 = #1-#7(自产内容+ID+时间戳+重抓脚本),复现主张限定为 score recomputation(A19 三层区分)。

## EU 补充

用户位于欧盟:数据库权(96/9/EC)与 DSM 2019/790 TDM 例外允许研究性挖掘但不自动授权公开分发语料正文——与上表 RESTRICT 结论一致,无需放宽。
