# G9 注册检索协议 v1.0(G9a 证据工件)

状态:v1.0,2026-07-13 由六轮审计轨迹正式整编(追溯性质如实声明:检索行为发生于 2026-07-11 至 2026-07-13 六轮审计期间,本文档将其固化为可复跑协议;G9b 为 LOCK 前的预注册重跑)。

## 1. 来源与数据库

- arXiv(abs 页 + html/ar5iv 全文;新论文以 html 全文核验为准)
- 通用 web 检索(审计方 Codex 独立检索 + 我方 Sonnet 核验兵交叉检索,双通道)
- 官方文档域(docs.polymarket.com、平台条款、监管文本;仅用于事实核验非文献)

## 2. 查询族(每轮均覆盖,G9b 重跑照抄)

Q1 multi-agent LLM credit assignment / counterfactual credit;Q2 LLM memory + reward/credit/RL(external memory, experience library);Q3 LLM forecasting + prediction markets(Polymarket/Kalshi, prospective, commit-reveal);Q4 counterfactual replay / intervention ledger / agent attribution;Q5 Shapley / leave-one-out for agent teams;Q6 prospective benchmarks with delayed real-world resolution。

## 3. 筛选与核验规则

标题/摘要初筛 → 全文逐论断核验(每条给 ≤25 词原文短引;✅逐字/✅逐义/⚠️部分/❌不成立);ID 或标题对不上即 ❌;抓不到全文标 ⚠️UNVERIFIED 并记录尝试 URL;逐条 verdict 保留,不宣传比率。

## 4. 比较者登记册(六轮累计 32 篇全文核验)

证据文件(哈希入 locks/artifact.lock.json 之 external 区之外,由 phase_b2 只读保存):

- 轮 1-2:`phase_b2/04_special_searches/credit_priors_verification.md`(6 篇)
- 轮 3:`phase_b2/04_special_searches/round3_novelty_verification.md`(4 篇)
- 轮 4:`phase_b2/04_special_searches/round4_novelty_verification.md`(5 篇):MATTRL/TreeMem/HiveMind/FutureWorld/CAR)
- 轮 5:`phase_b2/04_special_searches/round5_novelty_verification.md`(10 篇):HiMPO/Memory-R2/MemoPilot 系统名/CoMAM/LLMA-Mem/Fine-Mem/Foresight Arena/Prediction Arena/Coordination-as-Layer/AgenTracer)
- 轮 6:`phase_b2/04_special_searches/round6_novelty_verification.md`(7 篇):SelfMem/CMI/MemPO/MMPO/MemMA/MemCoE/Decision-Aware Memory Cards)
- 审计方独立日志:`phase_b1/*/07_source_log.md`(轮 4-6)

## 5. 残余交集(唯一许可的 novelty 表述所指对象)

七要素:真实预测市场事件流 × pre-outcome forecast commitments × 真实延迟结算 × 多智能体 credit × 外部记忆更新 × 随机化 policy 比较 × stateful 推断。六轮 32 篇中 0 篇单篇覆盖(轮 6 核验:最近触碰者 MemMA,probe 为 session 内合成信号非真实延迟 outcome)。措辞永远限定 "to our knowledge, under the registered search protocol"。

## 6. G9b 预注册重跑(LOCK 的前置)

LOCK 前 14 天内:同六个查询族 + 提交日期过滤(> 2026-07-13);双通道筛选(核验兵 + 审计方);输出 delta 表(新命中 → 全文核验 → 交集影响评估);任何触碰残余交集的新命中自动使 G1/G2/G6 转 PENDING 并重估。
