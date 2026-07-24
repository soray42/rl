# P1 v5.3 — Prospective Credit-to-Memory Comparative-Effectiveness Study

七审→八审→九审三轮工程对抗后的 v5.3。九审两 P0 闭合:①**N9-R1 完整 gate 规格钉死为代码常量**(ID→谓词→依赖集→证据路径逐项比对;C1/C2 臂对钉死)——九审谓词换血攻击重放实测被拒,37 处篡改逐条点名;②**N9-R2 锁拆两阶段**:input lock 排除 evidence/(自指环结构性消失,验收测试:真证据 PASS 与锁验证共存),release attestation 记录 input lock+全部证据哈希+结果;③**N9-R3 逐门 JSON Schema(additionalProperties:false、类型/边界/64hex)+ verdict 由 runner 按阈值机器推导**,自报 PASS 与机器结论不符即 FAIL(null 指标/伪 UTC/逻辑矛盾/超预算全被回归钉死);④N9-R4 readiness 不写仓库外锚,仅 release 写;**信任边界如实声明:链只防审计包内篡改,第三方可验证性来自 git 历史+tag 与审计方快照**;⑤N9-R5 严格 JSON(拒 NaN/Infinity 字面量+全树有限检查,含 1e999 溢出走私);⑥scoring 失败收据强一致;⑦**幅度端到端回归**:同秩/同号、仅改相对幅度→检索上下文与 prompt 哈希必变。G2 主张按九审收窄为 canonical-Brier-locked update policy with a non-feedback reporting layer。**权威载体 = manifest.json(canonical JSON 单解析语义;八审 #8 选项 2);manifest.yaml 为生成的展示文件。**

八审→v5.2 关键闭合:①ci.sh `set -euo pipefail`+测试退出码保真;②**G2 由构造成立**——更新管线只消费原始 (q,y),分数约定在代码里没有通往记忆的参数(八审域内消差反例失去攻击面);③deep_validate 跨字段语义(gate 集合精确、contrast 引用、FROZEN 逐字段类型)+2 个 r8 恶意形状 mutant;④attestation 哈希链(prev 链接)+**仓库外锚点**,改状态+重算校验和会被链和锚双重识破;⑤逐门 evidence 契约(必需 metrics 键+绑定当前 manifest/lock 哈希),五键空壳必 FAIL;⑥NaN/inf 时间戳拒收,neg-risk 不变量下沉到 state();⑦scoring 按模式选罚分(无自由参数)、全删失=显式错误、重复注册拒绝、失败类型通道;⑧G9a 五份证据文件哈希钉死;⑨**幅度重返记忆**:量化比率(scale-free)驱动检索与淘汰——回应八审身份偏差(不再只是秩/符号策略)。

七审(BLOCK)按修复契约 E0-E12 重建的仓库。**manifest 里写着它自己的诚实状态:`runnable scaffold under repair contract E0-E12; NOT a freezable experiment system`。** 状态唯一来源 = `./ci.sh` 产出的 `build/gate_status.json`(带 attestation envelope,手改即失效)。

## 命令

```bash
./ci.sh        # 就绪 CI:自动发现的测试 + 只读锁验证 + gate DAG(允许 PENDING)
./release.sh   # 发布语义:任何 PENDING/FAIL → 非零退出(当前必然拒绝,这是正确行为)
P1V5_REFRESH_INTENT=yes python3 tools/refresh_lock.py   # 显式发布动作:刷新锁+仓库外可信根
```

## 七审 → v5.1 的结构性变化

| 七审攻击 | v5.1 修复 | 证据 |
|---|---|---|
| P0-01 G0 收非法 manifest | 真 Draft-7(jsonschema,schema 先自检)+ `additionalProperties:false` + manifest↔运行时注册表绑定 + 3 个 mutant 必须被拒 | `test_manifest.py` |
| P0-02 锁自我重封/状态可手写 | refresh(显式授权)与 verify(只读)分离;全量清单(多文件即 FAIL);外部钉重算不信盘上值;**可信根存仓库外**;gate_status 带 attestation,手改被 `verify_status_file()` 识破 | `test_regressions_r7.py` |
| P0-05 乱序/非法 finalize/哈希注入/neg-risk 双赢 | 事件账本重建:**canonical fold(按 (t,source,msg_id) 纯函数折叠)→ 乱序不变性是构造性的**;非法转移一律 quarantine(fail-closed);dead-letter 不消耗幂等键;canonical-JSON 承诺哈希(防注入);组不变量(两个 yes → 整组隔离);承诺 write-once | `test_clocks.py` 15 fixtures + 回归 |
| P0-06 q=None 有利可图 | failure_loss=1.0(最坏损失,策略性失败结构性无利)+ 0.25 敏感性预注册 + 类型化失败分类 + 空注册=错误 | `test_policies.py` |
| P0-07 sham 单例/恒等置换 | Sattolo 环(保证无不动点)+ 单例预注册中性化 + 逐 rollout 收据配平 + 20 批次全解耦断言 | `check_g10_placebos` |
| P0-08 FREEZE 可骗 | schema 强制 FROZEN→非空值;FREEZE 要求理论工件内容收据(测试子进程 exit 0);external gate 要类型化证据 JSON,不认名字前缀;release 语义分离 | `release.sh exit=2` |
| P1-1 仿射普遍性过强 | 收缩为 manifest 声明的可容许域(a≤1e6, b∈[1e-6,1e6])+ 比率量化(9 位有效数字)秩归一 | `check_g2_invariance` |
| P1-2 G1 自证 | 独立解析 oracle((qr−qf)(qr+qf−2y))+ y∈{0,1}/ties/zero/clipping 五种世界 | `check_g1_estimators` |
| P1-3 断言可被 -O 剥掉 | unittest 断言 + config 导入时拒绝 PYTHONOPTIMIZE + CI 环境守卫 + `unittest discover` 自动发现(未来测试不会被漏跑) | `TestOptimizeGuard` |

## 当前机器状态

以 `python3 -B src/p1v5/gate_runner.py` 的实跑输出为准(README 不复述会过期的数字)。PENDING 门全部卡在外部证据工件(`evidence/*.json`,类型化 schema + referent 重算,由真实工具运行产出)。**release.sh 在任何 PENDING 存在时退出 2 是正确行为**——拒绝放行。

## 诚实边界(七审裁决起,r13 更新)

E3/E4 已实现:真实 LLM/transcript 管线(`src/p1v5/deliberation.py`,receipted,provider 钉死)、随机分配执行器与四账本估计器(`src/p1v5/analysis.py`,波内对比 + wave×family 联合 bootstrap,Bonferroni **NOMINAL** 联立 CI——覆盖率待 production G6 仿真升格)。仍未做:完整 g5a_candidate 批次、带收据 live micro-pilot(G7a 证据再生)、pre_outcome_branches 归档(G4)、G5a/G6 闭环。manifest `arms` 段的 toy_scaffold 标注指五臂的**玩具合成世界演示**(G1/G10 用),真管线的策略级区分要等前瞻窗口——这不是统计代码缺席,是确证数据缺席。
