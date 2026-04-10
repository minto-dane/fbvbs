# FBVBS ミッションクリティカル級 高保証メインフレーム-likeハイパーバイザー実装計画

- 文書バージョン: 1.0
- 日付: 2026-04-03
- 文書種別: 実装優先マスタープラン
- 対象: FBVBS ハイパーバイザー本体、管理面、サービス面、運用面、検証面
- 基本方針: **実装先行、セキュリティレビュー先行、検証は後追い。ただし本番意味論と検証意味論の乖離は増やさない**
- 公開表現上の注記: 本文でいう **「ミッションクリティカル級」「メインフレーム-like」** は、特定企業・特定製品・特定ブランドとの同等性、互換性、提携、認証取得を意味しない。ここでは、**強い隔離性、高可用性、継続運転性、大規模収容性、高監査性、高い運用品質** を備えた仮想化基盤としての品質水準を指す。

---

## 1. 文書の目的

本計画は、FBVBS を単なる研究用・試作的なハイパーバイザーから、以下の特性を持つ **本番運用可能な高保証仮想化基盤** へ段階的に発展させるための実装優先計画である。

### 1.1 目標とする品質特性
1. **強い隔離性**
   - guest / service / host control plane 間の強制分離
   - CPU / メモリ / DMA / 管理 ABI / 監査 ABI の全経路での境界強制
2. **高可用性**
   - 障害局所化
   - 段階的劣化運転
   - 安全停止
   - 回復可能性
3. **継続運転性**
   - 長時間連続運転
   - 保守容易性
   - 更新互換性
   - 実機運用性
4. **高監査性**
   - 改ざん検出可能な監査
   - 監査欠落検知
   - 長期保管
   - 証跡生成
5. **大規模収容性**
   - 高い VM / partition 密度
   - 多テナント運用
   - 管理面のスケーラビリティ
6. **高保証性**
   - セキュリティレビュー主導
   - 後追い形式検証に耐える設計
   - 仕様・実装・テスト・監査の整合

### 1.2 本計画の基本思想
- まず本番実装を完成させる
- ただし、あとで証明不能になる設計は禁止する
- 監査、権限、ABI、状態機械は後付けにしない
- 本番用実装と検証用実装を別物にしない
- 可用性は fail-open の言い訳に使わない
- trusted service を万能権限化しない

---

## 2. 適用範囲

### 2.1 対象
- ハイパーバイザー本体
- command ABI
- policy engine / capability / authorization
- partition / vCPU / memory / storage / device virtualization
- audit / telemetry / diagnostics / health / evidence
- IOMMU / interrupt / EPT/NPT 相当のメモリ変換管理
- confidential / secret / measurement / attestation の基盤
- build / test / fuzz / smoke / soak / proof / compliance artifacts

### 2.2 対象外
- 特定クラウドベンダー固有 API 互換
- 特定商用メインフレーム製品との互換主張
- 任意 OS の完全互換保証
- 未定義 ABI のままの運用ツール先行実装
- 安全性を損なうショートカット的な PoC 実装

---

## 3. 用語定義

### 3.1 役割
- **Host Control Partition**: ハイパーバイザー管理主体
- **Service Partition**: ストレージ、監査、鍵管理、運用支援などの専用サービス主体
- **Tenant Guest Partition**: テナント向け guest
- **Audit Collector**: 監査収集・保管を担当する主体
- **Operator**: 管理者
- **Break-glass Operator**: 非常時限定の強権限管理者

### 3.2 品質概念
- **Fail-closed**: 異常時にアクセスや機能を止める
- **Fail-operational**: 異常時でも限定機能で継続運転する
- **Degraded Mode**: 一部機能を制限した安全運用状態
- **Quarantine**: 隔離状態
- **Revocation**: 権限・割当・可視性の取り消し
- **Evidence Pack**: リリースまたはインシデントに関する証跡一式

### 3.3 検証概念
- **Production Semantics**: 本番実装の意味論
- **Verification Semantics**: 検証対象としての意味論
- **Acceptable Stub**: ハード依存のみ差し替える許容 stub
- **Forbidden Divergence**: 権限、状態遷移、監査可観測性を変える禁止乖離

---

## 4. 成功条件

本計画の成功は、以下をすべて満たしたときとする。

1. guest / service / host の境界が CPU / memory / DMA / ABI / audit の全経路で強制される
2. deny / lockout / fault / revoke / quarantine が欠落なく監査される
3. collector 不在や service fault 時の挙動が policy で固定される
4. ABI が versioning され、後方互換性ルールが運用される
5. 管理面、監査面、秘密管理面が guest 面と分離される
6. `__FRAMAC__` 等の検証分岐が、ハード依存差し替え中心に縮小される
7. 実機での長時間稼働、障害注入、更新試験を継続的に通過する
8. 重要状態機械に対して後追いで ACSL / proof contract を張れる構造が維持される

---

## 5. 実装優先ポリシー

## 5.1 原則
1. まず本番設計を固める
2. 実装差分ごとに secure-coding-verifier を先行実行する
3. その後に analyze / build / test / fuzz / smoke を回す
4. Frama-C / WP は機能収束後に段階適用する
5. 本番意味論と検証意味論の乖離を広げる変更は禁止する
6. 新規状態機械は最初から invariant を意識して設計する
7. ABI は後から壊さず、早期に versioning を導入する
8. 監査、権限、境界検査は MVP の時点から必須とする

## 5.2 非交渉事項
- 監査抜け禁止
- 権限バイパス禁止
- 無説明 fail-open 禁止
- trusted service の万能権限化禁止
- 検証分岐で policy engine を別物化すること禁止
- 互換性破壊を無通知で行うこと禁止
- 「あとで proof で直す」を理由に unsafe 実装を入れること禁止

## 5.3 実装順序ルール
1. 仕様整理
2. 探索エージェントによる変更最小案
3. 実装
4. secure-coding-verifier
5. unit / integration / regression / fuzz smoke
6. bare-metal / fault injection / soak の対象追加
7. proof 追随
8. compliance / evidence 更新

---

## 6. アーキテクチャ原則

## 6.1 最上位原則
1. 管理 plane を最小化し、一般 guest と混ぜない
2. 管理 plane と data plane を分ける
3. 権限は subject / object / action / context で判定する
4. 監査は機能ではなく安全境界である
5. confidentiality 機能は hypervisor 可視性の最小化を前提にする
6. migration / upgrade / compatibility は最初から状態機械で設計する
7. proof は後追いでも、proof impossible な設計は禁止する

## 6.2 層構造
### Layer 1: Hardware Isolation Layer
- VMX/SVM 相当の仮想化制御
- EPT/NPT 相当の二段変換
- IOMMU / DMA remapping
- interrupt virtualization
- timer virtualization
- CPU security feature control

### Layer 2: Core Resource Layer
- partition lifecycle
- vCPU lifecycle
- memory object
- page ownership
- storage object
- virtual / direct device assignment
- shared/private/transit page state

### Layer 3: Control Plane Layer
- command ABI
- policy engine
- capability registry
- role/domain/action authorization
- deny threshold / lockout / quarantine
- structured error / deny reason ABI

### Layer 4: Service Plane Layer
- storage control service
- audit collector
- attestation service
- secret / key service
- diagnostics / inventory service
- OCS / VCD 相当の運用支援サービス

### Layer 5: Operations Plane
- health model
- telemetry
- incident handling
- evidence pack generation
- compatibility / upgrade management
- retention / forensic export

### Layer 6: Verification Compatibility Layer
- hardware abstraction for proof
- meaning-preserving stubs
- production/model semantic diff control
- ACSL / invariants / proof shards

---

## 7. セキュリティ基本方針

## 7.1 権限モデル
- 権限は capability 単独ではなく、**role + domain + action + context** で判定する
- trusted service は役割限定権限とする
- host control と service control と audit control を分離する
- break-glass 権限は別監査経路で扱う
- すべての deny は理由コード付きで監査する

## 7.2 境界保護
- command ABI は guest input を直接信用しない
- memory object は owner / mapping / access intent の整合を必須とする
- device assignment は DMA 境界と割込境界を含めて扱う
- revoke / detach / teardown 後の stale visibility を禁止する
- audit collector や secret service へのアクセスを一般管理権限から分離する

## 7.3 機密性
- confidential guest 導入時は、guest private memory の hypervisor 可視性を最小化する
- shared buffer の明示的 grant/reclaim を必須化する
- secret injection は attestation 前提の one-shot にする
- crash dump / diagnostics / audit で秘密が露出しないよう scrub する

---

## 8. 可用性・回復基本方針

## 8.1 障害局所化
- 1 partition の故障は他 partition の停止に直結させない
- service partition fault は degraded mode へ落とす
- audit collector 喪失時の方針を固定する
- metadata corruption は quarantine / operator action を要求する

## 8.2 状態モデル
- healthy
- degraded
- quarantined
- revoked
- suspended
- failing
- emergency-stop

各状態遷移は、**理由、監査、回復条件、operator 可視性** を持たなければならない。

## 8.3 回復原則
- recovery path は operator に説明可能であること
- automatic recovery は policy 明示時のみ
- self-heal は監査を伴うこと
- quarantine 解除は必ず監査すること

---

## 9. 監査・証跡基本方針

## 9.1 必須監査対象
- policy deny
- lockout
- quarantine
- revoke
- fault
- watchdog event
- service failure
- config change
- capacity change
- ABI version change
- migration attempt
- attestation result
- key / secret lifecycle event
- break-glass operation

## 9.2 監査要件
- append-only
- hash-linked
- gap detectable
- exportable
- retention manageable
- schema versioned
- signed manifest possible
- support / forensic bundle 化可能

---

## 10. 完全版ワークストリーム

## WS-A: 制御面ハードニング
### 目的
command ABI、policy decision、replay 対策、管理安全性の一貫性を確立する。

### 実装項目
- [x] policy deny 監査の一貫化
- [x] hypercall abuse guard の同期化
- [x] command tracker ロック範囲最小化
- [x] 重大 policy deny 閾値到達時の fail-closed 隔離
- [x] deny 閾値超過時の運用復旧ガイダンスを管理 ABI に追加
- [x] command ABI schema registry
- [x] command version negotiation
- [ ] replay detection / anti-reordering
- [x] per-command idempotency rules
- [x] structured deny reason code ABI
- [x] operator privilege separation
- [x] emergency break-glass command path の別監査化
- [x] management command rate limiting
- [x] command origin attestation
- [x] admin session correlation ID
- [x] deterministic command-to-audit mapping
- [x] malformed input fuzz coverage 拡張
- [x] reserved field enforcement の全 ABI 徹底
- [x] state transition precondition validator

### 完了条件
- 同一入力は同一 deny reason と同一 audit shape を返す
- 管理 command は replay / reorder / spoof に耐える
- break-glass を通常運用と混同しない

---

## WS-B: 分離と隔離
### 目的
CPU / memory / DMA / service / ABI の全経路で強い境界を形成する。

### 実装項目
- [x] VCD owner mismatch の fail-closed 無効化
- [x] OCS/VCD 境界の capability 強制
- [x] partition 隔離状態の診断 ABI
- [ ] quarantine / suspended / revoked / degraded 状態機械
- [ ] cross-partition object access registry
- [ ] memory object ownership の全経路強制
- [ ] EPT/NPT permission consistency review
- [ ] DMA 隔離完成
- [ ] device revoke race closure
- [ ] shared / private / transit page state machine
- [ ] service partition access window 最小化
- [x] stale mapping detector
- [x] teardown postcondition validator
- [ ] partition lifecycle proof-friendly refactor
- [ ] attach / detach / reclaim regression suite
- [ ] revocation latency measurement
- [ ] cross-boundary telemetry without data leakage

### 完了条件
- revoke 後に stale mapping が残らない
- 無権限の cross-partition visibility が存在しない
- partition 状態遷移が説明可能で監査可能

---

## WS-C: 可用性と回復
### 目的
障害を局所化し、段階的劣化と安全停止を両立する。

### 実装項目
- [x] watchdog fault 経路の整合
- [ ] lock contention metrics 可視化
- [x] fault escalation matrix
- [x] safe stop / degraded / quarantine policy matrix
- [ ] crash containment domain 定義
- [ ] per-partition blast radius 制御
- [ ] metadata checkpoint
- [ ] restart validation
- [ ] auto-fence rules
- [x] collector loss mode
- [x] operator-confirmed recovery flow
- [ ] maintenance drain mode
- [ ] partial service loss behavior 定義
- [ ] long-running soak under fault injection
- [ ] stuck partition recovery ABI
- [x] degraded health scoring model

### 完了条件
- 1 partition の異常が全停止に直結しない
- collector/service 喪失時挙動が定義済み
- 再起動後の metadata 整合が保証される

---

## WS-D: 監査・証跡・フォレンジクス
### 目的
監査を改ざん検出可能かつ長期保管可能にし、フォレンジクスを可能にする。

### 実装項目
- [x] deny/lockout/fault の監査連鎖
- [x] OOB collector 欠落時の運用停止モード
- [ ] append-only audit chain
- [ ] hash-linked audit blocks
- [x] signed export manifest
- [x] evidence pack generator
- [x] retention integrity checker
- [x] remote export retry policy
- [x] time source integrity policy
- [x] audit gap detector
- [x] incident bundle format
- [x] audit schema versioning
- [x] forensic preservation mode
- [x] cross-log correlation tool
- [x] operator timeline reconstruction utility
- [x] audit backpressure policy
- [ ] sensitive field redaction policy

### 完了条件
- silent audit loss が起きない
- release ごとの evidence pack が自動生成できる
- incident timeline を後から再構成できる

---

## WS-E: 容量管理・ワークロード制御
### 目的
収容数増大時にも管理面・監査面を維持しつつ、優先度制御と noisy neighbor 抑制を行う。

### 実装項目
- [ ] CPU share / cap / reservation
- [ ] memory floor / ceiling
- [ ] overcommit policy
- [ ] service partition reserve
- [ ] tenant class / workload class
- [ ] starvation detector
- [ ] tail latency telemetry
- [ ] capacity planner ABI
- [ ] burst allowance policy
- [ ] admission control engine
- [ ] policy-based oversubscription guard
- [ ] audit for capacity changes
- [ ] NUMA-aware placement
- [ ] per-node allocator
- [ ] lock sharding / read-mostly optimization
- [ ] per-CPU fast path accounting
- [ ] noisy-neighbor penalty policy
- [ ] scheduler class hierarchy
- [x] quota drift detector

### 完了条件
- 低優先 guest が高優先 service を飢餓化できない
- 容量変更がすべて監査される
- control plane が O(n) ボトルネックで破綻しない

---

## WS-F: 機密計算・秘密保護
### 目的
hypervisor 可視性を最小化し、attestation と秘密注入を一体化する。

### 実装項目
- [ ] confidential partition type
- [ ] private/shared/transit/invalid page state machine
- [ ] shared buffer grant/reclaim ABI
- [ ] secret injection one-shot ABI
- [ ] attestation report ABI
- [ ] measurement chain extension
- [ ] sealing key design
- [ ] crash dump scrubbing
- [ ] confidential-aware diagnostics
- [ ] key zeroization rules
- [ ] operator policy for confidential guests
- [ ] memory exposure minimization review
- [ ] secret lifetime state machine
- [ ] attestation freshness policy
- [ ] secret unwrap policy
- [ ] confidential migration preconditions

### 完了条件
- confidential guest の private memory を通常診断で読めない
- attestation なし秘密注入を禁止
- log / dump / trace に private data を残さない

---

## WS-G: I/O 仮想化とデバイス信頼境界
### 目的
DMA、割り込み、device assignment を含めた完全な I/O 境界を形成する。

### 実装項目
- [ ] Intel VT-d / AMD-Vi 相当機能の実機 bring-up 完了
- [ ] device assignment state machine
- [ ] DMA remapping fault telemetry
- [ ] IOTLB invalidate correctness
- [ ] MSI/MSI-X isolation review
- [x] device quarantine mode
- [ ] hot-plug / hot-unplug policy
- [ ] emulated / para-virtual / direct device ABI 統合
- [ ] device revoke correctness
- [ ] passthrough safety policy
- [ ] interrupt remap verification
- [ ] device reset orchestration
- [ ] teardown postcondition checks
- [ ] stale DMA mapping detector
- [ ] I/O error recovery runbook
- [x] per-device evidence trail

### 完了条件
- DMA による他 partition 汚染を防げる
- revoke / teardown 後の stale DMA mapping が残らない
- device fault が他 partition に波及しない

---

## WS-H: サービス plane の最小権限化
### 目的
service partition を便利な万能権限主体にせず、責務別に分離する。

### 実装項目
- [x] storage control role
- [x] audit collection role
- [x] attestation role
- [x] secret/key role
- [x] diagnostics role
- [x] per-service object access policies
- [x] break-glass bypass prohibition by default
- [x] service identity attestation
- [x] service-to-service policy
- [x] service compromise containment
- [x] service lifecycle audit
- [x] service privilege review tooling
- [x] unused capability detector
- [x] service API surface minimization

### 完了条件
- 各 service が必要最小権限のみを持つ
- service compromise が全権限化しない
- authorize と実際の操作可能範囲が一致する

---

## WS-I: ストレージ仮想化の高保証化
### 目的
storage object、pool、vdisk、ownership、QoS を一貫した policy の下に置く。

### 実装項目
- [x] host / service / tenant の storage 権限整理
- [x] pool granularity invariant 強制
- [x] capacity / allocated / attached 整合性強化
- [x] vdisk lifecycle state machine
- [x] vdisk ownership / delegation policy
- [x] attach/detach audit consistency
- [ ] snapshot / clone ABI
- [ ] zeroization on release policy
- [ ] backing shortage fail-closed hash semantics
- [ ] storage QoS policy
- [x] corruption detection and quarantine
- [ ] pool health telemetry
- [x] storage evidence trail
- [x] destructive operation confirmation model

### 完了条件
- storage 権限モデルに意味差がない
- capacity invariant が破れない
- release / destroy / reclaim が監査される

---

## WS-J: メモリ管理・所有権・ハッシュ完全性
### 目的
memory object と page ownership を中心に、安全な割当・再利用・監査を実現する。

### 実装項目
- [ ] page ownership registry の強化
- [x] page lifecycle state machine
- [x] backing page count invariant
- [x] hash over full object semantics
- [ ] release on failure consistency
- [ ] stale page reuse detector
- [x] quarantine on corruption
- [x] zero-on-free and zero-on-reassign policy
- [x] list page integrity checks
- [ ] memory object metadata proof-friendly refactor
- [x] page leak detector
- [ ] metadata/contents visibility separation
- [ ] direct map visibility minimization
- [x] memory audit hooks

### 完了条件
- object hash が不足ページを成功扱いしない
- release 後の残留データ可視性がない
- ownership 逸脱が検知可能で fail-closed になる

---

## WS-K: 管理 ABI・互換性・アップグレード
### 目的
本番運用に耐える安定 ABI と update discipline を確立する。

### 実装項目
- [x] management ABI versioning
- [x] guest feature bitmap negotiation
- [x] deprecated field policy
- [x] command schema registry
- [x] upgrade compatibility tests
- [x] downgrade compatibility policy
- [x] state format versioning
- [x] operator tooling compatibility matrix
- [x] incompatible change detector in CI
- [x] migration compatibility checker
- [x] health schema compatibility
- [x] audit schema compatibility
- [x] failure mode compatibility guidance

### 完了条件
- minor upgrade で管理 plane が壊れない
- 旧 tooling が silent misbehavior しない
- 非互換変更が CI で検出される

---

## WS-L: サービス性・運用診断・サポート
### 目的
「なぜ止まったか」「なぜ隔離されたか」を operator が追える状態を作る。

### 実装項目
- [x] health state ABI
- [x] component inventory ABI
- [x] structured fault records
- [x] signed diagnostic bundle
- [x] operator console severity model
- [x] support dump with secret scrubbing
- [x] immutable incident timeline
- [x] compatibility matrix
- [x] runbook-linked reason codes
- [x] health aggregation model
- [x] incident export tool
- [x] degraded state guidance API
- [x] fault-to-remediation mapping
- [x] operator acknowledgment workflow

### 直近実装メモ
- `DIAG_GET_REASON_GUIDANCE` を追加し、deny / health / fault / partition 入力から severity / runbook code / recovery flags / action flags を返す
- `DIAG_GET_INVENTORY` を追加し、partition / artifact / device / storage の集約 inventory を返す
- `DIAG_GET_PARTITION_LIST` を拡張し、health / fault / quarantine / measurement epoch を含む structured partition diagnostics を返す
- `PARTITION_GET_FAULT_INFO` を拡張し、health / severity / runbook / deny reason / recovery guidance を含む structured fault record を返す
- `tools/diagnostics/export_diagnostic_bundle.py` を追加し、schema registry / inventory / partition list / fault records / guidance を manifest 付き tarball として export し、任意で detached signature を付与できるようにした
- diagnostic bundle export は allow-root 制約、symlink 拒否、secret-like include 拒否、measurement epoch / boot ID cross-check、signer fingerprint metadata を fail-close で強制し、`capture_complete` は operator 明示時のみ `true` にする
- `DIAG_NEGOTIATE_COMMAND_VERSION` を実装し、call ごとの negotiated ABI version / capability / host-vs-service class / compatibility flags を tooling が機械照会できるようにした
- `tools/diagnostics/scrub_support_dump.py` を追加し、UTF-8 support dump の bearer token / API key / password / private key block を redaction report 付きで scrub できるようにした
- `RETRY_LATER` のうち abuse-guard lockout だけを policy deny 監査へ流し、page busy / CAS 競合は transport retry として切り分けた
- `tools/audit/generate_command_audit_mapping.py` を追加し、device / storage / OCS / diagnostic command から emit し得る audit event と payload type の固定点を JSON / Markdown で生成できるようにした
- `fuzz/fuzz_command_page.c` を host caller allowlist まで通る初期状態へ揃え、`DIAG_GET_SCHEMA_REGISTRY` と `DIAG_NEGOTIATE_GUEST_FEATURES` の valid / unsupported profile / reserved field / tail-nonzero seed を `fuzz/corpus/command_page/` に追加して malformed-input smoke coverage を拡張した
- `tools/compatibility/check_standalone_reserved_fields.py` を追加し、compatibility matrix と `fbvbs_abi.h` から standalone 管理 ABI の reserved-zero enforcement report を生成し、command page / negotiation / scaling / storage create ABI の runtime evidence を CI で確認できるようにした
- `tools/partition/generate_standalone_command_contracts.py` を追加し、diagnostic / partition / OCS / storage command の idempotency class / repeat status / safe replay / transition preconditions を JSON / Markdown で固定できるようにした
- `tools/partition/validate_partition_transition_preconditions.py` を追加し、`partition list` と recovery approval artifact から `quiesce / resume / recover` の source-state と required-artifact 前提を fail-close に検証できるようにした
- acknowledgment artifact / ack ledger / recovery approval / correlation summary / evidence pack manifest に `session_correlation_id` を通し、administrative session 単位で incident 対応を追跡できるようにした
- `partition status` / `partition list` に `lockout_windows` と `policy_deny_count` を追加し、既存の hypercall abuse guard / rate limiting を operator tooling から観測できるようにした
- schema registry compatibility flags に `PARTITION_DIAGNOSTICS_STABLE` / `PARTITION_FAULT_INFO_STABLE` を追加し、expanded health/fault layouts の固定点を tooling へ露出した
- `tools/incident/reconstruct_incident_timeline.py` と `tools/incident/seal_incident_timeline.py` を追加し、`AUDIT seq=...` 行から boot/session ごとの JSON timeline を再構成し、後段で hash chain 付き sealed timeline を生成できるようにした
- `tools/compatibility/generate_operator_tooling_compatibility_matrix.py` を追加し、schema registry と command version negotiation の固定点から machine-readable / markdown の互換性 matrix を生成できるようにした
- compatibility matrix に `DIAG_SET_SCALING_LIMITS` と storage create/status ABI を追加し、standalone 管理面の row set を diagnostics だけでなく scaling / storage まで広げた
- `plan/standalone/operator-tooling-compatibility-baseline.json` を baseline 固定点として追加し、`tools/compatibility/check_standalone_compatibility_changes.py` で incompatible change を機械検出できるようにした
- deprecated field policy を `plan/standalone/deprecated-field-policy.md` と matrix JSON の `deprecated_field_policy` / `lifecycle.deprecated_fields` に落とし、minor upgrade での append-only discipline を固定した
- `make -C hypervisor compatibility-check` と CI の compatibility discipline job を追加し、baseline との互換性検査を常時ゲート化した
- `export_diagnostic_bundle.py` に scrub 済み support dump artifact と scrub report の正式格納を追加し、support dump 同伴時は report を必須にした
- `tools/operator/generate_operator_console_severity_summary.py` を追加し、inventory / partition list / fault record / guidance から operator 向け 1 画面 severity summary を JSON / Markdown / ISPF 風 panel text で生成できるようにし、presentation locale は `ja` / `en` をサポートした
- `tools/operator/render_operator_console_mainframe.py` を追加し、canonical severity summary JSON から primary option menu / incident list / partition detail / command reference を持つ mainframe-ispf-inspired panel set を `ja` / `en` で生成できるようにした
- `tools/operator/ocs_mainframe_tui.py` を追加し、canonical summary JSON を正本にした read-only full-screen TUI を実装して、`PF1/PF3/PF4/PF5/PF7/PF8/PF9/PF12` と command line で mainframe 風 panel 遷移ができるようにした
- `tools/diagnostics/correlate_standalone_incident_artifacts.py` を追加し、diagnostic bundle / sealed timeline / severity summary / acknowledgment ledger / compatibility matrix / panel manifest の相関 summary を JSON / Markdown で生成できるようにした
- `tools/diagnostics/generate_standalone_evidence_pack.py` を追加し、diagnostic bundle / timeline / severity / ack / compatibility / panel manifest を signed evidence pack として束ねられるようにした
- `tools/incident/issue_recovery_approval.py` と `tools/incident/verify_recovery_approval.py` を追加し、operator acknowledgment ledger と timeline root に束縛された recovery approval artifact を fail-closed に発行・検証できるようにした
- `tools/audit/detect_audit_gaps.py` を追加し、sealed / reconstructed timeline から gap 数と missing count を JSON / Markdown で検出し、必要に応じて non-zero exit できるようにした
- `tools/audit/check_retention_integrity.py` を追加し、diagnostic bundle / standalone evidence pack の manifest artifact digest を再計算して retention integrity を検証できるようにした
- `tools/diagnostics/validate_time_source_integrity.py` を追加し、timeline の timestamp monotonicity と future skew を JSON / Markdown で検証できるようにした
- `tools/diagnostics/plan_remote_export_retry.py` を追加し、standalone archive の fail-closed remote export retry schedule を machine-readable manifest として生成できるようにした
- `reconstruct_incident_timeline.py` / correlation / evidence pack に `audit_schema_version` を通し、audit schema versioning を timeline/evidence 境界まで固定した
- `generate_standalone_evidence_pack.py` に forensic preservation mode を追加し、capture-complete + signing 必須の append-only preservation manifest を同梱できるようにした
- `tools/audit/evaluate_audit_collector_mode.py` を追加し、collector loss / heartbeat loss / spool watermark / dropped bytes から `NORMAL` / `DEGRADED_BACKPRESSURE` / `HALT_NEW_MUTATIONS` を fail-closed に判定できるようにした
- `tools/operator/run_operator_console_tui.py` を追加し、canonical severity summary JSON を read-only full-screen TUI として表示し、PF key 相当キーと command line で primary / list / detail / reference を遷移できるようにした
- `tools/incident/record_operator_acknowledgment.py` を追加し、sealed incident timeline root に紐づく operator acknowledgment ledger を生成できるようにした
- `tools/operator/generate_standalone_operator_privilege_model.py` を追加し、command contract を正本に operator role / domain / action / origin / break-glass separate-audit 属性を JSON / Markdown で固定できるようにした
- `tools/security/issue_command_origin_attestation.py` と `tools/security/verify_command_origin_attestation.py` を追加し、session correlation / role / host callsite / transport / break-glass context に束縛された command origin attestation artifact を fail-close に発行・検証できるようにした
- `tools/audit/record_break_glass_audit.py` と `tools/audit/verify_break_glass_audit.py` を追加し、origin attestation と acknowledgment ledger に束縛された dedicated break-glass audit ledger を append-only hash chain で生成・検証できるようにした
- correlation / evidence pack / state manifest に `origin-attestation` と `break-glass-ledger` を取り込み、session drift と missing separate-audit を warning / artifact state として機械集約できるようにした
- `tools/service/generate_service_privilege_review.py` を追加し、`SERVICE_KIND_*` ごとの role 名と minimal capability baseline を JSON / Markdown で固定できるようにした
- `tools/service/detect_unused_service_capabilities.py` を追加し、service assignment JSON に対して unused / missing capability bits を fail-close に検出できるようにした
- `tools/verification/generate_framac_divergence_report.py` を追加し、`check_framac_stubs.py` の scan 結果から `hardware-dependent-only` / `acceptable-stub` / `forbidden-divergence` の divergence report を JSON / Markdown で生成できるようにした
- `make -C hypervisor semantic-drift-check` と CI artifact upload を追加し、forbidden divergence を semantic drift gate として機械検出できるようにした
- `hypervisor/compliance/wp_verification_boundary.md` を更新し、divergence report を verification boundary の補助証跡として参照するようにした
- `tools/partition/detect_stale_mappings.py` を追加し、destroyed / missing partition を指す cross-partition mapping と revoked-but-active mapping を stale として検出できるようにした
- `tools/partition/validate_teardown_postconditions.py` を追加し、memory object / shared object / mapping / attached vdisk の残存から teardown 後条件を fail-close に検証できるようにした
- `tools/partition/generate_fault_escalation_matrix.py` を追加し、health state / severity ごとの escalation level と containment policy を JSON / Markdown で固定できるようにした
- `tools/partition/score_partition_health.py` を追加し、health/severity/deny/lockout telemetry から partition health score と `HEALTHY` / `DEGRADED` / `AT_RISK` band を算出できるようにした
- `tools/partition/detect_quota_drift.py` を追加し、scaling limits と observed usage の drift を non-zero exit 付きで検出できるようにした
- `tools/storage/check_storage_invariants.py` を追加し、pool/vdisk の `capacity` / `allocated` / `attached` 整合性と granularity invariant を fail-close に検査できるようにした
- `tools/storage/detect_page_leaks.py` を追加し、memory object の backing page count mismatch、owner mismatch、unreferenced allocated page を leak として検出できるようにした
- `tools/service/generate_service_plane_policy.py` を追加し、service plane の `storage-control` / `audit-collection` / `attestation` / `secret-key` / `diagnostics` / `operator-console` profile、object access policy、service-to-service allowlist、break-glass bypass default deny、compromise containment を JSON / Markdown で固定できるようにした
- `tools/security/issue_service_identity_attestation.py` と `tools/security/verify_service_identity_attestation.py` を追加し、service profile / service kind / capability mask / object policy hash / peer policy hash / signer identity に束縛された service identity attestation artifact を fail-close に発行・検証できるようにした
- `tools/service/record_service_lifecycle_audit.py` と `tools/service/verify_service_lifecycle_audit.py` を追加し、service identity attestation に束縛された append-only service lifecycle ledger を生成・検証できるようにした
- `tools/service/generate_service_api_surface_minimization.py` を追加し、service profile ごとの allowed call surface を固定し、observed call set の逸脱を fail-close に検出できるようにした
- `tools/storage/generate_storage_authorization_model.py` を追加し、host / service / tenant の storage authorization、ownership scope、delegation policy を JSON / Markdown で固定できるようにした
- `tools/storage/generate_vdisk_lifecycle_model.py` を追加し、`PROVISIONED` / `ATTACHED` / `DETACH_PENDING` / `RELEASE_PENDING` / `QUARANTINED` / `DESTROYED` の lifecycle state と transition を機械可読化した
- `tools/storage/verify_storage_attach_detach_audit.py` を追加し、storage audit event と inventory snapshot から attach/detach の監査整合性を fail-close に検証できるようにした
- `tools/storage/issue_destructive_storage_confirmation.py` と `tools/storage/verify_destructive_storage_confirmation.py` を追加し、origin attestation と inventory precondition に束縛された destructive storage confirmation artifact を fail-close に発行・検証できるようにした
- `tools/storage/generate_storage_evidence_trail.py` を追加し、inventory / attach-detach audit report / destructive confirmation から pool/vdisk 単位の evidence trail を JSON / Markdown で生成できるようにした
- `src/storage/storage_virtualization.c` に actor-aware storage authorization を入れ、host に加えて `SERVICE_KIND_KCI + FBVBS_CAP_STORAGE_MANAGE` の trusted service admin と、owner tenant の `vdisk status / attach / detach` を runtime で許可するようにした
- `src/storage/storage_virtualization.c` と `include/fbvbs_hypervisor.h` に internal `vdisk lifecycle_state` を追加し、create / attach / detach / destroy の各遷移で `PROVISIONED` / `ATTACHED` / `DETACH_PENDING` / `RELEASE_PENDING` / `DESTROYED` を更新するようにした
- `src/partition.c` と `include/fbvbs_abi.h` に `fbvbs_audit_service_lifecycle_event` を追加し、trusted service の `measure / start / quiesce / resume / fault / recover / destroy` 遷移を runtime audit payload として記録するようにした
- `src/storage/storage_virtualization.c` と `tests/c/storage/test_scaling_storage.c` に vdisk corruption report -> `QUARANTINED` 遷移を追加し、metadata invariant 異常検出時の fail-closed quarantine（attach/detach/qos 変異禁止）と destroy 経路の整合性回復を実装した
- `src/storage/storage_virtualization.c` に pool granularity と vdisk size 整合チェック、create 系 invalid parameter の監査 emit を追加し、storage governance の audit 可観測性を強化した
- `src/partition.c` に service lifecycle operation 別の監査 severity マッピングを追加し、`fault`/`destroy` を warning、`quiesce`/`recover` を notice として runtime signal 品質を改善した
- `src/memory.c` と `include/fbvbs_hypervisor.h` に memory object lifecycle/quarantine 状態機械（`ALLOCATED` / `MAPPED` / `SHARED` / `QUARANTINED` / `RELEASED`）を追加し、map/shared カウンタ遷移に追随して fail-closed に更新するようにした
- `src/memory.c` に invariant validator と quarantine marking を追加し、backing metadata 異常時に object を `QUARANTINED` へ遷移させるとともに、read/write/hash/get_page_phys を遮断するようにした
- `src/memory.c` に owned backing page の zero-on-free を実装し、release 経路でページ内容を消去してから free するようにした
- `src/partition.c` に memory corruption audit hook（`FBVBS_EVENT_MEMORY_CORRUPTION`）を追加し、map/unmap/set_permission/share/unshare/vm_map の各経路で invariant 逸脱時に証跡を emit するようにした
- `src/partition.c` と `include/fbvbs_hypervisor.h` に device runtime quarantine state を追加し、passthrough 不可の fail-closed 返却時に device を quarantine し、再試行時は `INVALID_STATE` で遮断するようにした
- `src/partition.c` に stale device release 防止（assigned list に存在しない device_id の release を `NOT_FOUND` で拒否）を追加し、revoke 前提の誤操作を fail-close にした
- `tests/c/storage/test_scaling_storage.c` に memory object lifecycle 遷移テストと corruption->quarantine->audit emit テストを追加し、WS-J runtime の主要遷移を回帰固定した
- `tests/c/security/test_policy_security.c` に device quarantine 再試行遮断テストと stale device release 拒否テストを追加し、WS-G fail-closed の境界条件を回帰固定した

### 完了条件
- 隔離理由と停止理由を operator が追える
- support dump が秘密を含まず採取できる
- incident 対応手順がコード化されている

---

## WS-M: 大規模性・多テナント性・運用密度
### 目的
収容数とイベント量が増大しても control plane と audit plane を維持する。

### 実装項目
- [ ] partition table scale redesign
- [ ] object index redesign
- [ ] audit collector backpressure
- [ ] inventory indexing
- [ ] config fan-out control
- [ ] lock sharding
- [ ] RCU-like read optimization where appropriate
- [ ] high-cardinality telemetry design
- [ ] per-tenant quotas
- [ ] rate control for noisy tenants
- [ ] large-fleet diagnostics sampling
- [ ] management plane queue isolation
- [ ] operator bulk action safety model

### 完了条件
- 収容数増加時も管理・監査が詰まらない
- noisy tenant が共用面を圧迫できない
- 大規模運用時に O(n^2) 的挙動が除去される

---

## WS-N: 検証適合設計と意味乖離削減
### 目的
実装優先を維持しながら、後追い検証可能性を破壊しない。

### 実装項目
- [x] `__FRAMAC__` 分岐の棚卸し
- [x] divergence 分類表
  - hardware-dependent only
  - acceptable stub
  - forbidden divergence
- [x] production/model semantic diff review
- [ ] policy / audit / state transition の共有化
- [ ] meaning-preserving wrapper 導入
- [ ] contract skeleton 先行整備
- [ ] invariant predicate library
- [ ] assigns discipline 改善
- [ ] proof timeout budget 管理
- [ ] shard ownership and triage flow
- [x] semantic drift CI check
- [x] verification boundary 文書更新

### 完了条件
- 検証分岐がハード依存差し替え中心になる
- policy / state / audit の意味差が消える
- proof 追随時の全面書き換えが不要になる

---

## 11. マルチエージェント運用

## 11.1 役割
### Explore
- 目的: 変更最小化、既存設計との整合、回帰リスク低減
- 成果物: 実装差分案、影響分析、危険分岐一覧

### secure-coding-verifier
- 目的: 実装差分のセキュリティレビュー
- 実行タイミング:
  - 実装差分直後
  - テスト修正直後
  - 最終ゲート前

### Spec-Consistency Reviewer
- 目的: requirement / design / ABI / audit schema の整合確認

### Proof-Readiness Reviewer
- 目的: invariant と後追い proof 適合性の事前確認

### Operations Reviewer
- 目的: health / telemetry / audit / recovery / operator runbook 観点レビュー

## 11.2 実行順序
1. Explore
2. 実装
3. secure-coding-verifier
4. Spec-Consistency Reviewer
5. analyze / test / fuzz smoke
6. Operations Reviewer
7. 重ゲート
8. Proof-Readiness Reviewer
9. proof-shards 後追い
10. evidence / compliance 更新

---

## 12. フェーズ計画

## Phase 0: 基盤健全化
### 目的
危険な意味乖離と設計不整合を先に減らす。

### 実施項目
- `__FRAMAC__` 分岐棚卸し
- forbidden divergence トップ 20 の除去
- storage / service / host 権限統合
- command ABI / error ABI / deny reason 固定
- EPT/IOMMU invalidation correctness 再点検
- audit schema 固定
- health state 初期版固定

### Exit 条件
- 意味乖離一覧完成
- 危険乖離トップ 20 の除去
- ABI versioning の土台完成

---

## Phase 1: 強隔離ハイパーバイザー化
### 目的
研究コードから製品核へ移行する。

### 実施項目
- IOMMU 実機閉鎖
- deprivilege 完成
- partition quarantine / revoke / recovery
- storage / VCD / OCS / policy 統合
- immutable audit chain
- device revoke correctness
- teardown postcondition 監査

### Exit 条件
- CPU / memory / DMA / ABI の全経路で境界定義完了
- deny / fault / lockout / revoke が監査される

---

## Phase 2: 運用・監査・容量制御
### 目的
本番運用できる形へ進化させる。

### 実施項目
- QoS / shares / caps / reservations
- health ABI / inventory ABI
- evidence pack
- soak
- fault injection
- upgrade compatibility
- operator remediation guidance

### Exit 条件
- 長時間運転試験通過
- evidence pack から release 証跡を再構成できる
- 容量制御が一貫した policy で扱われる

---

## Phase 3: 機密計算・移行・大規模化
### 目的
差別化領域へ進む。

### 実施項目
- confidential partition
- attestation
- secret injection
- migration preflight
- dirty tracking
- NUMA / scale improvements
- service privilege segmentation 強化

### Exit 条件
- confidential guest の threat model が固定
- migration 可否条件が ABI 化
- 大規模収容でも管理面が破綻しない

---

## Phase 4: 高保証収束
### 目的
実装を土台に形式検証を回収する。

### 実施項目
- proof 範囲拡大
- model branch 縮小
- ACSL predicate library
- invariant 文書化
- verification boundary 更新
- residual risk 再評価

### Exit 条件
- 重要状態機械に invariant が張られる
- proof timeout 増加が管理される
- 既存対象 status=0 を維持する

---

## Phase 5: 長期互換・継続運用成熟
### 目的
プロダクトとしての継続運用基盤を完成させる。

### 実施項目
- 長期 ABI discipline
- multi-release compatibility
- evidence automation 完全化
- operator tooling 成熟
- service contracts 固定
- long soak campaigns
- incident drill
- compliance mapping 強化

### Exit 条件
- 連続リリースで互換性規律が維持される
- incident drill と recovery drill が定着する
- 運用・監査・更新の三位一体が成立する

---

## 13. CI / ゲート設計

## 13.1 常時ゲート
1. secure-coding-verifier
2. `make -C hypervisor analyze`
3. `make -C hypervisor test`
4. fuzz smoke
5. command ABI compatibility check
6. audit schema compatibility check
7. reserved field / deny reason regression check
8. basic health schema regression

## 13.2 拡張重ゲート
1. coverage
2. bare-metal smoke
3. fault injection suite
4. upgrade/downgrade compatibility suite
5. policy regression suite
6. selected proof-shards
7. device revoke / teardown suite
8. audit gap simulation
9. collector loss mode simulation

## 13.3 完全ゲート
1. full fuzz campaign
2. long soak
3. reproducible build
4. SBOM / provenance
5. evidence pack generation
6. full proof-shards
7. production/model semantic diff review
8. incident bundle reconstruction test
9. performance regression and contention review
10. compatibility matrix regeneration

---

## 14. Frama-C / 後追い検証計画

## FT-1: 意味乖離削減レビュー
### 対象
- `src/command.c`
- `src/security.c`
- `src/kernel.c`
- `src/memory.c`
- `src/core/scaling.c`
- `src/storage/storage_virtualization.c`
- `src/io/vcd_virtualization.c`
- `src/platform/iommu_*.c`

### 完了条件
- `__FRAMAC__` 分岐がハード依存差し替え中心になる
- 権限判断、状態遷移、監査可観測性の意味差が消える

## FT-2: 契約強化
### 対象
- quarantine state machine
- confidential page state machine
- deny threshold control
- migration preflight
- device revoke / teardown
- storage ownership / capacity invariants
- memory object ownership / backing invariants

### 完了条件
- requires / ensures / assigns が更新される
- pedantic-assigns を悪化させない
- 強い invariant を述語化する

## FT-3: 証明ゲート
### 実行
- `make -C hypervisor proof-shards`
- timeout trend tracking
- shard ownership triage

### 完了条件
- 既存対象 status=0 維持
- timeout 増加に budget を設定
- 重要関数で Stronger 依存を減らす

## FT-4: 文書整合
### 対象文書
- `compliance/wp_verification_boundary.md`
- `compliance/security_target_outline.md`
- `compliance/residual_risk_register.md`
- `compliance/operational_assurance_case.md`

### 完了条件
- 実装 / 証明 / 運用 / 監査の四者整合

---

## 15. ドキュメント体系

## 15.1 必須文書
- アーキテクチャ総覧
- 管理 ABI 仕様
- 監査 ABI 仕様
- deny reason code 一覧
- partition lifecycle 仕様
- memory ownership 仕様
- storage lifecycle 仕様
- device assignment 仕様
- confidential partition 仕様
- health state 仕様
- incident / recovery runbook
- compatibility policy
- verification boundary
- residual risk register
- operational assurance case

## 15.2 各 WS ごとの成果物
- design note
- threat model
- ABI delta
- audit schema delta
- tests added
- fuzz targets added
- operational impact note
- proof impact note
- residual risk update

---

## 16. リスク登録簿

## 16.1 技術リスク
- 本番意味論と検証意味論の乖離
- trusted service の権限膨張
- IOMMU / revoke / teardown race
- stale mapping / stale DMA visibility
- audit gap under backpressure
- compatibility breakage
- confidential guest での可視性漏れ
- scale 増大時の control plane contention

## 16.2 運用リスク
- collector 不在時の方針不明確
- operator tooling 未整備
- runbook 未成熟
- long retention 失敗
- time source integrity 喪失

## 16.3 対応原則
- 重大リスクは設計時に state machine へ落とす
- 監査・回復・operator 可視性をセットで設計する
- 高リスク領域は evidence-driven に進める
- residual risk は文書化し、沈黙させない

## 17. 実装完了判定

以下を満たしたとき、その機能群は「実装完了」とみなす。

1. 仕様が固定されている
2. secure-coding-verifier を通過している
3. analyze / test / fuzz smoke / relevant integration test を通過している
4. audit / deny / state transition が観測可能である
5. operator への挙動説明が可能である
6. ABI change が versioning されている
7. proof 追随のための divergence メモが更新されている
8. residual risk が記録されている

---

## 18. 最終宣言

FBVBS は、本計画に従い、**実装先行であっても設計規律を崩さず、強い隔離性、高可用性、継続運転性、高監査性、大規模収容性を備えたミッションクリティカル級・高保証・メインフレーム-like な仮想化基盤**へ進化させる。

そのために、以下を最重要原則として維持する。

1. **境界を後付けにしない**
2. **監査を省略しない**
3. **trusted service を万能化しない**
4. **本番と検証を別物にしない**
5. **ABI を無秩序に変えない**
6. **可用性を fail-open の言い訳にしない**
7. **証跡を残さない実装を完了扱いにしない**
8. **実装が進んでも、後追い高保証化を不可能にしない**
