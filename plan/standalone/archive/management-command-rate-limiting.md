# Management Command Rate Limiting

## 目的

standalone 管理 command の abuse guard を runtime で強制しつつ、operator tooling から lockout 状態を観測できるようにする。

## 実装

1. hypervisor 本体は既存の hypercall abuse guard / lockout windows を維持する
2. `partition status` は `lockout_windows` と `policy_deny_count` を返す
3. `partition list` も同じ値を返し、list view から lockout を追える
4. `generate_operator_console_severity_summary.py` は partition list からこの値を保持できる

## 完了条件

1. rate limit 自体は runtime で fail-close に発火する
2. operator tooling は lockout 中かどうかを JSON/ABI から読める
3. status/list の値が回帰テストで一致する
