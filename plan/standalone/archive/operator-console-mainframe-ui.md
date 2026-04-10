# Standalone OCS Mainframe UI Profile

## 目的

standalone OCS の operator-facing UI を、IBM mainframe の ISPF に着想を得た
panel-style workflow として固定する。

この profile は presentation 契約であり、management ABI や VCD ownership を変更しない。

## 採用した要素

1. action bar
2. `OPTION ===>` / `COMMAND ===>` 行
3. `SCROLL ===> PAGE` 表示
4. 番号選択式 primary option menu
5. `S` / `RB` / `QI` / `RS` / `RC` の line command model
6. PF key footer
7. panel ID

## repo 内での落とし込み

`hypervisor/tools/operator/render_operator_console_mainframe.py` は
canonical diagnostics JSON を入力に、次の panel set を生成する。

1. `ocs-primary-option-menu.txt`
2. `ocs-incident-list-panel.txt`
3. `ocs-partition-detail-panel.txt`
4. `ocs-command-reference-panel.txt`
5. `ocs-panel-manifest.json`

`hypervisor/tools/operator/ocs_mainframe_tui.py` は同じ canonical summary JSON を入力に、
full-screen の read-only TUI を起動する。

`hypervisor/tools/operator/run_operator_console_tui.py` は同じ canonical summary JSON を入力に、
PF key 相当のキー操作で panel 遷移できる full-screen TUI を提供する。

## 設計原則

1. canonical source of truth は machine-readable JSON である
2. panel text は deterministic render であり、状態の正本ではない
3. `ja` と `en` の両 locale をサポートする
4. locale により command token を変えない
5. shell / filesystem / arbitrary program execution は UI に追加しない

## full-screen TUI contract

1. TUI は read-only preview で開始する
2. `ACK / EXPORT / QI / RS / RC` は operator intent を message line に表示するが、
   現時点では hypervisor state を変更しない
3. PF key と同時に `q`, `?`, `j`, `k`, `Enter` などの代替キーを持つ
4. command line は allowlist command のみ解釈する
5. unknown command は fail-closed に拒否し、message line に表示する
6. interactive TUI でも状態変更系コマンドは read-only / fail-closed に扱う

## panel mapping

### OCS0001 primary option menu

1. system summary
2. active incidents
3. partition list
4. quarantine and recovery
5. runbook guidance
6. evidence export
7. operator acknowledgment
8. help and cross reference

### OCS0100 incident list

1. severity 順の partition list
2. line command による select / runbook / control action
3. command line による filter / locate / ack / export

### OCS0200 partition detail

1. partition ID
2. severity
3. health
4. fault code
5. quarantine reason
6. severity source
7. recommended action

### OCS0900 command reference

1. primary commands
2. line commands
3. PF key contract

## key flow

1. `PF1` / `HELP`: reference panel
2. `PF3` / `END`: primary menu へ戻る。primary menu 上では TUI を終了する
3. `PF4` / `RETURN`: 直前 panel へ戻る
4. `PF5` / `REFRESH`: 現在の summary を再描画する
5. `PF7` / `PF8`: list panel の選択を上下に動かす
6. `PF9` / `SWAP`: 現在 panel と直前 panel を入れ替える
7. `Enter`: list panel では detail を開き、command line 入力中は command を実行する

## interactive TUI contract

1. `F1` は help/reference
2. `F3` は end/exit
3. `F4` は return
4. `F5` は refresh message のみを返す
5. `F7/F8` は list scroll
6. `F9` は split/swap unavailable を返す
7. `F12` は command line clear
8. `j/k` と矢印キーで selection を移動する
9. `Enter` と `S` で detail を開く
10. `ACK` / `EXPORT` / `QI` / `RS` / `RC` は read-only fail-closed にする

## 検証

`hypervisor/tests/python/operator/test_render_operator_console_mainframe_tool.py` は次を固定する。

1. English panel set が生成される
2. Japanese panel set が生成される
3. mainframe-ispf-inspired manifest が出力される
4. option / command / scroll / PF key contract が panel に含まれる

`hypervisor/tests/python/operator/test_operator_console_tui.py` は次を固定する。

1. 数字選択で primary menu から panel 遷移できる
2. filter / locate が list selection に反映される
3. read-only command が fail-closed で拒否される
4. `j/k/Enter` による selection と detail 遷移が動く
5. terminal control sequence が描画前に sanitize される
