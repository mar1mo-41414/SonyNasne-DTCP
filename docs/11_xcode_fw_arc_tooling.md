# 11 ARC 解析ツール環境の調査と検証 — Ghidra ARCompact SLEIGH の導入

## 要約

[docs/08](08_xcode_fw_drm_module_phase2.md) §6 の残件 4「逆アセンブラの強化」への対応として、ARC(ARCompact 世代)の解析ツールの定石と Ghidra の ARC 対応の実在を調査し、最も有望な候補を既知の真値で検証した回の記録。

到達点:

- **Ghidra 公式に ARC のプロセッサ定義は無い**ことを実測で確定した。手元の 12.1.3 リリースにも、公式リポジトリの開発版先端(2026-11-10 時点)にも含まれない。「手元の環境に無いだけ」ではなく、公式には存在しない。
- コミュニティ製 SLEIGH は実在する。Nicolas Iooss(Ledger Donjon、SSTIC 2021)による **ARCompact 定義**で、現在の配布形態は「上流 Ghidra 12.1.2 + 単一コミット」の fork であり、2026-07-01 にリベースされている(追随が続いている)。ライセンスは Apache-2.0。
- 手元の Ghidra 12.1.3 にこのモジュールを導入し、[docs/05](05_xcode_firmware_images.md)・[docs/08](08_xcode_fw_drm_module_phase2.md) の真値で検証した。ベクタ表 6/6 一致、サンク表・レジストリ関数の首尾一貫した読み、デコンパイラの動作を確認し、capstone では意味を取れなかったベクタ [3] の先(0x100030)が `0xDEADC0DE` を記録する例外ハンドラとして読めた。**採用可能**と判定する。
- GNU objdump(Ubuntu binutils-arc-linux-gnu 2.42)は、GNU as で作った ELF を経由すれば主 FW も完全にデコードでき、その読みは Ghidra と全真値で一致した。第2段で binutils を「使用不可」とした判断([docs/08](08_xcode_fw_drm_module_phase2.md) §2.2)は、デコーダ自体の故障ではなく入力形式(raw バイナリ / objcopy 製 ELF)が原因と切り分け、**本書 §4 で訂正する**。

## 1. Ghidra 公式の ARC 対応 — 実在確認

- 手元の Ghidra 12.1.3 の `Ghidra/Processors/` 一覧(6502、68000、ARM、MIPS、RISCV、x86 等の 39 種)に ARC / ARCompact は無い([docs/08](08_xcode_fw_drm_module_phase2.md) §2.1 の実測と同じ)。
- 公式リポジトリ `NationalSecurityAgency/ghidra` の開発版先端(2026-11-10 のコミット `42db038f`)について、`Ghidra/Processors/` の一覧を git のツリー取得で確認した。やはり ARC は無い。リリース・開発版の双方で「公式には存在しない」が確定した。
- 公式 FAQ(Ghidra Wiki)にある対応プロセッサの列挙にも ARC は無く、同 FAQ の立場は「新しいプロセッサは SLEIGH 定義の追加で拡張でき、プルリクエストを歓迎する」というものである。
- 上流への取り込み経路について: 第三者のプロジェクト文書(evenRealities-openCFW の `MISSING-TOOLCHAIN.md`)は「プルリクエスト 3006 は ARCompact のもの」と言及している。開発版先端に ARC が無い以上、少なくとも現時点では未マージであることは確定する。プルリクエスト自体の open / closed の別は未確認であり、断定しない。
- 「なぜ公式に入っていないのか」について、公式の理由表明は調査範囲では見つからなかった。観測事実は次の通りである: 2019 年の公開以来、公式には一貫して含まれず、公開されている実装はコミュニティ(Iooss)が fork として維持しているものだけである。理由の推測は書かない。

## 2. コミュニティ製 ARC SLEIGH の列挙

| 実装 | 対象世代 | 配布形態 | 保守状態 | ライセンス |
|---|---|---|---|---|
| Nicolas Iooss の ARCompact 定義 | ARCompact(ARC600 / ARC700) | Ghidra の fork(ブランチ `arcompact`) | 2026-07-01 に Ghidra 12.1.2 へリベース。追随中 | Apache-2.0(Ghidra 本体と同じ) |
| Roman Korkikian の ARCv2 定義 | ARCv2(EM / HS) | GitHub リポジトリ `korkikian/ARCv2` | 2022 年発表時点で WIP | リポジトリ側の表示による |

### 2.1 Iooss の ARCompact 定義(本命)

- 素性: Ledger Donjon の Nicolas Iooss が SSTIC 2021 で発表した "Analyzing ARCompact firmware with Ghidra" の成果物。発表論文・スライドが sstic.org で公開されている。実使用例として、同著者らによる Intel Wi-Fi ファームウェア解析(Black Hat USA 2022)や、第三者による Calix ONT の ARCompact ファームウェア解析(2025 年の公開事例)での採用がある。
- fork の構成: 上流 Ghidra 12.1.2 のツリーに、コミット `d3fbf109ada6d051750e973779170c1758622530`("Add support for ARCompact instruction set"、著者日付は 2021-05-05、リベースで維持)だけを載せた形。差分は `Ghidra/Processors/ARC/` の追加のみである。
- モジュールの中身: `data/languages/` に `ARCompact.ldefs` / `.cspec` / `.pspec` / `.slaspec`(2,515 行)/ `.dwarf` / `.opinion`。ほかにエミュレーション用の Java クラス 1 個と、ARC700 のエミュレータテスト 2 件。言語 ID は `ARCompact:LE:32:default`。
- 関連リポジトリ: 作者の `ghidra-arcompact-test`(ARCompact 対応のテスト用)。
- 注意: これは ARCompact 専用であり、ARCv2 とは命令セットが大きく異なるため流用できない(BlackAlps 2022 の Korkikian の発表でも両者の差異が強調されている)。本件の対象(XCode の ARC は ARCompact 世代、[docs/05](05_xcode_firmware_images.md) §3)には Iooss の定義が合う。

### 2.2 ARCv2 定義(参考)

- Korkikian の ARCv2 向け SLEIGH(5,500 行超、約 380 命令の記述とされる)。世代が違うため本件では使えない。列挙に留める。

## 3. ARC 解析の定石

出典付きで整理する。

- **参照逆アセンブラは公式 GNU ツールチェーンの objdump**。Synopsys(現・MIPS 傘下)の foss ツールチェーン(`foss-for-synopsys-dwc-arc-processors/toolchain`、現在は `foss-for-mips-arc-processors` へ移行)がプリビルドを配布しており、Linux カーネルの ARC 公式ドキュメントも同ツールチェーンを標準として案内する。プリビルドの tarball は `arc_gnu_<版>_prebuilt_elf32_le_linux_install.tar.gz` の形式で、objdump / gdb を含む。
- **商用ツール**: IDA Pro は ARCTangent-A4 / ARCompact / ARCv2 の逆アセンブラを持つ(SSTIC 2021 のツール比較による)。デコンパイラは ARCv2 向けが別途提供されている(2022 年の BlackAlps 発表資料)。ベンダ純正の開発環境は MetaWare ツールチェーンである。
- **無料の対話解析**: Ghidra + Iooss の SLEIGH 定義(ARCompact。本書 §5 で検証)、Binary Ninja + コミュニティプラグイン `binja-arcompact`(nullableVoidPtr 作。Calix ONT の解析事例で使用)。
- **rizin / radare2 系**: 2021 年時点で「Argonaut RISC Core」対応の記載があるが、手元の radare2 5.5.0 には ARC プラグインが無かった([docs/08](08_xcode_fw_drm_module_phase2.md) §2.1 の実測)。デコンパイラは無い。
- **capstone**: ARC 対応は ARCv2 寄りの実装で、ARCompact の読みに限界がある([docs/08](08_xcode_fw_drm_module_phase2.md) §2.4 の実測。limm を含む命令等のデコードが疑わしく、線形スイープは同期ずれする)。

まとめると、ARC 解析の定石は「参照は公式 GNU objdump、本格的な対話解析は IDA か Ghidra + SLEIGH」という二層構造であり、本プロジェクトは無料の範囲で後者の Ghidra 路線を採る。

## 4. binutils-arc-linux-gnu が使えなかった理由の切り分け(docs/08 §2.2 の訂正)

第2段は Ubuntu の binutils-arc-linux-gnu 2.42 を「このビルドの ARC デコーダが機能していない」として使用不可と判断した。本段で切り分けた結果、その判断は誤りであり、原因は入力形式側にあった。実測は次の通り。

1. **第2段の実測の追認**: 主 FW の raw binary 入力、および objcopy で包んだ ELF(e_flags = 0x300、readelf 表示は "Unknown ARCompact")は、CPU 種別を `-m arc700` 等で明示しても全ワードが `.word` になる(ELF では見出しと `...` だけが出る)。本段でも再現した。
2. **デコーダ自体は正常**: 同一パッケージの GNU as で 5 命令の ARC700 オブジェクト(e_flags = 0x403、readelf 表示は "ARC700, v4 ABI")を作ると、同じ objdump が全命令を正しくデコードした(`j 0x113c20`、`mov r0,68`、`st.aw blink,[sp,-4]`、`ld.ab blink,[sp,4]`、`j [blink]`)。また、展開したパッケージの libopcodes には ARC デコーダのシンボル群が含まれていることをバイナリ上で確認した。
3. **as 製 ELF 経由なら主 FW もデコードされる**: as の `.incbin` で主 FW 全体(6,216,324 バイト、SHA-256 `3e99b4132b4e72dddbd7a94e6063b18d2278fbc2d450b8ad1e9441698fe2b4d5`)を包んだオブジェクトでは、ベクタ表・サンク表・0x100030 がデコードされ、その読みは Ghidra の読みと一致した(照合は §5.2)。
4. **objcopy 製 ELF は e_flags を書き換えても読めない**: objcopy 製 ELF の e_flags を 0x403("ARC700")に書き換えても、objdump はセクションを一切デコードしなかった(出力は見出しと `...` のみ)。この個別現象の機構は未特定である。
5. 運用上の注意: 抽出した .deb のバイナリは、付属の libbfd / libopcodes を読み込ませないと起動しない(ライブラリパスの設定が要る)。これも第2段の試行条件には含まれていた可能性があるが、本段の追認はライブラリパスを設定した上で行った。

結論: GNU の ARC objdump はデコード表の選択を ELF ヘッダ(e_flags の CPU 機種)に依存しており、raw 入力や objcopy の汎用ラップではデコードが始まらない(少なくとも本ビルド・本手順の実測範囲で。`-m` 指定では切り替わらなかった)。**「binutils は使用不可」は「raw / objcopy ELF では使えないが、as 製 ELF 経由では参照逆アセンブラとして使える」に訂正する。** [docs/08](08_xcode_fw_drm_module_phase2.md) §2.2 にも訂正注記を付けた。

## 5. Ghidra モジュールの導入と検証

### 5.1 導入手順(再現用)

1. fork `niooss-ledger/ghidra`(ブランチ `arcompact`、先端コミット `d3fbf109ada6d051750e973779170c1758622530`)を取得する。
2. `Ghidra/Processors/ARC/` ディレクトリを、手元の Ghidra 12.1.3 インストールの `Ghidra/Processors/` へコピーする。
3. `support/sleigh -a Ghidra/Processors/ARC/data/languages` で `ARCompact.slaspec` をコンパイルする。`ARCompact.sla`(44,622 バイト)が生成された。警告は NOP コンストラクタ 7 件のみ。
4. 解析時は analyzeHeadless 等で `-processor ARCompact:LE:32:default` を指定する。主 FW 平文イメージは `-loader BinaryLoader -loader-baseAddr 0x0` でインポートした。

なお、エミュレーション用の Java クラス(`ARCompactPcodeUseropLibraryFactory`)は lib jar の無い状態でも逆アセンブル / デコンパイルに支障が無かった(実測)。導入に必要なのは `data/languages` 一式とコンパイル済み `.sla` である。

### 5.2 検証(真値との照合)

真値は [docs/05](05_xcode_firmware_images.md)・[docs/08](08_xcode_fw_drm_module_phase2.md) の確定事項。検証は analyzeHeadless + 自作スクリプトで対象範囲を強制デコードして行った。

| 対象 | 真値 | Ghidra(Iooss 定義) | GNU objdump(as 製 ELF) |
|---|---|---|---|
| ベクタ表 0x00〜0x2F | `j` 先: [0]=0x113C20、[1]=0x113C00、[2]=0x113D5C、[3]=0x100030、[4]=0x1002B8、[5]=0x2D0144(docs/05 の訂正後の値) | **6/6 一致**。半語スワップされた limm の解決も正しい | **6/6 一致** |
| サンク表 0x8000 | blink 退避 → `jl` で 0x1922C0 付近を呼ぶ → blink 復帰 → return、0x50 バイト刻み | 一致。ラッパ 1 は `st.a blink,[sp,-0x4]`、引数アドレスを渡す `bl` 列、`jl 0x1922e0`、`ld.ab blink,[sp,0x4]`、`j blink` と読めた。ラッパ 2(0x8050)も同型 | 先頭ラッパの命令列・即値が一致 |
| 関数途中 0x113C20(ベクタ [0] の先) | capstone で検証済みの範囲 | limm 即値(`and r2,r2,0x4440`)を含め首尾一貫し、関数エピローグ(`mov sp,fp` / `pop_s blink` 等)まで読めた | 未照合 |
| レジストリ内関数 0x156830 | ベース + オフセットの構造体アクセスが支配的(docs/08 §3.5) | 一致。分岐先も関数内に解決 | 未照合 |
| ベクタ [3] の先 0x100030 | capstone では「データ様の並び」で意味を取れなかった(docs/08 §2.4・§3.1) | **`0xDEADC0DE`・PC・SP を固定アドレスへ記録し、処理を呼んで無限ループに入る例外ハンドラとして読めた** | 同一の読みで一致(`st.di.as 0xdeadc0de,...` 等。オフセット表記はスケーリングの差のみ) |
| ベクタ [5] の先 0x2D0144 | コードとしてデコードできず意味未解決(docs/08 §3.1) | 拡張レジスタ様のオペランドが混ざる読みになり、意味未解決のまま(状態は変わらない) | 未照合 |
| デコンパイラ | — | 動作する。0x1922C0 の分岐先関数について C コードが生成された | — |

混合 16/32 ビット命令の範囲(サンク表の 0x100 バイト)でもデコードの同期が崩れなかった。これは capstone の失敗様式(数命令で崩壊)と対照的で、定義の正しさの傍証になる。

### 5.3 限界

- 拡張命令の一部(EXT05 / EXT07 等)は未実装で、名前のまま出力される。ただし前後のデコード同期は崩れない。
- 定義は ARC700 前提である。ARC600 系や拡張構成の細部は未検証。
- ベクタ [5] の先のような意味の取れない領域は残る(デコーダの問題とは限らない。[docs/08](08_xcode_fw_drm_module_phase2.md) §3.1 の未解決事項のまま)。

### 5.4 判定

**採用可能**。真値の全項目に一致し、capstone の天井を破る読み(0x100030 の例外ハンドラ)が得られ、デコンパイラまで動作する。第4段以降の FW 実読は Ghidra を主環境とし、GNU objdump(as 製 ELF 経由)を照合用に併用できる。[docs/08](08_xcode_fw_drm_module_phase2.md) §6 の残件 4「逆アセンブラの強化」は本書で解決した。

## 6. 成果物と所在

- 導入済みモジュール: 手元の Ghidra 12.1.3 インストール内の `Ghidra/Processors/ARC/`(ディレクトリを削除すれば導入前に戻る)。
- fork の取得物、検証用 Ghidra プロジェクト、検証スクリプト、検証ログは、開発側の作業領域(FW 解析の作業置き場の `arc-tools` サブディレクトリ)に保管してある。
- 本書が本調査の記録である。

## 出典

- SSTIC 2021 論文・スライド: Nicolas Iooss, "Analyzing ARCompact firmware with Ghidra" — https://www.sstic.org/media/SSTIC2021/SSTIC-actes/analyzing_arcompact_firmware_with_ghidra/SSTIC2021-Slides-analyzing_arcompact_firmware_with_ghidra-iooss.pdf
- Iooss の fork: https://github.com/niooss-ledger/ghidra (ブランチ `arcompact`)
- ARCv2 SLEIGH: https://github.com/korkikian/ARCv2 、発表資料 https://old-ba.blackalps.ch/ba-22/files/talks/BlackAlps22-Korkikian.pdf
- Binary Ninja 用プラグイン: https://github.com/nullableVoidPtr/binja-arcompact 、採用事例 https://revers3everything.com/calix-case-five-0-days-five-cves/
- 公式 GNU ツールチェーン: https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases 、Linux カーネルの ARC ドキュメント https://docs.kernel.org/5.17/arc/arc.html
- Ghidra 公式 FAQ: https://github.com/NationalSecurityAgency/ghidra/wiki/Frequently-asked-questions
- プルリクエスト 3006 への言及: https://github.com/kalanihelekunihi/evenrealities-opencfw/blob/HEAD/MISSING-TOOLCHAIN.md
