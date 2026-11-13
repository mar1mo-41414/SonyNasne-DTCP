# 12. XCode ファームウェア DRM モジュール解析 第4段(Ghidra 実読: ベクタ表・コマンド番号の 2 層性・procIdx 配送・ディスパッチ探索)

第4段。環境は [docs/11](11_xcode_fw_arc_tooling.md) で整備した Ghidra 12.1.3 + ARCompact SLEIGH(Iooss 作)を主環境とし、主 FW 平文イメージ(6,216,324 バイト、ロードベース 0)を自動解析したうえで、ベクタ表の実読、ホスト側一次資料との突き合わせによるコマンド配送構造の確定、FW 側ディスパッチの探索を行った。実機には触れていない。

到達点の要約:

- **ベクタ[1](0x113C00)は命令の途中だった**。0x113BFE から始まる 4 バイト命令 `ld.di r1,[r20,0x24]` の後半半ワードが 0x113C00 であり、実行入口にはなり得ない(§2.1)。ベクタ[1] が指す先にハンドラは無い。
- **コマンド番号には 2 つの層があることを一次資料で確定した**(§3)。docs/02・[docs/09](09_xcode_fw_drm_phase3.md) §4.1 が「FW が受ける FunctionNumber」としてきた値(0x108 / 0x113 / 0x114 / 0x116 等)はドライバ API 層の番号であり、実際に FW へ渡る伝送層の FunctionNumber は別の小さい値(SCRAMBLER=37、SET_KEYSTORE_KEY=42、RESERVE_KEYSTORE_SLOT=44、READ_FROM_OTP=45)である。[docs/09](09_xcode_fw_drm_phase3.md) §4.1 の記述はこの点で訂正される。
- **procIdx の配送先を確定した**(§4)。既定は proc0 で、セキュリティ系コマンド(SET_KEYSTORE_KEY / READ_FROM_OTP / RSA 系)も proc0 行き。例外は SCRAMBLER で、CUST4_BUILD のビルドでは proc6 へ送られる。FW 側にも 7 プロセッサ分の通信記述子を初期化するコードがあり、proc6 が配送先として実在することは FW 側からも裏付けられた。ただし proc6 が「セキュリティ専用プロセッサ」であることまではコードから言えない。
- **FW 側の受信→ディスパッチ本体と DRM ハンドラ本体には今段も到達できなかった**(§5)。ただし探索の過程で、イメージ内の一部のライブラリが **+0x100000 ずれたアドレスビューでコンパイルされている**ことを実証した(§5.6)。この領域では絶対参照がすべて +0x100000 になるため、ベース 0 で構築した通常の xref では追跡できない。これが到達できない理由の一つとして具体化した。
- (a)/(b) の境界と READ_FROM_OTP の index 境界処理は、ハンドラ未到達のため**未判定のまま**(§6)。

---

## 1. 環境と手法、解析の到達範囲

- 対象: 主 FW 平文イメージ(docs/05 §2 と同一ファイル、SHA-256 は docs/05 に記録)。
- Ghidra 12.1.3 + ARCompact SLEIGH で新規プロジェクトを作成し、ベクタ表の 6 エントリをシードとして自動解析を実行した。結果: **命令 271,157 個、関数 1,840 個**を同定。
- コード密領域 [0x8000, 0x2D3070) については、命令バイト数 963,366、うち**どの関数にも所属しない孤立コードが 221,590 バイト(約 23%)**あった。関数表の走査や xref はこの孤立コードを対象にできない。§5 の陰性結果はすべてこの範囲注記とセットで読むこと。
- ホスト側一次資料として、GPL 公開分のカーネルドライバソースツリー(`xcodedriver_src`、ドライバ API 定義 `drv_if.h`、commsdk の `mipshost.h` / `crypto.h` / `sdevop.h` / `viper.h`、ドライバ実装 `kdrv/drv/*.c`)を実読した。

## 2. ベクタ表の実読

ベクタ表(イメージ先頭、8 バイト stride の `j limm` ×6)の飛び先は docs/08 §3.1 の実測どおり [0]=0x113C20、[1]=0x113C00、[2]=0x113D5C、[3]=0x100030、[4]=0x1002B8、[5]=0x2D0144。本段では各飛び先を Ghidra で実読した。

### 2.1 ベクタ[1]: 0x113C00 は命令の途中(確定)

0x113BD8〜0x113C24 の実読:

```
00113bdc  mov_s r0,0x9c
00113bde  mov_s r1,r19
00113be0  bl    0x002b7e20        ; 報告 API(§2.6)
00113be4  mov_s r0,0x9d
00113be6  mov_s r1,r14
00113be8  bl    0x002b7e20
00113bec  mov_s r0,0x9e
00113bee  mov_s r1,r25
00113bf0  bl    0x002b7e20
00113bf4  mov_s r0,0x9f
00113bf6  mov_s r1,0x2
00113bf8  bl    0x002b7e20
00113bfc  mov_s r0,0xa1
00113bfe  ld.di r1,[r20,0x24]     ; 4 バイト命令、0x113BFE〜0x113C01
00113c02  bl    0x002b7e20
00113c06  mov_s r0,0xa2
00113c08  ldb.di r1,[r19,0x4]
00113c0c  bl    0x002b7e20
00113c10  mov_s r0,0xa3
00113c12  ldb.di r1,[r19,0x5]
00113c16  bl    0x002b7e20
00113c1a  cmp_s r14,r25
00113c1c  bhi   0x00113a6a
00113c20  ld.di r2,[r18,0x60]     ; ← ベクタ[0] の飛び先
```

- 0x113C00 のバイト列は `01 28` で、これは 0x113BFE の `ld.di r1,[r20,0x24]`(バイト列 `24 14 01 28`)の後半半ワード(limm 部)に一致する。**0x113C00 は命令境界ではない**。
- 裏付けとして、Ghidra + ARCompact SLEIGH と GNU objdump の 2 つの独立したデコーダがどちらも 0x113C00 から命令をデコードできない(objdump は当該範囲を `...` と表示して読み飛ばす)。一方 0x113BFE を境界とする読みでは前後が破綻なく繋がる。
- したがってベクタ[1] は、このイメージのままでは**実行可能な入口を指していない**。解釈としては「使われていない例外スロットで、飛び先が有効なコードになったことがない」か「表の当該エントリが想定と違う解釈を要する」のいずれかであり、どちらかは静的には決められない。少なくとも、[1] 経由で受信処理や DRM 処理に繋がることは無い。

### 2.2 ベクタ[0] の周辺: 報告呼び出しとリスト処理のコード塊

- ベクタ[0] の飛び先 0x113C20 は Ghidra 上で関数として成立する(本体 0x113C20〜0x113CBD)。内容は、文脈構造体(r18 基点)の [＋0x60] のビット検査、[＋0x38]/[＋0x3C] の範囲で連結リストを辿る処理、末尾で報告 API を番号 0x9C で呼ぶ形である。
- §2.1 の実読のとおり、その直前にも番号 0x9C〜0xA3 を付けた報告 API 呼び出しが並んでおり、0x113A6A / 0x113A7A / 0x113B48 への分岐も含めて、この一帯(少なくとも 0x113A00〜0x113E57)は**1 つの大きなルーチン**を成す。性格としては、状態の検査結果を通し番号付きで報告しながら構造体群を辿る、診断・状態ダンプ系の処理と読める(断定ではなく読みの提示)。
- リセットハンドラらしい初期化列(スタック設定、データ初期化等)とは読めなかった。ベクタ[0] がリセット入口であるという前提は、本イメージでは裏付けられない。

### 2.3 ベクタ[2]・[3]: 例外記録(確定)

- ベクタ[2](0x113D5C)の関数は、一方の分岐で **0x100530 へ 0xDEADC0DE、0x100534 へ復帰アドレス相当(0x113D70)、0x100538 へスタックポインタ**を書き込み、共通トラップ先 FUN_002b8a64 方面へ進んで戻らない。docs/11 で読んだベクタ[3](0x100030、例外ハンドラで 0xDEADC0DE を記録)と同型の**例外記録ハンドラ**である。
- もう一方の分岐は境界計算とカウンタ加算(0x6662D0)を行う経路で、例外の種別判定を含んでいるように読めるが、種別の同定まではしていない。
- 記録先 0x100530〜 は、§5 の FUN_0015a3e0 の失敗分岐でも同じ 3 ワード(0xDEADC0DE / 復帰アドレス / スタック)で使われており、イメージ共通の異常記録領域である。

### 2.4 ベクタ[4]: 0x1002B8

- 関数として成立(本体 0x1002B8〜0x1003E9)。引数の照合(文脈の [＋0x120] / [＋0x128] との一致検査)を行い、カウンタ(基点＋0x1B32C)を進め、記録系の 2 関数(FUN_001cfd24、FUN_000dab14)へデータ構造のアドレス(0x3EBC1C〜)を渡して呼ぶ。周期的に呼ばれる状態監視・記録系のハンドラと読める。具体的な割り込み種別の同定はしていない。

### 2.5 ベクタ[5]: 0x2D0144 は DMA / アクセラレータ制御ルーチンの内部

- 飛び先は関数 FUN_002cfa94(本体 0x2CFA94〜0x2D0437、約 2.5KB)の内部で、デコンパイル結果にも 0x2D0144 に対応するラベルは現れない(流れの途中)。
- この関数は aux レジスタ 0x200〜0x274 を介して転送エンジンを設定する処理である: 転送元アドレス(param_1 ＋オフセット)、サイズ、制御値 0x100、モード値を書き、busy ビット(0x10)が落ちるまでポーリングする、という単位を複数チャネル分繰り返す。拡張レジスタ(r32〜r55、mlo)も使う。メディア系データ転送の DMA / アクセラレータ初期化・駆動ルーチンと読める。
- DRM 文字列密集域(0x2D3070〜)の直前に位置するが、関数自体は暗号や鍵に触れる内容ではなかった。[5] が独立した割り込み入口として使われる形跡も無い。[1] と同様、入口として有効な形では無い、というのが実読の結果である。

### 2.6 共通報告 API の実体(自動解析の表示に関する訂正)

- FUN_002b7e20 はイメージ全体から **180 件**の呼び出しがある小さな関数である。実読すると: 引数 (r0=番号、r1=値) を保存し、aux レジスタ 4 を読む葉関数 FUN_002b8a64 を呼び、その戻り値(現在文脈の識別バイトと読める)で分岐する、番号付き報告 API である。
- Ghidra の自動解析は FUN_002b7e20 / FUN_002b8a64 を「復帰しない関数」と表示し、呼び出し側のデコンパイルにも "Subroutine does not return" と付くが、これは関数境界の誤認による表示である(FUN_002b8a64 の先頭ブロックは `lr r0,[0x4]; lsr; extb; j blink` の葉関数であり、その直後に関数本体が続く)。第2〜3段の一部で前提にした「致命トラップ」的な読みは、この 2 関数については撤回する。§2.3 の「戻らない」も、0xDEADC0DE 記録後に当該ハンドラが処理を継続しない、という範囲での記述である。

## 3. コマンド番号の 2 層性(docs/09 §4.1 の訂正)

### 3.1 2 つの番号体系

ホスト側ドライバの一次資料を突き合わせると、コマンド番号は 2 層に分かれる。

- **API 層**(`drv_if.h` の enum): ドライバへの ioctl レベルの番号。CMD2_SDEV_SCRAMBLER=0x108、CMD2_SDEV_SET_KEYSTORE_KEY=0x113、CMD2_SDEV_RESERVE_KEYSTORE_SLOT=0x114、CMD2_SDEV_XC4_RSA_REQUEST=0x115、CMD2_SDEV_READ_FROM_OTP=0x116、オープン系は CMD_SDEV_OPEN_SECUREDTS=0x30、CMD_SDEV_OPEN_GENERIC=0x2E 等。docs/02 がホスト側で実測し、[docs/09](09_xcode_fw_drm_phase3.md) §4.1 が引用したのはこの層である。
- **伝送層**(`mipshost.h` の `mhcmd` enum): ドライバ実装(`kdrv/drv/*.c`)がパケットの FunctionNumber に実際に書く番号。ドライバ実装が使う識別子 `CMD2_SCRAMBLER` 等は `drv_if.h` には無く(API 層は `CMD2_SDEV_*` と綴る)、`mipshost.h` 側にのみ存在することから、解決先は伝送層であると特定できる。

対応表(抜粋、全 52 値のうち関係分):

| API 層(drv_if.h) | 伝送層 FunctionNumber(mhcmd) |
|---|---|
| (オープン系全般) | OPEN_STREAM = 8 |
| CMD2_SDEV_SCRAMBLER = 0x108 | CMD2_SCRAMBLER = 37 |
| ― | CMD2_SCRAMBLER_CRI = 40 |
| ― | CMD2_GET_RANDOM_BYTE = 41 |
| CMD2_SDEV_SET_KEYSTORE_KEY = 0x113 | CMD2_SET_KEYSTORE_KEY = 42 |
| CMD2_SDEV_XC4_RSA_REQUEST = 0x115 | CMD2_XC4_RSA_REQUEST = 43 |
| CMD2_SDEV_RESERVE_KEYSTORE_SLOT = 0x114 | CMD2_RESERVE_KEYSTORE_SLOT = 44 |
| CMD2_SDEV_READ_FROM_OTP = 0x116 | CMD2_READ_FROM_OTP = 45 |
| CMD2_SDEV_GET_MAC = 0x117 | CMD2_GET_MAC = 46 |
| CMD2_SDEV_NVMDATA = 0x11A | CMD2_NVMDATA = 50 |

伝送層の番号は 0〜51(LAST_MHCMD_NUMBER = 52)である。

### 3.2 帰結

- **FW 側の振り分けは 0〜51 の小さい値に対する処理**であり、0x100 以上の値で振り分けるコードは存在しないはずである。[docs/09](09_xcode_fw_drm_phase3.md) §4.1 が「FW 側で 0x108 等を受ける」前提で書いた部分は、本書をもって訂正する(docs/09 自体は当時の記録として残す)。
- **SECUREDTS には専用の伝送層 FunctionNumber が無い**(このドライバコピーの範囲)。オープン系は OPEN_STREAM = 8 を共有し、SECUREDTS かどうかはパケットのペイロード側(`sdev_op` の descram_op / `CRYPTOCTRL2`、`scramble_ctrl` の各 index 等)で表される。したがって FW 側で「SECUREDTS のハンドラ」を探すなら、OPEN_STREAM の処理の中でペイロードの種別を見る分岐が対象になる。
- パケット構造 `MIPSHOSTCOMPACKET`(全て uint32、サイズ 0x2C): ＋0x00 Next、＋0x04 Prev、＋0x08 Direction(1 = HOST2MIPS / 2 = MIPS2HOST)、**＋0x0C FunctionNumber**、＋0x10 PacketProcessed、＋0x14 Input、＋0x18 NextPacket、＋0x1C/＋0x20 CallerPrivate、＋0x24 procIdx、＋0x28 予約。
- ペイロード側の要点: SCRAMBLER のパケットには `control_words[24]` がインラインで入り(トークンはこの形で FW へ渡る)、ほかに keyStoreIndexOfSrcData / keyStoreIndexOfDstData を持つ。SET_KEYSTORE_KEY のパケットには鍵値 32 バイトがインラインでコピーされ、KeyIndex と NumberOf64BitSlot を伴う。READ_FROM_OTP のパケットは KeyIndex を渡す。`CRYPTOCTRL2` のフラグには ENCRYPTED_CW(0x4、「平文 CW でなければ」)と USE_SYSTEM_KEY(0x8)がある。

## 4. procIdx の配送先

### 4.1 ホスト側一次資料

- パケットバッファ取得(`Get_Mips_Com_Buffer`、mips.c)は **procIdx の既定値を 0** にする。明示的に書き換える発行元だけが別プロセッサへ行く。
- **SCRAMBLER(txc_scrambler.c)**: `FunctionNumber = CMD2_SCRAMBLER` に続けて、`#ifdef CUST4_BUILD` で **procIdx = 6**、そうでなければ 0。SCRAMBLER_CRI は procIdx = 0。SET_KEYSTORE_KEY(tx
...[truncated 6154 chars]