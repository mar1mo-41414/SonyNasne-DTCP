# 01. DTCP 実装の静的解析(公式ファームウェア)

実機には一切触れず、手元の作業環境に集めた素材(公式 rootfs の展開物・バイナリ・カーネルモジュール・GPL ソースツリー・SDK ヘッダ・先行解析)のみで、DTCP(著作権保護)関連の実装と鍵の流れを解析した記録(2026-11-11 実施、2026-11-13 に本リポジトリへ移行)。

目的は、「既存録画の回収」の成立を分ける 3 つの問いへの前進:

- (a) 録画本体 `.dat` の暗号化はソフト実装か、チップ内閉域(SoC の SECUREDTS/SECUREDLOCAL ストリーム)か
- (b) 暗号化鍵の正体(タイトル鍵/個体鍵/セッション鍵)と保存場所
- (c) 鍵が静的に抽出可能な形で存在するか

目標形は「復号に必要な鍵だけ nasne 実機から抜いて、実 TS の復号は PC の性能で」。

**鍵の値そのものは本書に書かない**(存在・形式・所在・導出手順の構造まで)。

> 移行後の追記: 本書の §3・§7 で「未確定」とした `.dat` の保存時暗号化は、その後の実機観測で実形態が確定した(SECUREDTS + GENERIC-AES、実効鍵はファームウェア側解決)。最新のモデルは [docs/02](02_dat_encryption_model.md)。

## 0. 結論サマリ

1. **DTCP-IP 配信の暗号化(PCP)はチップ内閉域**。平文 TS はチップ内に入り、ユーザーランドが受け取るのは暗号化済みデータのみ(`adapter_firmware_t::open_local` + `dtcp_read_from_fw: Direct Read Data From F/W`)。AKE(認証鍵交換)のプロトコル処理はユーザーランドの DTCP スタック(後述、dtvtuner 内蔵)が担うが、証明書の取得・鍵演算はファームウェア経由であり、交換鍵は「ファームウェアインスタンス」としてチップ側に保持される。
2. **新規発見: 専用カーネルモジュール `tpkeydec.ko` が「鍵のアンラップ」をソフト AES で行う**。デバイス固有の素材は **sysInfo ページ(物理 `0x1ffef000`)内の 3 箇所(オフセット `0x130` から 6 バイト、`0x3d0` から 5 バイト、`0x3d5` から 5 バイト、計 16 バイト)** にあり、ドライバ内の決定的な難読化処理で AES-128 鍵に変換される。ユーザーランド(dtvtuner の Tp ストリーミング経路)は 64 バイトの「ラップ済み鍵 blob」を渡し、平文の 16 バイト鍵を受け取る。**この導出はドライバのバイナリから完全に復元可能であり、sysInfo の 16 バイトさえ読めれば PC 側でも同じ鍵を計算できる**(§5、導出の完全復元は [docs/02](02_dat_encryption_model.md))。
3. ただし、**tpkeydec がどの鍵をアンラップしているか(blob の発行元・用途)は未確定**。呼び出し元は dtvtuner の `TpStreamSource::Create`(Tp = リモート視聴系ストリーミング基盤)であり、少なくとも Tp ストリーミングの鍵処理に使われる。`.dat` の保存時暗号化の鍵そのものかどうかは、現時点では言えない(§7)。
4. **`.dat` が保存時に暗号化されているかどうか自体が、静的解析だけでは未確定**(本解析時点)。入力経路(SECUREDTS)は B-CAS 復号をチップで行い平文 TS をユーザーランドへ出すことが実証済みで、保存段で SECUREDLOCAL(0x32)に通すかどうかは dtvtuner 側の呼び出しを静的に特定できていない(§3、§7)。実機での観測が決め手になる(§9。観測結果は [docs/02](02_dat_encryption_model.md) にある)。
5. 本体の裏面ラベル値(DTCP の 16 進 10 桁)が「録画データ暗号化に関与する鍵ラベル」という従来の理解には、**FW 実装からの裏付けは得られなかった**。FW 側で確認できた個体鍵素材は sysInfo 内の上記 16 バイトと、工場工程で SoC の OTP に書かれる DTCP 鍵(§6)であり、ラベル値(10 桁 = 40 bit)は DTCP デバイス ID(5 バイト)と桁数が一致する点が唯一の接点(ID であって鍵ではない可能性が高い)。

## 1. 素材と手法

| 素材 | 内容 |
|---|---|
| 公式 rootfs 展開物 | 公式ファームウェア 2.60 の rootfs を PC 側で展開したもの(84MB) |
| dtvtuner / webapi / TpCore 等 | rootfs 内 `/opt/dtvtuner/bin/` |
| 共有ライブラリ群 | rootfs 内 `/opt/dtvtuner/lib/`(`libTelepathy.so`、`libcommlib.so`、`libsechdd.so` 他) |
| カーネルモジュール | rootfs 内 `/opt/dtvtuner/lib/modules/{xcode4drv.ko, tpkeydec.ko}` |
| GPL ソースツリー | SIE 公開の GPL ソース(ViXS commsdk + xcode4drv ドライバ、Linux 2.6.29) |
| SDK ヘッダ | GPL ソース同梱の `drv_if.h` と、ドライバの ioctl コマンド表 |
| 既存解析 | 姉妹リポジトリ側の先行解析(ハードウェア、TS と B-CAS 復号、ドライバ ioctl、sysInfo) |

手法: `strings`、`readelf`、`mipsel-linux-gnu-objdump -d` による逆アセンブル(dtvtuner は約 100 万行に展開して文字列参照を追跡、tpkeydec.ko は ioctl ハンドラを全解読)。

## 2. コンポーネント棚卸し

### 2.1 DTCP に関与するコンポーネント

| コンポーネント | 役割 | DTCP との関係 |
|---|---|---|
| `dtvtuner`(5,582,708B) | チューナー制御・録画・配信の中核デーモン | **DLNA DMS + DTCP-IP ソース(送信)スタックを内蔵**。ソースパス文字列 `./dlna/dtcp/src/{dtcp_core, ake_helper, cert, dtcp_ip_server, dtcp_pcp_stream, adapter_firmware, srm, session, response, net_server, utils}.cpp`(識別子は `nobf0024::` 名前空間で難読化)。文字列数: DTCP 関連 193 件。tpkeydec の利用者でもある(§5) |
| `webapi`(5,709,364B) | HTTP API(64210) | DTCP 関連文字列 201 件。工場検査系パス(`/var/opt/dtvtuner/tmp/00010001/ftest/OTP2/spikeywrite`、`.../setdtcp.cfg`)を持ち、DTCP デバイス ID の表示・設定系(`sysInfoSetDtcpDeviceId`)に関与。`/dev/tpkeydec` も参照する(利用文脈は本解析では未特定) |
| `TpCore`(2,516,596B) | Telepathy 基盤のコア | `telepathy.device.dtcpmgr.server`、`GetDtcpDeviceId`、`GetDTCPStatus`、P2P DTCP ping/listen。DTCP 管理サービスの提供側 |
| `libTelepathy.so`(3,065,072B) | Tp 基盤ライブラリ | DTCP マネージャとの RPC |
| `libcommlib.so` | sysInfo アクセス | `seiSysInfoOpen` が物理 `0x1ffef000` を mmap し `sysInfoGet*/Set*`(チップ ID、MAC、**DTCP 機器 ID**、ファーム版数等)を提供 |
| `libsechdd.so` / `libsechddext.so` | HDD セキュリティ | `.hai`(HDD 登録情報)の生成・検証側。DTCP 本体とは別系統 |
| `libdtvrmtext.so` | リモートチューナー拡張 | `dtvRemoteTunerDtcpDeviceIdGet`、`dtvRemoteNVSecureDataRead/Write`(外出先視聴のペアリング系 NV データ) |
| `tpkeydec.ko`(32,068B、Proprietary) | **鍵アンラップ専用カーネルモジュール** | ソフト AES(rijndael テーブル実装)を内蔵し、sysInfo から導出したデバイス鍵で 64B blob を復号して 16B 鍵を返す(§5)。先行解析では「ロードするだけ」とだけ記録されていたものの実体 |
| `xcode4drv.ko` | ViXS XCode4210 ドライバ | ファームウェアへのコマンドディスパッチ(`ioctl 0x17241724`)。暗号実体はファーム側 |
| SoC ファームウェア(XCode4210) | チップ内処理 | B-CAS デスクランブル(SECUREDTS)、DTCP PCP 暗号化(LOCAL ストリーム)、AKE の鍵演算・証明書保持、DH セッション鍵(鍵スロット参照) |

証明書ファイルについて: rootfs 内を走査した範囲では DTCP デバイス証明書に相当するファイルは**存在しない**(`/opt/dtvtuner/etc/cert/` にあるのは DAP 用 CA 証明書 `DapClient_ca.crt` のみ)。デバイス証明書は `adapter_firmware_t::get_cert` で**ファームウェアから取得**する設計(§4)。

### 2.2 AKE(認証鍵交換)の実装所在

- プロトコル状態機械・証明書検証・SRM(更新可能性メッセージ)処理は **dtvtuner 内蔵の DTCP スタック(ユーザーランド)** が実装する(`ake_helper.cpp`、`cert.cpp`、`srm.cpp`、SRM はファイルとして保持され `micro_media_server_t::dtcp_set_srm_file` で指定)。
- しかし鍵演算そのものはチップ側: `adapter_firmware_t::send_generic(..., DTCPMSG*)` で `/dev/vixs/xcodedrv` 経由でファームに DTCP メッセージ処理を委譲し、交換鍵(Kx)は `dtcp_core_t` のレジストリで「ファームウェアインスタンス」として管理される(`dtcp_send_info_t::set_exchange_key: set firmware ins`)。つまり **Kx の実体はユーザーランドに平文で存在しない**。
- SDK 側の対応: SECUREDTS オープン引数 `param_opensecuredts.xcode_key_index` は「交渉済み Diffie-Hellman 鍵へのインデックス」と明記されており、DH 鍵はチップ内に残りホストは番号で参照するだけ、という設計が SDK 全体で一貫している。`param_openlocal` にも `decrypt_key_slot_id` / `encrypt_key_slot_id`(鍵スロット ID)があり、鍵はスロット参照が原則。
- なお SDK には `pdwSelector`(「128bit コンテンツ鍵と 128bit IV が置かれたホストメモリの開始アドレス」)という「ホストから鍵を渡す」規定もあるが、これは他 DRM 方式向けの汎用規定であり、nasne の DTCP 経路で使われている証拠はない。

## 3. 録画経路(チューナー → `.dat`)

先行解析で確定している入力側:

```
チューナー → [チップ内] SECUREDTS (CMD 0x30)
              input_encrypt_mode = BCAS(1), securedts_mode = 0x40 (VIA_BCASCARD)
              B-CAS カードで ECM 処理 → MULTI2 デスクランブルはチップ内
           → 平文 TS がユーザーランド (dtvtuner) に渡る   ★実証済み
              (自作の受信ツールが同じ経路で平文 TS を受信できている)
           → dtvtuner が p3 (00000015/<bucket>/<group>/<quality>/0000/NNN.dat) へ書く
              2,147,483,520 バイト (2GiB-128B) で分割、品質ディレクトリ毎に "999" ファイル
```

- SECUREDTS にはミラー出力(mt_* 系)があり、元画質と変換画質の同時生成(実測された品質コード 1 と 4 の同時存在)と整合する。
- **未確定点**(本解析時点): dtvtuner が受け取った平文 TS をそのまま `.dat` に書くのか、保存用に SECUREDLOCAL ストリーム(CMD 0x32、OPEN_LOCAL と同じ引数構造 `param_openlocal` を共有)へ通してから書くのか。SDK 上 SECUREDLOCAL は「ローカル保存用の保護ストリーム」として存在するが、dtvtuner 内で cmd 0x32 を発行する箇所は本解析では特定できなかった(ストリップ済みコード内の ioctl 構造体組み立てを静的に追うのは困難)。GENERIC モードの `DTCP 0x200` フラグは「DTCP 保護付き汎用ストリーム」の存在を示すが、録画保存への使用は未確認。
- したがって **`.dat` の保存時暗号化の有無は静的解析では未確定**(本解析時点)。`.dat` の実バイト列は当時の方針で未読であり、どちらに転んでも矛盾しない材料しか揃っていない(その後の物理読みでは、`.dat` はブロック暗号相当の暗号化が掛かっていることが確定した。[docs/02](02_dat_encryption_model.md))。

## 4. 再生・配信経路(`.dat` → DTCP-IP)

```
.dat 読み出し → [チップ内] LOCAL ストリーム (CMD_SDEV_OPEN_LOCAL = 0x10)
                  adapter_firmware_t::open_local: SOURCE モード、EMI と MoveLabel を設定、
                  SRM の検証・設定 (verify_srm / set_srm) を伴う
               → ユーザーランドが読むのは PCP 暗号化済みデータ
                  ("micro_media_server_t::dtcp_read_from_fw: Direct Read Data From F/W",
                   "get the FIRST ENCRYPTED data", "new PCP, size=...")
               → dtcp_pcp_stream / dtcp_ip_server (dtvtuner 内蔵) が HTTP で送信
```

- 配信段では**平文 TS はユーザーランドに現れない**(チップが読み出しと PCP 暗号化を一体で行い、暗号文だけがホストに渡る)。入力が平文ファイルか保存暗号化ファイルかに関わらず、この段の構造は変わらない(チップ内ストリームが入力側で必要なら復号も担う)。
- DTCP-IP のコンテンツ鍵は AKE でセッション毎に交渉され、鍵スロット/ファームウェアインスタンスとしてチップ内に保持される(§2.2)。**配信鍵は静的抽出の対象にならない**(セッション鍵であり、実体がチップ外に出ない)。
- これとは別に、**Tp ストリーミング経路**(torne mobile 等のリモート視聴系、`TpStreamServer` / `TpStreamRPC::GetStreamKeySet` / `KeyInfo` / ペアリング ACL)が dtvtuner 内にあり、その鍵セットアップで tpkeydec が使われる(§5)。DLNA/DTCP-IP 経路と Tp 経路は別の保護基盤である点に注意。

## 5. tpkeydec.ko の全解読(本解析の中心)

### 5.1 概要

- misc デバイス `/dev/tpkeydec` を登録するだけの小さなモジュール。`open`/`release` は無処理(即成功)。
- 唯一の ioctl は **cmd = 0**、引数は 24 バイト構造体へのポインタ:
  - `+0x00`: 入力 blob へのユーザーポインタ
  - `+0x04`: blob 長(64 でなければならない)
  - `+0x08..+0x17`: 出力 16 バイト(アンラップ済み鍵)の書き戻し先
- 内蔵するのはテーブル駆動のソフト AES(rijndael 実装、`rijndaelSetupEncrypt/Decrypt`、`rijndaelEncrypt/Decrypt`)。暗号処理はすべてこのモジュール内(カーネル内)で完結し、チップには行かない。

### 5.2 デバイス鍵の導出(初回 ioctl 時に 1 度だけ)

1. 物理 `0x1ffef000`(sysInfo ページ)を 4KB 要求・マップする。
2. 次の 3 断片、計 **16 バイト**を読む: オフセット `0x130` から 6 バイト、`0x3d0` から 5 バイト、`0x3d5` から 5 バイト。これが個体素材 `S`。
3. ドライバ内の決定的アルゴリズムで 2 本の固定列 `A`・`B`(各 16 バイト、線形漸化式で生成される定数列)を用意する。`A` は AES 鍵、`B` は XOR パッドとして使う。**どちらも全個体共通の定数**であり、バイナリから再計算可能(難読化であって秘密ではない)。
4. 中間値 `C[i] = (~S[i]) XOR B[i]` を作り、`Kdev = AES-128-Encrypt(key=A, block=C)` を計算して保持する。以後 `Kdev` がアンラップ鍵になる。

すなわち **秘匿性は sysInfo の 16 バイト `S` のみに依存** し、導出全体はオフラインで再現できる。`S` の各断片の意味(何の ID/素材か)は本解析では未特定(その後、断片の正体は特定された: [docs/02](02_dat_encryption_model.md))。断片サイズ 5 バイトは DTCP デバイス ID のサイズと一致するが、`0x3d0`/`0x3d5` がそれだという証拠はない(本解析時点)。

### 5.3 blob の形式とアンラップ処理

入力 blob は 64 バイト固定:

| オフセット | 内容 |
|---|---|
| `+0x00..+0x03` | 全長(ビッグエンディアン 32bit)。構造体の長フィールドと一致し、64 であること |
| `+0x04` | モードバイト。`1` でなければならない |
| `+0x05..+0x0f` | (ドライバは参照しない) |
| `+0x10..+0x1f` | CBC の IV として使う 16 バイト |
| `+0x20..+0x3f` | AES-128-CBC 暗号文 2 ブロック(鍵は `Kdev`) |

ドライバは 32 バイトを CBC 復号し、**先頭 16 バイトだけ**を構造体 `+0x08` に書き戻す(後半 16 バイトは復号されるが返されない。パディング/検証用とみられる)。失敗時は `-EINVAL`/`-ENOMEM` 等を返し、ユーザーランド側(TpStreamSource)は ENOMEM をリトライ、EINVAL をエラーとして扱うことも逆アセンブルで確認した。

### 5.4 呼び出し元

- dtvtuner 内で `/dev/tpkeydec` を開き ioctl(0) を呼ぶのは **`TpStreamSource::Create`** の 1 箇所(文字列参照の追跡で特定。他の 1 件の一致は無関係な即値だった)。
- アンラップ結果の 16 バイトは `TpStreamSource` オブジェクト内に保持される。
- 周辺には `TpStreamRPC::GetStreamKeySet(... KeyInfo*)`、`TpStreamService::GetKeyInfo` があり、**blob は Tp の鍵情報(KeyInfo)として外部(ペアリング相手またはストレージ)から供給される**可能性が高いが、発行元の特定には至っていない。
- webapi も `/dev/tpkeydec` を参照するが、呼び出し箇所の特定は未了(工場/設定系の文脈とみられる)。

## 6. 鍵素材の所在まとめ

| 素材 | 所在 | 形式・備考 |
|---|---|---|
| tpkeydec の個体素材 `S`(16B) | **sysInfo ページ(物理 `0x1ffef000`)内オフセット `0x130`/`0x3d0`/`0x3d5`** | 断片配置。sysInfo は SPI フラッシュの INFO 系領域から起動時に構築されるページであり、**SPI ダンプ側にも源データが存在するはず**(対応付けは本解析では未検証。その後、対応付けは確定した: [docs/02](02_dat_encryption_model.md)) |
| DTCP デバイス ID(5B) | sysInfo(`sysInfoGetDtcpDeviceId`) | 識別子。webapi の表示形式は 16 進 10 桁 |
| DTCP デバイス証明書 | **ファームウェアから取得**(`adapter_firmware_t::get_cert`)。rootfs 内にファイルなし | 候補として SPI の `0x90000`/`0xA0000` の blob(各 3,328B、高エントロピー、先行解析で未解読と記録)が挙がるが未確認 |
| DTCP デバイス鍵(秘密鍵) | SoC の **OTP** とみられる | dtvtuner 内文字列 `[NOTE] PLEASE CHECK IF PROGRAMMED DTCP KEY INTO OTP!`、webapi の工場工程パス `ftest/OTP2/spikeywrite` / `setdtcp.cfg`(SPI 経由で OTP へ書く工程)。**静的抽出は不可能な設計** |
| DTCP-IP 交換鍵・コンテンツ鍵 | チップ内(ファームウェアインスタンス/鍵スロット参照) | セッション毎。ユーザーランドに平文で存在しない(§2.2、§4) |
| tpkeydec の blob(64B) | 発行元未特定(Tp KeyInfo 経由) | §5.3 の形式。**永続保存されるものなら HDD/DB 側に存在するはず**で、次段の探索対象(探索結果は [docs/02](02_dat_encryption_model.md): 回収済み素材の中に blob 形式のデータは存在しなかった) |
| SRM | ファイル(`micro_media_server_t::dtcp_set_srm_file`、拡張子 `.dtcp` のファイルが関係) | DTCP の更新可能性情報。鍵ではない |
| B-CAS カード鍵・ECM 由来鍵 | B-CAS カード内 + チップ内 SECUREDTS | 放送スクランブル用。保存用ではない |

本体裏面のラベル値について: 16 進 10 桁 = 40 bit であり、FW 側で 40 bit の個体値として実在が確認できるのは **DTCP デバイス ID(5 バイト)** だけだった。ラベルが ID の印刷だとすれば「録画データ暗号化に関与する鍵」という従来メモは言い過ぎで、**少なくとも tpkeydec の素材 `S` はラベル値とは別物**(sysInfo 内の 16 バイト断片であり、表示・印刷を前提としない配置)。ラベル値 = DTCP デバイス ID 説は桁数一致以上の裏付けはなく、断定はしない(その後、sysInfo の `+0x3d0` の値とラベルが一致することが実測で確認され、この説は確定した: [docs/02](02_dat_encryption_model.md))。

## 7. 問い (a)(b)(c) への回答

### (a) `.dat` の暗号化はソフトかチップ内か — **未確定(ただし構造はかなり絞れた)**(本解析時点)

- 入力段(放送 → 平文 TS)はチップ内処理(B-CAS/MULTI2)で確定。出力段ユーザーランドへの受け渡しは平文で実証済み。
- 保存段に SECUREDLOCAL 等のチップ保護が掛かるかは未確定。掛からないなら `.dat` は平文 TS(192 バイト単位化と分割のみ)であり、そもそも復号不要。掛かるなら復号はチップの鍵スロット経由になる可能性が高く、PC 復号には「鍵スロットに入る鍵の正体」の解明が別途必要。
- 一方、**ソフト実装の鍵アンラップ(tpkeydec)が実在し、その鍵はオフライン計算可能**(§5)。もし `.dat` のタイトル鍵が tpkeydec の blob 形式で DB/HDD 側に保存されているなら、保存段がチップ保護でも「鍵だけ抜く」目標形は成立しうる。これが次段の最重要の判定点。

### (b) 鍵の正体と保存場所 — **階層構造は判明、`.dat` 用鍵のみ未特定**

判明した階層: 個体素材 `S`(sysInfo)→ 導出鍵 `Kdev`(tpkeydec)→ blob アンラップ → 16B 鍵(Tp 経路で使用)。DTCP-IP 配信鍵は AKE のセッション鍵(チップ内)。DTCP デバイス鍵は OTP。`.dat` の保存鍵(存在すれば)がこのどの階層にぶら下がるかは未特定。

### (c) 静的抽出可能性 — **素材次第で可否が分かれる**

- tpkeydec 系: **可**。`S` は SPI フラッシュ由来のページにあり、導出は決定的。SPI ダンプ + 本書の手順で `Kdev` を PC 上で計算できる見込み(源データと sysInfo ページの対応付け検証が前提)。
- DTCP デバイス鍵・AKE セッション鍵: **不可**(OTP/チップ内閉域)。ただしこれらは配信専用で、録画回収には不要なはず。
- `.dat` 保存鍵: 存在と形式が判明すれば (a) の判定次第。blob 形式なら回収可能圏内。

## 8. 目標形(鍵だけ抜いて PC で復号)への含意

- **追い風**: 「鍵アンラップがソフト処理で、鍵導出がオフライン再現可能」という実例(tpkeydec)が見つかった。暗号化が全部チップ内閉域という最悪の想定は崩れた。nasne 系で解けてきた暗号(.dlm、録画 DB、`.hai`)がすべて「ソフト + ファーム内に鍵」というパターンだったこととも整合する。
- **前提条件**: 目標形が成立するには、(1) `.dat` が実際に暗号化されていること(平文なら不要)、(2) その鍵または鍵を包む blob が HDD 側(DB・`999` ファイル・品質ディレクトリ内メタ等)に永続化されていること、(3) 暗号アルゴリズムとモードが特定できること、の 3 点が要る。本解析時点では (1) 自体が未確定(その後の観測で (1) は肯定、(2) は否定方向に進んだ: [docs/02](02_dat_encryption_model.md))。
- **DTCP-IP 配信鍵の抽出は目標に入れない**: セッション鍵 + チップ内保持で設計されており、録画回収とは無関係。

## 9. 次に実機で観測すべき点(観測の狙いどころ)

実機が使えるようになったら、優先順に(実施結果は [docs/02](02_dat_encryption_model.md) を参照):

1. **公式 FW での録画実行中に dtvtuner の ioctl を観測**(xcode4drv 宛): OPEN 系コマンド番号の列を取り、**cmd 0x32(SECUREDLOCAL)/ GENERIC の DTCP フラグ 0x200 が録画開始時に発行されるか**を確認する。これで問い (a) がほぼ決着する。
2. **`.dat` の先頭数 KB の実バイト確認**: TS 同期バイト(0x47)周期が見えるか、高エントロピーか。併せて品質ディレクトリの `999` ファイル(1,296B)と録画 DB の未解釈タグ(`dr_c_data` 等)に **64 バイト blob(先頭 BE 長 = 64、第 5 バイト = 1)** らしい構造が無いか照合する。
3. **tpkeydec の ioctl 観測**: 録画開始・再生開始・Tp ストリーミング開始のどれで呼ばれるか、入力 blob のコピー元バッファ(どのファイル/DB レコードから来たか)を追う。blob の発行元が特定できれば問い (b) が前進する。
4. **sysInfo ページのダンプと SPI ダンプの対応付け**: 実機の sysInfo(物理 `0x1ffef000`、物理メモリ読み出しツール利用可)でオフセット `0x130`/`0x3d0`/`0x3d5` の断片が SPI のどの領域に対応するかを確認(値は記録に書かない。対応の有無と、断片が MAC/DTCP ID 等の既知フィールドと重なるかだけ)。ラベル値 = DTCP デバイス ID 説の検証もこのとき(`sysInfoGetDtcpDeviceId` の戻りとラベルの照合は実機側でのみ行い、値は残さない)。
5. Debian/stage1 環境から: 同じ `tpkeydec.ko` は Debian 側でもロード可能なので、公式 FW に戻さなくても blob のアンラップ実験自体は可能。HDD 上で blob らしい 64 バイトが見つかれば、その場でアンラップ → 16B 鍵が得られるか試せる。

## 10. 残課題・本解析の限界

- dtvtuner の録画書き込み関数の特定(ストリップ + 最適化で ioctl 構造体の組み立て追跡が困難)。Ghidra での関数境界復元 + エミュレーション実行(SECUREDTS で実績のある手法)が有効な見込み。
- webapi 側の tpkeydec 利用文脈、blob の発行元(Tp KeyInfo の供給経路)。
- SPI blob(`0x90000`/`0xA0000`)と DTCP 証明書の関係。
- sysInfo 断片 `S` の各部の意味づけ。

## 付記: 解析メモ

- tpkeydec.ko の ioctl ハンドラ逆アセンブルは作業環境の一時ファイルに置いた(揮発)。要点は §5 に転記済み。
- dtvtuner の `/dev/tpkeydec` 参照はファイルオフセット `0x41b6b4`(仮想 `0x81b6b4`)、呼び出しは仮想アドレス `0x5c5cd4` 付近(open → ioctl(fd, 0, &struct))。
- 本書は、録画データ側の調査([docs/02](02_dat_encryption_model.md))に対する FW 側からの回答編にあたる。
