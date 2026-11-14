# 21. torne mobile (iOS) 復号済み IPA の静的解析 — 録画/再生 API と DTCP-IP クライアント実装

公式クライアントである torne mobile (iOS 版) の復号済み IPA を静的解析し、nasne との通信 (録画一覧・予約・再生) の API 構造と、クライアント側の DTCP-IP 実装の痕跡を洗い出した記録 (2026-11-14 実施)。ネットワークへの接続は一切行っていない (展開・文字列・シンボル・定数の静的読みのみ)。

**現在の到達点**: クライアントと nasne の間には 3 系統の制御/転送面があることを同定した — (1) nasne 独自 WebAPI (エンドポイント 62 件を文字列から全数抽出)、(2) UPnP (ContentDirectory / X_PvrControl / X_ScheduledRecording の SOAP テンプレートがバイナリ内に埋め込み)、(3) DLNA DMS のコンテンツ転送 (ポート 60151 の ObjID 形式 URL)。再生の保護は DTCP-IP で、クライアント側には Sony 製 DTCP-IP ミドルウェア「DEWEY」(AKE の全コマンドクラスと鍵管理 API) と、AVBase 側の独立した CDtcpIp スタックの 2 系統が同梱されている。保存 `.dat` の鍵に関する情報はクライアントには存在しない (配信鍵と保存鍵は別物という既存モデルと整合)。

## 1. 対象と方法

### 1.1 対象の同定

- ファイル: `com.playstation.tornemobile-20261113-021606-40a54849e595babd.ipa` (復号済み IPA、78,248,109 バイト、SHA-256 `576e9fba01693cbe1e037881a10dcd1f2e330b3f0c807f71454d7a6ce7355579`)。
- アプリ: バンドル ID `com.playstation.tornemobile`、表示名 torne® mobile、バージョン **1.50** (ビルド `2026072311`)、最低 iOS 13.0、arm64 単一アーキテクチャ。
- 本体 `Payload/torneplus.app`、実行ファイル名 `torneplus`。同梱フレームワークは自社製 2 件のみ: `Frameworks/AVBase.framework` (`jp.torne.AVBase`) と `Frameworks/PvrBgApp.framework` (`jp.torne.PvrBgApp`)。
- 3 バイナリとも `LC_ENCRYPTION_INFO_64` の **cryptid = 0** で、FairPlay 復号済みであることを実測で確認した (torneplus: cryptoff 16384 / cryptsize 9,338,880、AVBase: cryptsize 2,555,904、PvrBgApp: cryptsize 3,702,784)。

### 1.2 方法

- IPA を展開し、`strings` (ASCII / UTF-16LE)、`llvm-objdump` (ロードコマンド・リンクライブラリ)、`llvm-nm` (定義/未定義シンボル) で抽出。バイナリサイズは torneplus 11,662,848 バイト、AVBase 2,895,888 バイト、PvrBgApp 4,106,640 バイト。ASCII 文字列の行数は torneplus 66,894 行、PvrBgApp 14,419 行、AVBase 11,793 行。
- 暗号定数テーブルは既知のバイト列 (AES S-box/逆 S-box、SHA-256 K 初期値、SHA-1/MD5 初期値、Blowfish P-array) を全バイナリに対して走査した。
- 本書で「事実」とするのは上記の静的読みで直接確認できたものだけとし、構造からの推測は「解釈」と明記する。

## 2. バンドル構成とリンク関係

- リソース: `GCRESOURCEDIR.psarc` (1,335,654 バイト)、`PvrResource.cxml` (12,034,656 バイト)、`PvrTheme.cxml` (6,025,456 バイト)、`PvrVersionHistory.cxml`、`NicoJkResource.cxml`、`TwitterResource.cxml`、`initialContent.db` (366,592 バイト)、`TelepathyDeviceConfig.bin` (12,272 バイト)、`SceCompanionUtilResorce.bundle` ほか。`.cxml` はバイナリ形式 (先頭から平文 XML ではない)。`initialContent.db` は SQLite マジックを持たず先頭から高エントロピーで、平文 SQLite ではない (暗号化ないし独自形式。形式の同定は未実施)。
- torneplus のリンク先 (システム): AVFoundation / CoreMedia / VideoToolbox (再生)、Security (鍵・証明書)、CFNetwork、SystemConfiguration、StoreKit (課金)、EventKit (カレンダー登録)、Social / SafariServices、UserNotifications、libxml2、libresolv、libz、libc++、OpenAL / GLKit (UI エンジン系)。`NSLocalNetworkUsageDescription` は「アプリから nasne をご利用いただくため」と明記され、`NSAllowsArbitraryLoads = true`。
- 静的に組み込まれたライブラリの痕跡: **libcurl 7.48.0** (SecureTransport バックエンド、`CLIENT libcurl 7.48.0` の文字列)、**CocoaAsyncSocket** (GCDAsyncSocket の文字列が torneplus と PvrBgApp の双方に 39 件)、**Telepathy** (後述のリモートアクセス基盤、`Tp` 接頭辞のクラス群が torneplus 内に静的リンク)。
- torneplus が PvrBgApp から import する DTCP 関連シンボルは **`_PvrDtcpIpKeyManagerInitialize` と `_PvrDtcpIpSetTrustedTimeFunc` の 2 件だけ** (llvm-nm の未定義シンボルで確認)。AVBase は `PvrDtcpIp` 接頭辞のシンボルを import していない (§4.2)。

## 3. nasne との通信

### 3.1 発見 (ディスカバリ)

- torneplus 内に SSDP 探索の実装 (`"ssdp:discover"`、`ST: urn:schemas-upnp-org:device:MediaServer:1`、Telepathy 側の `TpDServiceDevDiscoveryProcSSDP` / `LookupDeviceBySSDP`) があり、nasne を UPnP MediaServer として LAN 内で発見する構造。
- ルーター側の UPnP IGD (WANIPConnection / WANPPPConnection、`AddIGDPortMappingSoap` 等) を操作するコードもあり、リモート視聴のためのポートマッピングを行う設計。

### 3.2 nasne WebAPI (独自 HTTP API)

torneplus の文字列から、`PvrNasneWebAPI` クライアントが使うエンドポイント **62 件**を全数抽出した (パス末尾の名前。データモデル側のクラスとして `PvrNasneWebAPIConfInfo`、`PvrNasneWebAPIDtcpipClientInfo`、`PvrNasneWebAPIHDDInfo`、`PvrNasneWebAPILiveStatus` 等の RTTI 名も存在する)。

- **config/ (17 件)**: HDDRegister、HDDRegisterProgressGet、HDDRelease、**PINVerify**、areaInfoSet、boxNameSet、channelScanCancel、channelScanProgressGet、channelScanStart、currDateSet、dtcpipClientStop、finishSetup、internalHDDInitialize、internalHDDInitializeProgressGet、mobileBitrateInfoSet、parentalRatingInfoSet、recNgListDelete
- **recorded/ (13 件)**: PMTMapGet、SEMapDataGet、recordedContentAdditionalInfoGet、recordedContentAdditionalInfoSet、recordedContentChpDataGet、recordedContentCountGet、recordedContentMaxCountGet、recordedContentResumePositionSet、recordedContentThumbnailGet、thumbnailMapGet、titleDelete、titleListGet、titleUpdate
- **schedule/ (7 件)**: conflictListGet、reservedInfoBitrateGet、reservedInfoCreate、reservedInfoDelete、reservedInfoUpdate、reservedListGet、reservedListGet2
- **status/ (25 件)**: BCASInfoGet、CAMsgInfoGet、EMMMsgInfoGet、EPGVersionInfoGet、HDDInfoGet、HDDListGet、areaInfoGet、boxNameGet、channelListGet、currDateGet、dmsStreamStopReasonListGet、**dtcpipClientListGet**、dtvtunerDeviceInfoGet、isFinishSetup、liveStreamPCRGet、liveStreamPCRGet2、liveStreamStatusListGet、mobileBitrateInfoGet、multiTunerLiveStreamStatusListGet、networkIfInfoGet、parentalRatingInfoGet、recNgListGet、requestClientInfoGet、softwareVersionGet、updateCheck

所見:

- 録画一覧 (`recorded/titleListGet`)、予約 CRUD (`schedule/reservedInfoCreate/Delete/Update`)、ライブ状態 (`status/liveStreamStatusListGet`) など、アプリの主要機能がこの WebAPI で完結する構成。
- DTCP-IP 関係では `status/dtcpipClientListGet` (nasne 側の DTCP-IP クライアント一覧の取得) と `config/dtcpipClientStop` があり、クライアントは **nasne 側の DTCP-IP セッション状態を WebAPI 経由で照会・停止できる**。本体側のメソッド名として `GetDtcpipClientListByPurpose`、`GetDtcpipClientInfoSelf`、`CanBecomeDtcpipClient`、`StopDtcpIpClient`、`SetDtcpipClientInfoList` (引数は `PvrNasneWebAPIDtcpipClientInfo` の vector) の RTTI/シンボル痕跡がある。
- 認証については `config/PINVerify` の存在から PIN による検証が組み込まれていることまでは分かるが、トークンの形式やヘッダ名 (例: `X-DTVToken` のような文字列) は 3 バイナリの文字列に**存在しない** (実測の陰性)。また既知の WebAPI ポート番号 `64210` の文字列も 3 バイナリとも存在しない。ポートや認証情報は数値定数として埋め込まれているか、発見経路 (UPnP デバイス記述) から得ているとみられるが、文字列解析の範囲では未同定。

### 3.3 UPnP / SOAP と DMS コンテンツ転送 (ポート 60151)

torneplus には SOAP リクエストの**テンプレート文字列そのもの**が埋め込まれており、対象サービスは次の 3 つ。

- **ContentDirectory:1** (`urn:schemas-upnp-org:service:ContentDirectory:1`): `Browse` (BrowseDirectChildren / BrowseMetadata、ObjectID・Filter・StartingIndex・RequestedCount を埋め込むテンプレート)。
- **X_PvrControl:1** (`urn:schemas-s-bras-org:service:X_PvrControl:1`): 引数として `TitleID`、`Id`、`BroadcastType` + `SkipChannel`、`recordDestinationID` を取るアクションのテンプレート群 (チャンネル切替や録画先指定などの PVR 制御)。
- **X_ScheduledRecording:2** (`urn:schemas-xsrs-org:service:X_ScheduledRecording:2`): xsrs スキーマの item を組み立てるテンプレート群。予約作成 (scheduledStartDateTime / scheduledDuration / scheduledChannelID (broadcastingType、channelType="2"、0x%04x 形式) / desiredQualityMode / desiredMatchingID (type="SI_PROGRAMID") / reservationCreatorID / priorityFlag / recordDestinationID)、予約検索 (SearchCriteria、ソート ±scheduledStartDateTime)、既存予約への titleProtectFlag / titleNewFlag の更新など。`X_ScheduledRecordingExt:1` の URN も存在する。

コンテンツ実体の取得先はポート **60151** の URL テンプレート (いずれも torneplus 内、書式文字列のまま抽出):

- EPG/ロゴ: `http://%s:60151//EPG_TRDEPG_FILE.dat`、同 BS/CS/USB-HDD 系 (`EPG_BS*`、`EPG_CS*`、`EPG_HA*`、ロゴ用 `*_LOGO_FILE.dat`)
- コンテンツ: `http://%s:60151/ObjID=V_%u_ResID=/IFO_PS_%u.ifo`、`http://%s:60151/ObjID=/IFO_PS_%u.ifo`、`http://%s:60151/ObjID=USBV_%u_ResID=/USBIFO_PS_%u.ifo` (ObjID/ResID でコンテンツと IFO を指す DLNA DMS 形式)

すなわち録画のブラウズは ContentDirectory、実体の転送は 60151 の HTTP で行われ、保護付きコンテンツの転送に DTCP-IP が被さる (§4) という DLNA 標準型の構成である。DIDL 側の DTCP 情報として torneplus には `DTCP1HOST=`、`DTCP1PORT=`、`DTCP1RAPORT=`、`DTCPDevID`、`replaceDtcp1Info` の文字列と、DLNA プロファイル名 `DTCP_AVC_TS_JP_AAC_T`、`DTCP_AVC_TS_BP_720p/360p/180p_30_AAC_T`、`DTCP_AVC_MP4_BP_VGA_30_AAC` がある (AKE の接続先ホスト/ポートを転送メタデータから得る DTCP-IP の標準的な形と整合する)。

このほか torneplus には `http://127.0.0.1:%u/nasne_home/index_mobile.html` という URL テンプレートがある。`nasne_home` は nasne 自身の Web UI のパスで、localhost 形式の用途 (内蔵ブラウザ部品向けのプロキシ等) は文字列だけでは決まらない (未確定)。

### 3.4 ウェブビデオ (ポート 58890)

PvrBgApp には `http://%s:58890/web/video/PvrAll/pvr?id=%s` という URL テンプレートが 1 件ある。ブラウザ/WebView 向けのプログレッシブ再生 (いわゆるウェブビデオ) 用の経路とみられる (解釈)。主経路 (§3.3 + §4) とは別の、軽量な再生経路の存在を示す。

## 4. DTCP-IP クライアント実装

### 4.1 PvrBgApp: Sony DTCP-IP Middleware「DEWEY」

PvrBgApp の文字列に **`[Sony DTCP-IP Middleware DEWEY Ver. %s]`** というバナーがあり、Sony の DTCP-IP ミドルウェア (名称 DEWEY) が同梱されている。C++ の RTTI から復元できるクラス構成 (抜粋):

- **Sink (受信) 側の中核**: `SdiSinkAuthentication`、`SdiSinkAuthMgr`、`SdiSinkAuthThread`、`SdiSinkContKeyConf` (コンテンツ鍵確認)、`SdiSinkRAManagement` (リモートアクセス管理)、`SdiSinkAkeProtocolTimerThread`。Source 側のリスナ IF (`ISdiSourceAuthMgrListener`) もコンパイルされているが、クライアントとしての実働は Sink 側。
- **AKE プロトコルのメッセージクラス**: `SdiReqCHALL` / `SdiRespCHALL` (チャレンジ)、`SdiReqEXKEY` / `SdiRespEXKEY` (交換鍵)、`SdiReqRESP` / `SdiRespRESP` / `SdiReqRESP2` / `SdiRespRESP2` (レスポンス)、`SdiReqCAPA_REQ` / `SdiRespCAPA_REQ` / `SdiReqCAPA_EX` / `SdiRespCAPA_EX` (能力交換)、`SdiReqMV_CKC` / `SdiRespMV_CKC` / `SdiRespCKC` (鍵確認、MV = Move)、`SdiRespSRM` (System Renewability Message)、`SdiReqCANCEL` / `SdiRespCANCEL`、`SdiReqRTT_TEST` / `SdiReqRTT_SETUP` / `SdiRespRTT_READY` (往復時間計測)、`SdiTtlCheck` (TTL チェック)、`SdiDevCert` (デバイス証明書)、`SdiAuthCapa` / `SdiAuthInfo`、`SdiDtcpCmdNegotiator`、`SdiAkeCmdSender`、`SdiAvcCmdSender`、`SdiDtcpSocket` / `SdiTcpSocket`、`SdiTrsDevice`。
- **鍵管理の公開 API は 3 関数だけ**がフレームワークの定義済み外部シンボルとして存在する: `PvrDtcpIpKeyManagerInitialize`、`PvrDtcpIpKeyManagerFinalize`、`PvrDtcpIpSetTrustedTimeFunc`。本体 (torneplus) はこのうち Initialize と SetTrustedTimeFunc を import して起動時に鍵マネージャを初期化する (§2)。「TrustedTime」の注入があるのは、DTCP の証明書/SRM の時刻検証を外部時刻に委ねる設計のためと読める (解釈)。
- DTCP-IP の HTTP 拡張ヘッダとして `Range.dtcp.com`、`Content-Range.dtcp.com`、`BLKMove.dtcp.com`、`RemoteAccess.dtcp.com` の文字列がある (dtcp.com 名前空間を使う DTCP-IP 標準のベンダヘッダ群)。
- PvrBgApp は CommonCrypto (`CCCrypt`、`CCCryptorCreate/Update/Final`、`CCKeyDerivationPBKDF`、`CC_SHA256`) と Security (`SecKeyEncrypt`)、SecureTransport (`SSLCreateContext` ほか) を import しており、**AKE の暗号処理は CommonCrypto 経由でこのプロセス (アプリ) 内で実行される**ことがリンク関係から分かる (事実)。

### 4.2 AVBase: 独立した CDtcpIp スタック

AVBase には DLNA プレイヤ側のクラス群がある: `CDlnaClient`、`CDlnaClientIf`、`CDlnaClientTask`、`CDlnaClientHttpWrapper`、`CDlnaClientNetworkWrapper`、`CDlnaClientDlfWrapper`、`CDlnaClientDtcpIpUtilityWrapper`、そして DTCP-IP 担当の **`CDtcpIpAuth`、`CDtcpIpHttp`、`CDtcpIpMemory`、`CDtcpIpStreaming`、`CDtcpIpWrapperImpl`** (メソッド側の痕跡として `ActivateDtcpIp`、`CheckActivationDtcpIp`、`PrepareDtcpIp`、`LoadDtcpIpUtility` / `UnloadDtcpIpUtility`)。AVBase も `CCCrypt` と `SSLCreateContext` を import する。

重要なのは §2 のとおり **AVBase は PvrBgApp の `PvrDtcpIp*` シンボルを import していない**点で、リンク関係の上では、再生プレイヤ側 (AVBase) の DTCP-IP スタックと、PVR/リモート側 (PvrBgApp の DEWEY) は独立している。両者の使い分け (例: ローカル再生とリモート再生で別スタック) や、内部で同じコードを静的に取り込んでいるかは、文字列とリンク関係だけでは決まらない (未確定)。

### 4.3 クライアント側の鍵の扱い (設計の読み)

事実として確定できるのは次の範囲である。

- クライアントは DTCP-IP の **Sink として完全な AKE を自前実装**しており、デバイス証明書 (`SdiDevCert`)、交換鍵 (EXKEY)、コンテンツ鍵確認 (CKC) を含む。AKE の暗号は CommonCrypto でアプリプロセス内で処理される。すなわち **DTCP-IP 配信については、復号に必要な鍵材料 (交換鍵・コンテンツ鍵) がクライアントのメモリ上に現れる設計**である。
- ただしこれは **配信 (DTCP-IP) の鍵**であって、保存 `.dat` の暗号化鍵ではない。保存鍵は nasne 側 XCode ファームウェアが解決する ([02](02_dat_encryption_model.md) のモデル) もので、クライアント側のどこにも保存鍵・CW トークンの痕跡はない (文字列・シンボルの範囲での陰性)。

## 5. リモート視聴 (Telepathy)

自宅外からのリモート視聴は Sony の **Telepathy** 基盤 (PS 系のリモートプレイと同系統) の上で行われる。

- torneplus の文字列に `http://tp-resolver.ndmdhs.com/trs/` (Telepathy Resolver Service) と `ipv4only.tpy.ndmdhs.com` があり、接続先 nasne の解決を Sony 側サービスに問い合わせる。UPnP 側にも `urn:schemas-sony-com:device:TelepathyDevice` / `urn:schemas-sony-com:service:X_Telepathy` の URN があり、バンドルには `TelepathyDeviceConfig.bin` が同梱されている。P2P 輸送は Jingle/ICE 系 (`urn:telepathy:jingle:transports:ice-udp:1`)。
- リモート経路では DLNA/DTCP が P2P トンネル越しにプロキシされる設計の痕跡がある: 起動時設定キー `Boot.Device.DlnaProxyClientStream*` (AKE 用のパケット数・バッファサイズ等)、計測ログ文字列 `::TIME:: P2P_SETUP DTCP_LISTEN` / `DTCP_PING` / `DTCP_PING_OR_LISTEN`、`telepathy.p2p.dlnaproxy.ake` (解釈: リモートでも AKE はエンドツーエンドでクライアント⇔nasne 間に行われ、中継はトンネルとして働く)。
- Telepathy 基盤自体のセキュリティとして、torneplus には `TpSecCryptoEnc`、`FillHttpHMAC` / `VerifyHttpHMAC` / `GetHttpHMACParams`、**`HttpRPCGetContentKey` / `OnContentKeyRequest` (appid・port・contextID を引数に取るログ文字列群)**、`TpSerializeContentKeyArgs` (isEncrypt / destroyAuth / noEncData フラグ) がある。これらは Telepathy アプリ間メッセージングの暗号化のためのコンテンツキー受け渡し RPC であり、§4 の DTCP-IP の鍵とは別系統である (Tp = Telepathy のシンボル体系と引数の形からの解釈)。
- アカウント連携には PSN の OAuth 2.0 エンドポイント (`auth.api.sonyentertainmentnetwork.com` 系、`auth.api.e1-np...`、`auth.api.sp-int...` (検証環境)) が組み込まれている。リモート視聴の前提としてのアカウント認証用 (参考情報)。

## 6. 暗号まわりの総括

- **使用ライブラリ**: CommonCrypto (AES/ハッシュ/PBKDF) と Security フレームワーク (SecKeyEncrypt = RSA 公開鍵暗号、キーチェーン属性 `kSecAttr*` の使用痕跡)、SecureTransport (TLS、libcurl 7.48.0 のバックエンドおよび GCDAsyncSocket の TLS)。OpenSSL / BoringSSL / mbedTLS の文字列は無い (陰性)。
- **定数テーブルの走査結果** (事実): AES **逆** S-box のバイト列は 3 バイナリ全てに存在する (torneplus @ファイルオフセット 0x8d7a28、AVBase @0x252928、PvrBgApp @0x357f20)。AES **正** S-box の先頭 8 バイト列は 3 バイナリとも存在しない (生成しているのか配置の形が違うのかは未確定)。SHA-256 K 初期値 (LE 配置) は torneplus (@0x8d5900) と PvrBgApp (@0x355df8) に、SHA-1/MD5 初期値の並びは torneplus (@0x884c20) と PvrBgApp (@0x35df20/@0x35df30) に存在する。**Blowfish の P-array は 3 バイナリとも存在しない** (nasne 側 SPI 復号で使われる Blowfish はクライアントには無い、という当然の陰性)。
- パスワード由来の鍵導出の痕跡として `AESKeyForPassword:salt:` / `AESKeyWithPassword:salt:`、`AESKeyRandomlyGenerated`、`AES128crypte:key:iv:data:` という ObjC メソッド名が torneplus と PvrBgApp にある (用途は未同定。PIN やローカル保存データの暗号化等が候補だが決め手は無い)。
- 鍵らしき固定の埋め込み値 (長い16進文字列等) は文字列抽出の範囲では目立つものは無かった。ただしこれは文字列として現れる形に限った陰性で、バイナリデータとして埋め込まれた鍵の有無は本解析では判定していない。

## 7. 既存の調査 (オラクル方式) との関係

事実:

1. torne mobile は nasne の通常再生 (DTCP-IP) とリモート視聴 (Telepathy + プロキシ) の両方で **正規の Sink** として動作し、AKE と復号はクライアント側プロセス内で完結する。したがって正規クライアントの再生では、平文 TS は iPhone 側プレイヤ (AVBase → AVFoundation) に渡る。
2. クライアントが nasne 側の DTCP-IP 状態を WebAPI (`dtcpipClientListGet` / `dtcpipClientStop`) で操作できること、`CanBecomeDtcpipClient` のような可否判定を持つことが、DTCP-IP セッション管理の実装詳細として新たに分かった。
3. 保存 `.dat` の復号に関する鍵・トークン・手順はクライアントに存在しない (§4.3)。本解析は [02](02_dat_encryption_model.md) の「保存鍵はファームウェア側解決」というモデルと矛盾しない。

解釈 (含意):

- 本線のオラクル方式 ([03](03_playback_path_and_oracle.md)) は nasne 実機側で平文を取り出す設計であり、クライアント解析はその代替にはならない (保存復号はクライアントでは起きない)。一方で、DTCP-IP の AKE を自前クライアントとして実装・検証する場面では、本書のプロトコル痕跡 (AKE コマンド構成、RTT/TTL チェック、dtcp.com ヘッダ、DTCP1HOST/PORT の受け渡し) が一次資料になる。
- 「別の正規 Sink を観測する」という方向では、torne mobile の再生中に iPhone 側で平文が得られる構造自体は E3 (nasne 側 Tp 経路の観測) と対をなす観測点になる。ただし iOS 側の動的観測は脱獄等の別途の環境が要り、本解析の範囲外である。

## 8. 未確定事項

- WebAPI のベース URL の組み立て方 (ポート 64210 の文字列が無く、ポート・認証トークンの確定方法が文字列からは追えない)。`config/PINVerify` の具体的な認証手順も未同定。
- AVBase の CDtcpIp スタックと PvrBgApp の DEWEY の使い分け・重複の理由。
- DEWEY のバージョン文字列の実値 (書式文字列のみで、実値はリソース側か実行時に決まる)。
- `initialContent.db` の形式 (平文 SQLite でないことだけ確定)。
- AES 正 S-box がバイト列として存在しない理由 (実行時生成か、テーブル配置の形の問題か)。
- 58890 ウェブビデオ経路の保護の有無 (平文 HTTP なのか、別途の保護があるのかは文字列からは決まらない)。
- `DTCP1RAPORT` (リモートアクセス用ポート) を使った、リモート時の AKE 接続先の決定手順の詳細。
