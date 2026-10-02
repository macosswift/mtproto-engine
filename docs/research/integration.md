# MtProtoKit integration surface and the engine seam

Research note for the Rust MTProto engine (`third-party/mtproto-engine`). It maps every place where
code outside MtProtoKit touches MtProtoKit, spells out the behaviour TelegramCore relies on, and
proposes where an engine switch (MtProtoKit vs Rust) should live so that switching engines from
developer settings never logs the user out.

Snapshot: macOS app repo `beta` @ 502236a04, telegram-ios submodule @ f9fb8aa01e (2026-10-01).

## Path prefixes used below

| Prefix | Absolute location |
|---|---|
| `TC/` | `submodules/telegram-ios/submodules/TelegramCore/Sources/` |
| `MPK/` | `submodules/telegram-ios/submodules/MtProtoKit/` (`MPK/Sources/*.m`, `MPK/PublicHeaders/MtProtoKit/*.h`) |
| `IOS/` | `submodules/telegram-ios/submodules/` (other telegram-ios modules) |
| `IOSAPP/` | `submodules/telegram-ios/Telegram/` (iOS app extensions) |
| `MAC/` | macOS app repo root (`Telegram-Mac/`, `packages/`, `TelegramShare/`) |

All line numbers are 1-based and refer to the snapshot above.

## TL;DR

1. The real coupling is narrow. Only four TelegramCore types own MtProtoKit runtime objects:
   `Network` (`TC/Network/Network.swift`), `Download` (`TC/Network/Download.swift`),
   `UpdateMessageService` and `UnauthorizedUpdateMessageService` (`TC/State/UpdateMessageService.swift`,
   `TC/State/UnauthorizedAccountStateManager.swift`). Everything else talks to `Network` /
   `Download` / `MultiplexedRequestManager` in Swift terms.
2. 185 TelegramCore files `import MtProtoKit`, but almost all of them only need `MTRpcError` (the error
   type of every `Network.request` signal, about 1,020 call sites) or the pure crypto functions.
   Keep `MTRpcError` as the lingua franca; do not try to replace it.
3. Persistence is entirely MTContext-owned: NSKeyedArchiver blobs in the Postbox `KeychainTable`
   under keys `"<group>:<key>"` (`persistent:datacenterAuthInfoById`, `persistent:authTokenById`,
   `temp:globalTimeDifference`, ...). MTContext writes whole dictionaries (last writer wins), and
   `makeExclusiveKeychain` disables any older `Keychain` for the same account. So **there must be
   exactly one writer**: MTContext.
4. Recommended seam: a Swift `NetworkEngineSession` protocol (plus a small `NetworkEngine` factory)
   below `Network`/`Download`, replacing `MTProto + MTRequestMessageService`. **MTContext stays the
   configuration and persistence source of truth for both engines.** The Rust engine reads keys,
   addresses, the API environment and time from MTContext and writes back only through MTContext's
   public mutators (`updateAuthInfoForDatacenterWithId`, `setGlobalTimeDifference`, ...). That makes
   switching lossless in both directions by construction.
5. Read the engine choice inside `initializedNetwork(...)` (`TC/Network/Network.swift:467`), which
   already receives `NetworkSettings`, `ProxySettings` and `AppConfiguration` from all 5 call sites.
   Inject the Rust factory through `NetworkInitializationArguments` so TelegramCore and the share
   extension do not link the Rust library. Apply the switch at Network creation (next launch or
   account reload), not live.
6. The #1 risk is a **false 401**. Any 401 other than `SESSION_PASSWORD_NEEDED` on the main session
   calls `Network.loggedOut`, which makes the app call `logoutFromAccount`, and then
   `cleanupAccount` sends `auth.logOut` and deletes the account record. This cannot be undone.
   `AUTH_KEY_PERM_EMPTY` must never reach that path (MtProtoKit swallows it in
   `MPK/Sources/MTProto.m:2027-2043`).
7. The #2 risk is `AUTH_KEY_DUPLICATED` (406), returned when the same auth key is used concurrently
   from two IPs. Two engines (or IPv4 vs IPv6, or proxy vs direct) must never hold live connections
   with the same key at the same time.

---

## 1. Symbol inventory

### 1.0 Who imports MtProtoKit

| Location | Files importing | What they actually use |
|---|---|---|
| `TC/` (TelegramCore) | 185 `.swift` | 50 files name `MTRpcError` explicitly; the rest import for `Signal<_, MTRpcError>` inference, crypto or nothing. Runtime objects only in `Network.swift`, `Download.swift`, `UpdateMessageService.swift`, `UnauthorizedAccountStateManager.swift`, `ProxyServersStatuses.swift`, `NetworkFrameworkTcpConnectionInterface.swift`, `Serialization.swift`, `Account.swift` |
| `IOS/WebProxyTransport` | 1 src + 1 test | `MTTcpConnectionInterface(Delegate)`, `MTNetworkUsageCalculationInfo` |
| `IOS/NetworkLogging` | `NetworkLogging.m` | `MTLogSetLoggingFunction`, `MTLogSetShortLoggingFunction`, `MTLogSetEnabled` |
| `IOS/CloudData` | `CloudData.swift` | `MTBackupDatacenterData`, `MTIPDataDecode` (iOS only) |
| `IOS/ShareItems` | `ShareItems.swift`, `TGItemProviderSignals.m`, `TGShareLocationSignals.m` | `MTSignal`/`MTSubscriber`/`MTBlockDisposable`, `MTHttpRequestOperation` (pure utilities) |
| `IOS/SettingsUI`, `IOS/QrCodeUI`, `IOS/UrlHandling`, `IOS/TelegramUI/Sources/OpenUrl.swift` | 5 | `MTProxySecret` parsing only |
| `IOS/DebugSettingsUI`, `IOS/LegacyUI`, `IOS/AuthorizationUI` | 3 | import only; no MtProtoKit symbol (DebugController writes `NetworkSettings` via TelegramCore) |
| `MAC/Telegram-Mac` | `app/AppDelegate.swift`, `utils/InAppLinks.swift` | `MTLogSetEnabled` |
| `MAC/packages` | `ProxyUI`, `ProxyUtils`, `TelegramLinks`, `ChatExportUI`, `SettingsUI/DeveloperViewController` | `MTProxySecret`, `MTSocksProxySettings`, `MTProxyConnectivity`, `MTRpcError.errorDescription`, `MTLogSetEnabled` |
| `MAC/packages/TelegramUtils` | `ManageSharedAccountInfo.swift` (no import; via `network.context`) | `MTContext.knownDatacenterIds/authInfoForDatacenter/chooseTransportScheme...` |

Unused upstream stubs exist in MtProtoKit: `MTProtoEngine`, `MTProtoInstance`,
`MTProtoPersistenceInterface` (`MPK/Sources/MTProtoEngine.m`, `MTProtoInstance.m`). Nothing outside
MtProtoKit references them. They hint at an upstream plan for a pluggable engine with a
`get/set(NSData)` persistence interface; they carry no behaviour today.

### 1.a Session / request path

| Symbol | Call site | Used for |
|---|---|---|
| `MTProto(context:datacenterId:usageCalculationInfo:requiredAuthToken:authTokenMasterDatacenterId:)` | `TC/Network/Network.swift:633` | Main session to the master DC (no token, master=0) |
| | `TC/Network/Download.swift:64` | Worker session per DC; `requiredAuthToken = dcId` and `authTokenMasterDatacenterId = master` when `!isCdn && dc != master` (`Download.swift:57-62`) |
| `MTProto.useTempAuthKeys` | `Network.swift:634` (= `context.useTempAuthKeys`, always `true`, `Network.swift:507`) | PFS temp keys on main session |
| | `Download.swift:70` (`context.useTempAuthKeys && !isCdn`) | Temp keys on workers except CDN |
| `MTProto.checkForProxyConnectionIssues` | `Network.swift:635` | Produces `proxyHasConnectionIssues` in connection state |
| `MTProto.cdn`, `.media`, `.getLogPrefix` | `Download.swift:66-71` | CDN mode (persistent CDN key, CDN RSA keys), media address selection and ephemeralMedia key, log prefix |
| `MTProto.delegate` (`MTProtoDelegate`) | `Network.swift:660`, delegate class `Network.swift:95-158` | Connection status flags (see 2.7) |
| `MTProto.add(_:)` (= `addMessageService:`) | `Network.swift:661`, `Download.swift:78` | Attach `MTRequestMessageService` |
| | `TC/State/AccountStateManager.swift:443` | Attach `UpdateMessageService` (once, on first `reset()`) |
| | `TC/State/UnauthorizedAccountStateManager.swift:110` | Attach `UnauthorizedUpdateMessageService` |
| `MTProto.remove(_:)`, `.stop()`, `.finalizeSession()` | `Download.swift:95-97` (deinit) | Worker teardown (`finalizeSession` is a no-op, `MTProto.m:395`) |
| `MTProto.pause()` / `.resume()` | `Network.swift:983-993`, `Download.swift:81-91` | Driven by `shouldKeepConnection` (see 2.8) |
| `MTProto.datacenterId` | `TC/Account/Account.swift:90`, `:105`, `:229` | `UnauthorizedAccount.masterDatacenterId`, DC migration check |
| `MTProto.context` | `Network.swift:1139` | `getAuthKeyId()` |
| `MTProto.requiredAuthToken`, `.authTokenMasterDatacenterId` | `Download.swift:103` | Re-request token transfer after a 401 on a foreign DC |
| `MTRequestMessageService(context:)` | `Network.swift:639`, `Download.swift:72` | Request scheduler per session |
| `MTRequestMessageService.delegate` (`MTRequestMessageServiceDelegate`) | `Network.swift:816`, `:957`; `Download.swift:40`, `:77` | `requestMessageServiceAuthorizationRequired` (`Network.swift:1067-1070`, `Download.swift:101-104`) |
| `MTRequestMessageService.forceBackgroundRequests` | `Download.swift:73` | Wrap every worker request in `invokeWithoutUpdates` |
| `MTRequestMessageService.didReceiveSoftAuthResetError` | `Network.swift:906-908` | 406 errors, forwarded to `Account.postSmallLogIfNeeded` (`Account.swift:1360-1362`) |
| `MTRequestMessageService.add(_:)`, `.removeRequest(byInternalId:)` | `Network.swift:1218-1222`, `:1278-1282`; `Download.swift:182-186`, `:242-246`, `:298-302`, `:351-355`, `:406-410`, `:462-466` | Submit and cancel |
| `MTRequest()` and its properties `setPayload(_:metadata:shortMetadata:responseParser:)`, `dependsOnPasswordEntry`, `needsTimeoutTimer`, `expectedResponseSize`, `shouldContinueExecutionWithErrorContext`, `acknowledgementReceived`, `progressUpdated`, `completed`, `shouldDependOnRequest`, `internalId` | `Network.swift:1157-1216`, `:1229-1276`; `Download.swift:135-180`, `:198-240`, `:252-296`, `:309-349`, `:361-404`, `:417-460` | The 7 request builders; see 2.2 |
| `MTRequestErrorContext.floodWaitSeconds`, `.floodWaitErrorText`, `.internalServerErrorCount` | same blocks (`Network.swift:1168-1179`, `Download.swift:384`, `:440`) | Flood wait policy, `failOnServerErrors` |
| `MTRequestResponseInfo.timestamp`, `.networkType`, `.duration` | `Download.swift:390-401`, `:446-456` | `NetworkResponseInfo` for download stats |
| `MTRpcError` (type and `init(errorCode:errorDescription:)`) | `Network.swift:1154`, `:1202`, `:1226`, `:1262`; `Download.swift:134`, `:235`, `:291`, `:344`, `:399`; `TC/Network/MultiplexedRequestManager.swift:40`, `:160`, `:391-431`; plus about 1,020 `request` sites | Error type everywhere; see 2.4 |
| `MTMessageService` (protocol) | `TC/State/UpdateMessageService.swift:7`, `TC/State/UnauthorizedAccountStateManager.swift:7` | Update receivers. Implemented callbacks: `mtProtoDidChangeSession` (`:25`), `mtProtoServerDidChangeSession` (`:29`), `mtProto(_:receivedMessage:authInfoSelector:networkType:)` (`:37`). `mtProtoWillAdd(_:)` (`:21`) does not match the ObjC selector `mtProtoWillAddService:` and its `mtProto` back-pointer is never read |
| `MTIncomingMessage.body` | `UpdateMessageService.swift:38`, `UnauthorizedAccountStateManager.swift:30` | `BoxedMessage` from `Serialization.parseMessage` |
| `MTDatacenterAuthInfoSelector` | same callbacks; `Network.swift:1144` (`.persistent`); `Account.swift:206-207` | Key selector (persistent / ephemeralMain / ephemeralMedia) |
| `MTSerialization` (protocol) | `TC/State/Serialization.swift:261-338` | Layer (`:262-264`, currently **230**), `parseMessage` (`:266-271`), `exportAuthorization` (`:273-288`), `importAuthorization` (`:290-292`), `requestDatacenterAddress` (`help.getConfig`, `:294-324`), `requestNoop` (`help.test`, `:326-337`) |
| `MTExportedAuthorizationData`, `MTExportAuthorizationResponseParser`, `MTDatacenterAddressListData`, `MTRequestDatacenterAddressListParser`, `MTRequestNoopParser` | `Serialization.swift:273-337` | Data carriers for the above |

### 1.b Context / config / persistence

| Symbol | Call site | Used for |
|---|---|---|
| `MTContext(serialization:encryptionProvider:apiEnvironment:isTestingEnvironment:useTempAuthKeys:)` | `TC/Network/Network.swift:509` | One context per `Network` (per account, per process) |
| `MTContext.keychain =` | `Network.swift:563` | Loads all persisted state asynchronously on `contextQueue` (`MPK/Sources/MTContext.m:444-527`) |
| `MTContext.keychain` (read) | `Account.swift:915`, `TC/Authorization.swift:1400`, `TC/TelegramEngine/Auth/TwoStepVerification.swift:56,146,175,247,276,366`, `TC/TelegramEngine/Auth/TelegramEngineAuth.swift:116`, `TC/Statistics/StarsRevenueStatistics.swift:415`, `TC/TelegramEngine/Payments/StarGifts.swift:3807`, `TC/TelegramEngine/Messages/RequestMessageActionCallback.swift:156`, `TC/TelegramEngine/Peers/ChannelOwnershipTransfer.swift:101`, `TC/TelegramEngine/Wallet/WalletBackup.swift:86`, `TC/SecretChats/SecretChatEncryptionConfig.swift:20,25` | Passed to `passwordKDF`/`MTCheckMod`/`MTCheckIsSafePrime` purely as the `primes:` result cache |
| `MTContext.makeTcpConnectionInterface` | `Network.swift:523-525`, `:530`, `:536-538`, `:1017-1021` | Swap TCP implementation (NetworkFramework, WebProxy carrier) |
| `MTContext.setSeedAddressSetForDatacenterWithId` + `MTDatacenterAddressSet` + `MTDatacenterAddress` | `Network.swift:541-561` | Hard-coded seed IPs (test: DC1-3, prod: DC1-5 incl. IPv6) |
| `MTContext.setDiscoverBackupAddressListSignal` + `MTBackupAddressSignals.fetchBackupIps` | `Network.swift:590-591` | Backup DC discovery (DoH plus optional CloudData source); not for `supplementary` |
| `MTContext.setExternalRequestVerification` / `setExternalRecaptchaRequestVerification` | `Network.swift:592-626` | `APNS_VERIFY_CHECK_` / `RECAPTCHA_CHECK_` resolution (15 s timeout, `"APNS_PUSH_TIMEOUT"`, `"RECAPTCHA_TIMEOUT"`) |
| `MTContext.add(_:)` (= `addChangeListener:`) + `MTContextChangeListener` | `Network.swift:711-761`, `:956` (`NetworkHelper`) | `fetchContextDatacenterPublicKeys` (CDN RSA keys via `help.getCdnConfig`, `Network.swift:911-942`), `isContextNetworkAccessAllowed` (= `shouldKeepConnection`, `:943-948`), `contextApiEnvironmentUpdated` (proxy id, `:753-756`), `contextLoggedOut` (`:758-760`, `:951-954`) |
| `MTContext.apiEnvironment` / `updateApiEnvironment` | `Network.swift:688-701` (systemCode), `:890`, `:1025-1039` (proxy); `TC/Settings/NetworkSettings.swift:36-38`; `TC/TelegramEngine/Localization/Localizations.swift:152` | Live API environment changes |
| `MTApiEnvironment(deviceModelName:)` and `apiId`, `langPack`, `layer`, `disableUpdates`, `withUpdatedLangPackCode`, `withUpdatedSocksProxySettings`, `withUpdatedNetworkSettings`, `accessHostOverride`, `withUpdatedSystemCode`, `systemCode`, `socksProxySettings` | `Network.swift:475-505`, `:688-701`, `:754`, `:890`, `:1026-1035` | Builds `initConnection` parameters; `disableUpdates = supplementary` (`:480`) |
| `MTSocksProxySettings(ip:port:username:password:secret:[webProxy:])` | `TC/Settings/ProxySettings.swift:22-31`; `MAC/packages/ProxyUI/Sources/ProxyUI/ProxyAlert.swift:122-128` | SOCKS5 / MTProxy / WEB proxy description |
| `MTNetworkSettings(reducedBackupDiscoveryTimeout:)` | `TC/Settings/NetworkSettings.swift:14-16` | Discovery tuning |
| `MTProxySecret.parse/parseData/serialize/serializeToString` | `IOS/SettingsUI/Sources/Data and Storage/ProxyServerSettingsController.swift:240,306,348`; `.../ProxyListSettingsController.swift:551`; `IOS/QrCodeUI/Sources/QrCodeScreen.swift:501`; `IOS/UrlHandling/Sources/UrlHandling.swift:248`; `IOS/TelegramUI/Sources/OpenUrl.swift:35`; `MAC/packages/ProxyUI/Sources/ProxyUI/ProxyListController.swift:38,51`, `ProxyAlert.swift:46`; `MAC/packages/TelegramLinks/Sources/TelegramLinks/LinkParsing.swift:248,414,827`, `URLHelpers.swift:80` | Pure parsing of proxy secrets (engine-independent) |
| `MTProxyConnectivity.pingProxy(with:datacenterId:settings:)` + `MTProxyConnectivityStatus` | `TC/Network/ProxyServersStatuses.swift:16-38` (internal `network.context` at `:68`); `MAC/packages/ProxyUI/Sources/ProxyUI/ProxyAlert.swift:134-135` | Proxy list reachability and RTT; opens its own sockets |
| `MTContext.globalTime()` / `globalTimeDifference()` / `performBatchUpdates` | `Network.swift:1049-1065`, `:1107-1109`; `TC/PendingMessages/EnqueueMessage.swift:593`, `:913`; `TC/PendingMessages/PendingPeerMediaUploadManager.swift:108`; `TC/State/HistoryViewStateValidation.swift:374`, `:403`; `TC/TelegramEngine/Messages/EphemeralMessages.swift:204`; `IOS/TelegramUI/Sources/ChatControllerNode.swift:612` | Server-corrected clock (message dates, TTLs, validation) |
| `Network.globalTime` / `globalTimeDifference` / `getApproximateRemoteTimestamp` (wrappers) | about 15 sites incl. `MAC/Telegram-Mac/account/AccountContext.swift:809-816`, `MAC/packages/SelectPeersUI/.../SelectPeersController.swift:251-252`, `MAC/packages/TelegramContext/.../PeerChannelMemberCategoriesContextsManager.swift:292`, `TC/State/ManagedAutoremoveMessageOperations.swift:45,141`, `IOS/WalletContext/Sources/WalletTonConnect.swift:273,854` | Same, via `Network` |
| `MTContext.addAddressForDatacenter`, `transportSchemesForDatacenter`, `updateTransportSchemeForDatacenter`, `MTTransportScheme(transport: MTTcpTransport.self, ...)` | `Network.swift:1111-1136` (`mergeBackupDatacenterAddress`, called from `IOS/TelegramUI/Sources/SharedNotificationManager.swift:409` on a push with a new DC address) | Push-delivered DC addresses |
| `MTContext.updateAddressSetForDatacenter(withId:addressSet:forceUpdateSchemes:)` | `TC/State/ManagedConfigurationUpdates.swift:19-36` | `help.getConfig` DC options |
| `MTContext.authInfoForDatacenter(withId:selector:)` | `Network.swift:1144` (`getAuthKeyId`); `Account.swift:206`; `MAC/packages/TelegramUtils/Sources/TelegramUtils/ManageSharedAccountInfo.swift:25` | Persistent key id (TON Connect binding check `IOS/WalletContext/Sources/WalletTonConnect.swift:203-210`, passkey DC switch `TC/Authorization.swift:1226`), shared account export |
| `MTContext.authInfoForDatacenter(withIdRequired:isCdn:selector:allowUnboundEphemeralKeys:)` + `beginExplicitBackupAddressDiscovery()` | `Account.swift:198-211` | Pre-generate temp keys for DC 1,2,4 (prod) or 3 (test) while unauthorized |
| `MTContext.knownDatacenterIds`, `chooseTransportSchemeForConnection`, `transportSchemesForDatacenter` | `ManageSharedAccountInfo.swift:23-30` | macOS writes `accounts-shared-data` with auth keys (`:72-80`) |
| `MTContext.contextQueue()` | `Network.swift:1142` | Read auth info on the context queue |
| `MTContext.perform(objCTry:)` | `Network.swift:1342` | Wrap `NSKeyedArchiver` in `@try` |
| `MTContext.updateAuthTokenForDatacenter` / `authTokenForDatacenter(withIdRequired:...)` | `Download.swift:102-103` | Token re-transfer after 401 on foreign DC |
| `MTKeychain` (protocol) implemented by `Keychain` | `Network.swift:1327-1382` | Postbox-backed storage, see 4 |
| `MTKeychain` as parameter type | `Account.swift:666`, `:682`, `:772` | Prime cache for SRP |
| `MTDeprecated.unarchiveDeprecated(with:)` | `Network.swift:22-24` (`legacy_unarchiveDeprecated`), `:1355`, `:1370`; `Account.swift:1128` | Decoding keychain archives |
| `MTDatacenterAuthInfo(authKey:authKeyId:validUntilTimestamp:saltSet:authKeyAttributes:)` | `Account.swift:302-321` (backup restore) | Writes `persistent:datacenterAuthInfoById` directly through `transaction.setKeychainEntry` |
| `MTDatacenterAuthInfo.authKey` / `.authKeyId` | `Account.swift:1120-1176` (`accountBackupData`) | Reads the same entry |

### 1.c Pure crypto and utility functions (engine-independent, keep linking MtProtoKit for them)

| Symbol | Call sites | Purpose |
|---|---|---|
| `MTSha1` | `TC/SecretChats/SecretChatEncryption.swift:19,30,40,50,272`; `TC/SecretChats/SecretChatRekeySession.swift:62`; `TC/SecretChats/UpdateSecretChat.swift:44`; `TC/State/ManagedSecretChatOutgoingOperations.swift:241,356`; `TC/State/CallSessionManager.swift:1112,1389` | Secret chat / call key fingerprints, MTProto 1.0 secret chat layer |
| `MTSubdataSha1` | `SecretChatEncryption.swift:168` | msg_key check |
| `MTSha256` | `SecretChatEncryption.swift:100,106,224,347`; `CallSessionManager.swift:1120,1397,1401,1695`; `TC/Network/FetchV2.swift:510`; `TC/Network/MultipartFetch.swift:456` | E2E keys, CDN hash check |
| `MTAesEncrypt` / `MTAesDecrypt` | `SecretChatEncryption.swift:148,195,294,357`; `Account.swift:1086` (push payload) | AES-IGE |
| `MTAesCtrDecrypt` | `FetchV2.swift:827`; `MultipartFetch.swift:441` | CDN file AES-CTR |
| `MTAesDecryptBytesInplaceAndModifyIv` / `MTAesEncryptBytesInplaceAndModifyIv` | `FetchV2.swift:190`; `MultipartFetch.swift:39`; `TC/Network/MultipartUpload.swift:66` | Encrypted file parts (secret chats) |
| `MTExp`, `MTModSub`, `MTModMul`, `MTMul`, `MTAdd`, `MTIsZero` | `Account.swift:726,809,812,824,828,834,835`; `ManagedSecretChatOutgoingOperations.swift:225,231,304,340,346`; `CallSessionManager.swift:1102,1379,1618,1690`; `TC/TelegramEngine/Peers/CreateSecretChat.swift:28`; `SecretChatRekeySession.swift:52`; `UpdateSecretChat.swift:34` | SRP and DH |
| `MTCheckIsSafeGAOrB`, `MTCheckIsSafeG`, `MTCheckIsSafeB`, `MTCheckIsSafePrime`, `MTCheckMod` | `Account.swift:667-679,804,830`; `ManagedSecretChatOutgoingOperations.swift:201,227,306,334,342`; `CallSessionManager.swift:1099,1375,1620,1691`; `CreateSecretChat.swift:30`; `SecretChatRekeySession.swift:48`; `UpdateSecretChat.swift:27`; `SecretChatEncryptionConfig.swift:15,20,25` | DH parameter validation (uses keychain group `primes`) |
| `MTPBKDF2` | `Account.swift:720,818,879,901` | 2FA password KDF |
| `MTRsaFingerprint` | `Network.swift:931` | CDN public key fingerprints |
| `MTRsaEncryptPKCS1OAEP` | `TC/TelegramEngine/SecureId/GrantSecureIdAccess.swift:326` | Passport |
| `MTIPDataDecode` + `MTBackupDatacenterData` | `IOS/CloudData/Sources/CloudData.swift:117-148` | iCloud backup DC list (iOS) |
| `MTGzip.compress` / `.decompress` | `Download.swift:27` (gzip_packed 0x3072cfa1 upload bodies via `MTOutputStream`, `:29-32`); `TC/TelegramEngine/Calls/RateCall.swift:50`; `TC/State/AccountStateManager.swift:1876,2321`; `TC/Utils/ImageRepresentationsUtils.swift:107` | gzip |
| `MTOutputStream` | `Download.swift:29-32` | Builds `gzip_packed` |
| `MTSignal`, `MTSubscriber`, `MTDisposable`, `MTBlockDisposable` (bridging with SwiftSignalKit) | `Network.swift:564-626`, `:727-751`; `ProxyServersStatuses.swift:18-31`; `TC/Network/FetchHttpResource.swift:12-31`; `Network.swift:355-426`; `IOS/ShareItems/...` | Callbacks across the ObjC boundary |
| `MTHttpRequestOperation` / `MTHttpResponse` | `FetchHttpResource.swift:12-16`; `IOS/ShareItems/Impl/Sources/TGShareLocationSignals.m:221,262` | Plain HTTPS GET |
| `MTLogSetEnabled`, `MTLogSetLoggingFunction`, `MTLogSetShortLoggingFunction` | `IOS/NetworkLogging/Sources/NetworkLogging.m:28-38` (registered by `Network.swift:160-163`, toggled from `TC/Utils/Log.swift:46-100`); `MAC/Telegram-Mac/app/AppDelegate.swift:450,457`; `MAC/Telegram-Mac/utils/InAppLinks.swift:1468`; `MAC/packages/SettingsUI/Sources/SettingsUI/DeveloperViewController.swift:196` | Logging. The Rust engine needs an equivalent log sink into `Logger.shared` |

None of 1.c needs to change for the engine switch. MtProtoKit stays linked as a library.

### 1.d Network accounting / stats

| Symbol | Call site | Used for |
|---|---|---|
| `MTNetworkUsageCalculationInfo(filePath:incomingWWANKey:...)` | `Network.swift:207-215` | Per-category counter slots in `<basePath>/network-stats` |
| | passed at `Network.swift:633` (main, category generic), `:1091` (workers, category from `TelegramMediaResourceFetchTag.statsCategory`), `Download.swift:51,64` | |
| `MTNetworkUsageManager(info:)`, `addIncomingBytes/addOutgoingBytes`, `resetKeys`, `currentStats(forKeys:)` | `Network.swift:274-287` (`updateNetworkUsageStats`, called by `Account.swift:1687` for call traffic), `:289-428` (`networkUsageStats`, read by `MAC/packages/DataUsageUI/Sources/DataUsageUI/NetworkUsageStatsController.swift:312,330`) | Data-usage screen |
| `MTNetworkUsageManagerInterface{WWAN,Other}` | `Network.swift:274-276`; `TC/Network/NetworkFrameworkTcpConnectionInterface.swift:263,354` | Interface bucket |
| `MTTcpConnectionInterface.setUsageCalculationInfo` | `NetworkFrameworkTcpConnectionInterface.swift:101-110`, `:448`; `IOS/WebProxyTransport/Sources/WebProxyTransport.swift:532` (no-op) | Byte accounting at the socket layer |
| `NetworkResponseInfo` (Swift, built from `MTRequestResponseInfo`) | `MultiplexedRequestManager.swift:89-93`; `Download.swift:450-454`; consumed by `TC/Network/NetworkStatsContext.swift` via `MultipartFetch.swift:893` | Download speed stats per DC and network type |

File format of `network-stats`: flat array of little-endian `int64`, slot offset = `key * 8`
(`MPK/Sources/MTNetworkUsageManager.m:12-26`, `:69-97`), with
`key = category * 4 + connection * 2 + direction` (connection 0 = cellular, 1 = wifi; direction
0 = incoming, 1 = outgoing; category 0..7 = generic, image, video, audio, file, call, stickers,
voiceMessages, `Network.swift:175-200`). Slots 80/81 hold reset timestamps (`:202-205`). Writers
do read-modify-write without a file lock; one more writer adds no new class of race.

### 1.e Connection interfaces

| Symbol | Call site | Used for |
|---|---|---|
| `MTTcpConnectionInterface` (protocol, `MPK/PublicHeaders/MtProtoKit/MTContext.h:30-53`) | `TC/Network/NetworkFrameworkTcpConnectionInterface.swift:28` (`@available(iOS 12, macOS 14)`); `IOS/WebProxyTransport/Sources/WebProxyTransport.swift:501` | Pluggable byte stream: `connectToHost:onPort:viaInterface:withTimeout:error:`, `writeData:`, `readDataToLength:withTimeout:tag:`, `disconnect`, `resetDelegate`, `setGetLogPrefix:`, `setUsageCalculationInfo:`, optional `isWebProxyCarrier` |
| `MTTcpConnectionInterfaceDelegate` | `NetworkFrameworkTcpConnectionInterface.swift:48,76,434`; `WebProxyTransport.swift:15,116,507,516` | Callbacks: `connectionInterfaceDidConnect`, `DidReadData:withTag:networkType:`, `DidReadPartialDataOfLength:tag:`, `DidDisconnectWithError:` |
| Factory selection | `Network.swift:511-539` (NetworkFramework if `NetworkSettings.useNetworkFramework` or `useBetaFeatures`; WEB proxy carrier when active server is `.web` and not an app extension), `:1012-1022` (re-select on proxy change) | |

The Rust engine should accept the same kind of injected byte-stream factory (see 5.2), so the WEB
proxy carrier and NWConnection can be reused instead of re-implemented.

---

## 2. Session / request path: the contract TelegramCore relies on

### 2.1 Object graph per account

```
Account / UnauthorizedAccount
 └─ Network  (TC/Network/Network.swift:816)          one per account per process
     ├─ context: MTContext   (public)                 config + persistence + key factory
     ├─ mtProto: MTProto     (main DC, internal)      main session: updates + user requests
     │    ├─ MTRequestMessageService                  request scheduler (delegate = Network)
     │    └─ UpdateMessageService                     added later by AccountStateManager.reset()
     ├─ MultiplexedRequestManager                     media/file pool, own Queue
     │    └─ Download × (≤4 per target × continueInBackground) each with its own MTProto + MTRequestMessageService
     └─ ad-hoc Download via network.download()/upload()/background()   (stats DC, wallet, group-call streams, history preload)
```

`MTProto` instances share **one global serial queue** (`MPK/Sources/MTProto.m:140-149`,
`"org.mtproto.managerQueue"`) across all accounts. `MTContext` state is serialized on another
global queue (`MTContext.m:318-327`, `"com.mtproto.MTContextQueue"`).

### 2.2 `request()` / `requestWithAdditionalInfo()` semantics

`Network.request` (`Network.swift:1226-1284`) and `Network.requestWithAdditionalInfo`
(`:1154-1224`) are cold `Signal`s. Subscribing creates an `MTRequest`; disposing removes it.
`Download` has 5 near-identical builders (`request`, `requestWithAdditionalData`, `rawRequest`,
`part`, `webFilePart`, plus `uploadPart`). The fields TelegramCore sets:

| MTRequest field | Network | Download | Meaning the engine must honour |
|---|---|---|---|
| `payload` | TL-serialized function (TelegramApi `Buffer`) | same; upload bodies optionally `gzip_packed` (`Download.swift:25-38`) | Opaque bytes; the engine never needs the API TL schema |
| `metadata` | `WrappedRequestMetadata(description, tag)` (`Network.swift:65-77`) | tag always nil | Logging plus the dependency tag carrier |
| `responseParser` | `{ data.2.parse(Buffer) -> BoxedMessage }` | same | Called on the raw `rpc_result` body (after gzip unwrap). Returning nil makes MtProtoKit synthesize `MTRpcError(500, "TL_PARSING_ERROR")` **and clear `apiInitializationHash`** (`MTRequestMessageService.m:809-824`) |
| `dependsOnPasswordEntry` | `false` | `false` | No request is held back by `SESSION_PASSWORD_NEEDED` |
| `needsTimeoutTimer` | not set (false) | `useRequestTimeoutTimers` (true unless AppConfiguration `ios_killswitch_disable_request_timeout`, `Account.swift:331-336`; false for `changedMasterDatacenterId` and extensions) | If a pending request sees no transport activity for **5 s**, MtProtoKit performs `requestSecureTransportReset` + `requestTransportTransaction` (`MTRequestMessageService.m:324-391`) |
| `expectedResponseSize` | not set | from caller | Cancelling a request with `expectedResponseSize >= 512 KB` that is in flight **resets the session** (`MTRequestMessageService.m:165-167`, `:188-190`) so the big response is not downloaded |
| `shouldContinueExecutionWithErrorContext` | flood logic | flood + `failOnServerErrors` | Called on FLOOD/420 and on 500/-500; `true` = retry after the wait (or 2 s for 500), `false` = surface the error |
| `acknowledgementReceived` | only for `requestWithAdditionalInfo` | n/a | Setting it requests a quick-ack (`needsQuickAck`, `MTRequestMessageService.m:638`). Emits `.acknowledged` when `info.contains(.acknowledgement)`. Used by sendMessage (`TC/State/PendingMessageManager.swift:1954`, `:2230`; `TC/PendingMessages/StandaloneSendMessage.swift:522`, `:630`) to mark "delivered to server" |
| `progressUpdated` | `requestWithAdditionalInfo` | n/a | Receive progress of the response packet `(Float, packetLength)`, emits `.progress`; used by `TC/WebpagePreview.swift:154-165` |
| `shouldDependOnRequest` | when `tag != nil` | n/a | Wraps in `invokeAfterMsg` (0xcb9f372d) pointing at the latest earlier request whose tag matches; resolved dynamically if that request is in the same container (`MTRequestMessageService.m:485-520`, `:642-665`). Only producer: `PendingMessageRequestDependencyTag` (`PendingMessageManager.swift:191-204`, same peer and namespace, lower id) keeps outgoing messages ordered |
| `completed(result, info, error)` | `.result` / `MTRpcError` | adds `info.timestamp` (server time of the response message), `networkType`, `duration` | A body that does not cast to `T` becomes `MTRpcError(500, "TL_VERIFICATION_ERROR")` in TelegramCore |
| `internalId` | cancellation key | same | `removeRequest(byInternalId:)` |

`automaticFloodWait` (default `true`): on `FLOOD_WAIT_X` / `FLOOD_PREMIUM_WAIT_X` / any 420 except
`FROZEN_METHOD_INVALID`, MtProtoKit parses X, calls `onFloodWaitError(errorText)` first, then either
re-queues the request with `minimalExecuteTime = now + X` (`MTRequestMessageService.m:905-960`) or,
when `automaticFloodWait == false`, completes it with the error. 88 call sites pass `false`.
`onFloodWaitError` feeds premium-upsell events: `FLOOD_PREMIUM_WAIT` maps to
`Network.addNetworkSpeedLimitedEvent` (`TC/Network/MultipartUpload.swift:473-480`,
`TC/Network/FetchV2.swift:864`).

### 2.3 Request decoration done by the engine (byte-exact expectations)

Order of wrapping, innermost first (`MTRequestMessageService.m:423-552`):

1. `invokeWithLayer(layer = Serialization.currentLayer())` + `initConnection` (0xda9b0d0d,
   0xc1cd5ea9), added to every request in a transaction while the auth key's
   `authKeyAttributes["apiInitializationHash"]` differs from `MTApiEnvironment.apiInitializationHash`
   (`:559`). Flags: bit 0 = proxy (MTProxy secret set, adds `inputClientProxy` 0x75588b3f
   ip/port), bit 1 = `params` (systemCode JSON, from `NetworkInitializationArguments.appData`). After
   the first successful result the hash is stored into the auth info (`:837-847`).
   `CONNECTION_NOT_INITED` (400) removes the hash and retries (`:961-972`). Any change of the API
   environment sends a `help.test` no-op to re-init (`:405-421`).
2. `invokeWithoutUpdates` (0xbf9459b7) when `apiEnvironment.disableUpdates` (= `supplementary`,
   i.e. extensions and cleanup) or `forceBackgroundRequests` (all `Download` workers).
3. `invokeAfterMsg` (0xcb9f372d) for dependency tags.
4. `invokeWithApnsSecret` (0x0dae54f8 nonce, secret) after `APNS_VERIFY_CHECK_<nonce>`; `invokeWithReCaptcha`
   (0xadbb0f94 token) after `RECAPTCHA_CHECK_<method>__<siteKey>` (`:973-1039`).

The apiInitializationHash string is
`apiId=..&deviceModel=..&systemVersion=..&appVersion=..&langCode=..&layer=..&langPack=..&langPackCode=..&proxy=..&systemCode=..`
(`MPK/Sources/MTApiEnvironment.m:422`). The Rust engine must compute exactly the same string from
the same `MTApiEnvironment` and keep it in the same `authKeyAttributes` slot (see 4.4). Otherwise every
switch forces a re-init, and a stale hash after switching back skips a needed re-init.

### 2.4 Errors

**Handled inside MtProtoKit, never (or not only) surfaced** (`MTRequestMessageService.m:849-1044`,
`MTProto.m:2027-2043`, `:1941-1975`, `:2410-2489`):

| Server condition | MtProtoKit behaviour | Surfaced to TelegramCore |
|---|---|---|
| rpc_error 401 `SESSION_PASSWORD_NEEDED` | `updatePasswordInputRequired(true)` | yes, as the request error (2FA flow) |
| any other rpc_error 401 | `delegate.requestMessageServiceAuthorizationRequired`; on workers with `requiredAuthToken` and `SESSION_REVOKED`/`AUTH_KEY_UNREGISTERED`: park the request (`waitingForTokenExport`) and retry after the token arrives | Main session: **`Network.loggedOut` (2.11)**. Workers: token re-transfer, request retried |
| rpc_error 401 `AUTH_KEY_PERM_EMPTY` | intercepted at the MTProto layer: whole packet dropped, `handleMissingKey` (re-create and re-bind the temp key), `requestSecureTransportReset` | **no** |
| transport error -404 (key unknown) | `handleMissingKey` (`MTProto.m:2090-2170`): ephemeral or CDN key dropped and re-created; foreign-DC persistent key dropped with token; master persistent key goes to `MTContext.checkIfLoggedOut` (bind probe; only `ENCRYPTED_MESSAGE_INVALID` counts as removed, `MTDiscoverConnectionSignals.m:353-377`) | Only via `contextLoggedOut` → `Network.loggedOut` |
| rpc_error 500 / -500 | `internalServerErrorCount++`, retry after 2 s unless `shouldContinue` says no (`failOnServerErrors`) | after retries are refused |
| 400 `MSG_WAIT_TIMEOUT` / 500 `MSG_WAIT_FAILED` | wait for the dependency request, then resend | no |
| `FLOOD_WAIT_X` / `FLOOD_PREMIUM_WAIT_X` / 420 | see 2.2 | only if `automaticFloodWait == false`; 420 `FROZEN_METHOD_INVALID` always surfaces |
| 400 `CONNECTION_NOT_INITED` | clear hash, resend | no |
| 403 `APNS_VERIFY_CHECK_*`, `RECAPTCHA_CHECK_*` | external verification, resend wrapped | no (unless verification never resolves) |
| any 406 | `didReceiveSoftAuthResetError()` → `Account.postSmallLogIfNeeded` | yes |
| bad_msg_notification 16/17/48, bad_server_salt | time sync / salt update, resend | no |
| bad_msg 32/33 | `resetSessionInfo` (new session id) → `mtProtoDidChangeSession` → `UpdateMessageService` emits `.reset` | no (updates reset) |
| unparsable result | `MTRpcError(500, "TL_PARSING_ERROR")` + hash cleared | yes |

**Passed through verbatim and inspected by TelegramCore and app code.** About 137 distinct
uppercase error strings are compared in `TC/`. The ones that matter to engine fidelity:
`FLOOD_WAIT*` (58 `hasPrefix` sites), `FROZEN_METHOD_INVALID` (`Network.swift:1316`),
`AUTH_KEY_DUPLICATED` (406, `TC/State/AccountStateManager.swift:874`, `:1462`, treated as "skip
difference"), `(PHONE_|USER_|NETWORK_)MIGRATE_X` (`TC/Authorization.swift:201-204` leads to
`changedMasterDatacenterId` and a new `Network`), `FILE_REFERENCE_*`/`FILEREF_INVALID`
(`PendingMessageManager.swift:2245`), `SESSION_TOO_FRESH_*`, `PASSWORD_TOO_FRESH_*`,
`TAKEOUT_INIT_DELAY_` (`MAC/packages/ChatExportUI/Sources/ChatExportUI/ChatExportManager.swift:991-996`),
and `errorCode == 406` checks (for example `TC/TelegramEngine/Privacy/RecentAccountSessions.swift:35`).
The engine must deliver `(errorCode, errorDescription)` exactly as received in `rpc_error`. TelegramCore
also synthesizes its own `MTRpcError`s (`"TL_VERIFICATION_ERROR"`, `"internal"`, `"Internal"`,
`"KDF_ERROR"`, ...). That is another reason `MTRpcError` must stay constructible from Swift.

### 2.5 Cancellation, resend and delivery guarantees

- Delivery is at-least-once from the engine's point of view. A request keeps its `MTRequest`
  identity across resends; its MTProto `msg_id` changes when it is re-sent after
  `mtProtoDidChangeSession` (all contexts cleared, `MTRequestMessageService.m:1249-1260`),
  `new_session_created` (only those with `msg_id < first_msg_id` not in the containers after it,
  `:1262-1277`), `transactionsMayHaveFailed` / `AllTransactionsMayHaveFailed` (transport
  change, `:1159-1193`), `messageDeliveryFailed` (bad_msg, `:1128-1157`),
  `messageResendRequestFailed` (`:1218-1233`).
- `msgs_detailed_info` leads to `msg_resend_req` only if the request is still pending
  (`:1195-1216`, `MTProto.m:2502-2545`).
- Server-side idempotency is what prevents duplicates (sendMessage `random_id`). The Rust engine
  must not resend more aggressively than MtProtoKit. "Re-send on every reconnect" would duplicate
  non-idempotent calls.
- `addRequest` is a silent no-op when the service is not attached to an MTProto
  (`MTRequestMessageService.m:121-139`): the signal never completes. Today it always is attached.
- Cancelling an in-flight request does **not** send `rpc_drop_answer` (commented out at `:163`);
  responses for unknown msg ids are logged and dropped (`:1074-1077`).

### 2.6 Updates (`UpdateMessageService` as `MTMessageService`)

- Attached once per account by `AccountStateManager.reset()` (`TC/State/AccountStateManager.swift:434-447`),
  which also starts `.pollDifference`. macOS calls `account.resetStateManagement()`
  (`TC/Account/Account.swift:1609`) from `MAC/Telegram-Mac/account/SharedWakeupManager.swift:182-185`.
- MtProtoKit dispatch (`MTProto.m:2381-2577`): service messages (acks, bad_msg, detailed info,
  pong) are consumed internally. `new_session_created` invokes
  `mtProtoServerDidChangeSession(firstValidMessageId:otherValidMessageIds:)` on every service.
  Every other parsed message (body = `BoxedMessage` from `Serialization.parseMessage`, after
  container and gzip unwrapping) goes to `mtProto(_:receivedMessage:...)` on every service.
  `MTRequestMessageService` picks `rpc_result`; `UpdateMessageService` picks `Api.Updates`.
- `UpdateMessageService` contract (`UpdateMessageService.swift:25-94`):
  - `mtProtoDidChangeSession` (client-side session reset) emits `[.reset]`
  - `mtProtoServerDidChangeSession` (`new_session_created`) emits `[.reset]`
  - `Api.Updates`: `.updates`/`.updatesCombined` become groups with a seq range; `.updateShort`
    becomes date-only; `.updateShortMessage`/`.updateShortChatMessage` become a synthesized
    `updateNewMessage`; `.updatesTooLong` emits `[.reset]`; `.updateShortSentMessage` emits `.updatePts`.
- `.reset` makes `finalStateWithUpdateGroups` treat the state as having a hole
  (`TC/State/AccountStateManagementUtils.swift:589-592`). This is the only signal that tells
  TelegramCore to run `updates.getDifference`. **An engine that does not report session changes
  loses updates until the next pts gap is noticed.**
- Unauthorized accounts use `UnauthorizedUpdateMessageService`
  (`UnauthorizedAccountStateManager.swift:7-50`) for `updateLoginToken`,
  `updateServiceNotification`, `updateSentPhoneCode` (QR login, payment-required sign-in).
- Updates that arrive inside an `rpc_result` (for example sendMessage results) are not pushed through
  the update service. TelegramCore feeds them via `stateManager.addUpdates`. Ordering across both
  paths is reconciled by pts.
- Incoming messages with odd seqno must be acked (`MTProto.m:2401-2408`); duplicates are suppressed
  per session (`:2383-2395`).

### 2.7 Connection status

`MTProtoConnectionStatusDelegate` (`Network.swift:95-158`) folds 4 delegate callbacks into
`MTProtoConnectionFlags` (`:26-34`):

| Flag | Source callback | Engine meaning |
|---|---|---|
| `NetworkAvailable` | `mtProtoNetworkAvailabilityChanged` | reachability (SCNetworkReachability in `MTNetworkAvailability`) |
| `Connected` (+ clears `ProxyHasConnectionIssues`) | `mtProtoConnectionStateChanged(state.isConnected)` | TCP and transport up |
| `ProxyHasConnectionIssues` | `state.proxyHasConnectionIssues` while not connected | Proxy configured but failing (`checkForProxyConnectionIssues`) |
| `UpdatingConnectionContext` | `mtProtoConnectionContextUpdateStateChanged` | Actualization ping in flight after connect (`MPK/Sources/MTTcpTransport.m:159-160`) |
| `PerformingServiceTasks` | `mtProtoServiceTasksStateChanged` | Awaiting time sync / salts, or resend in progress (`MTProto.m:427-463`) |
| `proxyAddress` | `state.proxyAddress` | Shown in the UI |

Derivation (`Network.swift:641-659`): Connected and (Updating or ServiceTasks) gives `.updating`;
Connected alone gives `.online`; not NetworkAvailable gives `.waitingForNetwork`; otherwise
`.connecting(proxyAddress, proxyHasConnectionIssues)`. Then `distinctUntilChanged` (`:849-851`).
`dropConnectionStatus()` forces `.waitingForNetwork` on proxy change (`:859-861`, `:1034`).
`Account` combines it with `stateManager.isUpdating` into `AccountNetworkState`
(`Account.swift:1364-1397`). Only the **main** session drives status; workers do not.
When paused (no transport), MTProto reports `networkAvailable = false` and a nil state
(`MTProto.m:266-283`).

### 2.8 Pause / resume (`shouldKeepConnection`)

- `MTProto` is created **paused** (`MTProto.m:175-179`). Nothing connects until resumed.
- `Network.shouldKeepConnection` (`Network.swift:863`) → `distinctUntilChanged |> deliverOn(queue)`
  → `mtProto.resume()/pause()` (`:981-993`). `pause` drops the transport (`MTProto.m:205-222`);
  `resume` resets the transport, requests a transaction, and re-asks for awaited keys/tokens (`:224-246`).
- Drivers: `Account.swift:1415-1424` (`shouldBeServiceTaskMaster ∈ {.now, .always} && postbox.isMasterClient`);
  `UnauthorizedAccount` `Account.swift:188-196`.
  - macOS: every logged-in account is `.always` (`MAC/Telegram-Mac/account/SharedWakeupManager.swift:172-181`);
    sleep forces `.never`, wake forces `.never` then `.always`, a forced reconnect (`:99-116`); the auth screen uses
    `.now` (`MAC/Telegram-Mac/app/ApplicationContext.swift:156`, `:165`).
  - iOS: `IOS/TelegramUI/Sources/SharedWakeupManager.swift:1145-1151` folds foreground, background
    tasks, audio, location and processing tasks.
  - iOS NSE: `IOSAPP/NotificationService/Sources/NotificationService.swift:1524`, `:2225`, `:2677`.
- Workers: `combineLatest(shouldKeepConnection, shouldExplicitelyKeepWorkerConnections,
  continueInBackground && shouldKeepBackgroundDownloadConnections)` on the **main queue**
  (`Network.swift:1084-1091`), applied in `Download.init` on `Network.queue` (`Download.swift:80-91`).
- The WEB proxy carrier rides the same flag (`Network.swift:995-1009`).
- `isContextNetworkAccessAllowed` (= `shouldKeepConnection`) gates MTContext's own background
  work: key generation, discovery and transfers (`Network.swift:943-948`).

### 2.9 Download workers

- One `Download` = one `MTProto` (own session id, own TCP connection) + one
  `MTRequestMessageService` with `forceBackgroundRequests = true`.
- Foreign DC (`dc != master`, not CDN): `requiredAuthToken = NSNumber(dc)`; MTProto waits in
  `AwaitingDatacenterAuthToken` until `MTContext.authTokenById[dc] == token` (`MTProto.m:347-352`).
  MTContext runs `MTDatacenterTransferAuthAction`: `auth.exportAuthorization(dc)` on master, then
  `auth.importAuthorization` on the target (`MPK/Sources/MTDatacenterTransferAuthAction.m:111-161`),
  then persists `authTokenById` (`MTContext.m:1496-1518`).
- 401 on a worker (`Download.swift:101-104`): drop token, request transfer again; the request stays
  parked and is retried on `mtProtoAuthTokenUpdated` (`MTRequestMessageService.m:1279-1293`).
  **Workers never log the account out.**
- CDN (`isCdn`): persistent key per CDN DC created with CDN RSA keys from `help.getCdnConfig`
  (`NetworkHelper.fetchContextDatacenterPublicKeys`, `Network.swift:911-942`, persisted as
  `ephemeral:datacenterPublicKeysById`); no temp keys, no token.
- Media (`isMedia`): address list filtered for `preferForMedia`, temp key selector `ephemeralMedia`
  (`MTProto.m:911-923`).
- Consumers: `network.download(datacenterId:isMedia:)` in stats (`TC/Statistics/PeerStatistics.swift:319,352,827`,
  `MessageStatistics.swift:75`, `PollStatistics.swift:54`, `StoryStatistics.swift:60,278`),
  wallet (`TC/TelegramEngine/Wallet/Wallet.swift:675,720`, `WalletBackup.swift:325`), bank cards
  (`TC/TelegramEngine/Payments/BankCards.swift:12`), group-call streaming with server timestamps
  (`TC/TelegramEngine/Calls/GroupCalls.swift:3092,3131,3185`); `network.upload()`
  (`MultipartUpload.swift:415`); `network.background()` (`TC/Network/FetchedMediaResource.swift:460`,
  `TC/State/ChatHistoryPreloadManager.swift:301`).

### 2.10 MultiplexedRequestManager

`TC/Network/MultiplexedRequestManager.swift`: targets `.main(dc)` / `.cdn(dc)` × `continueInBackground`;
at most **3 requests per worker, 4 workers per target** (`:217-219`); priority by `pushPriority(resourceId:)`
(`:128-158`, driven by `TC/TelegramEngine/Resources/TelegramEngineResources.swift:418`); workers come
from `Network.makeWorker` (`Network.swift:959-979`, always `isMedia = true`); idle workers are
dropped after **20 min** (`:335-369`). Requests go through `Download.rawRequest`
(`:291-323`). Users: `FetchV2.swift:681,798,853,978`, `MultipartFetch.swift:114`, `MultipartUpload.swift:413,487`.
The manager is engine-agnostic as long as `Download` keeps its Swift API.

### 2.11 Logout, authorizationRequired, soft auth reset

```
401 (≠ SESSION_PASSWORD_NEEDED) on main session
  → Network.requestMessageServiceAuthorizationRequired (Network.swift:1067-1070)
MTContext.checkIfLoggedOut → bind probe says key removed → contextLoggedOut
  → NetworkHelper.contextLoggedOut (Network.swift:758-760, 951-954)
      → Network.loggedOut?() → Account: _loggedOut = true, callSessionManager.dropAll() (Account.swift:1353-1359)
          → macOS ApplicationContext (MAC/Telegram-Mac/app/ApplicationContext.swift:494-506)
            / iOS ApplicationContext (IOS/TelegramUI/Sources/ApplicationContext.swift:266-279)
              → logoutFromAccount (TC/Account/AccountManager.swift:367-391): adds .loggedOut attribute
                  → managedCleanupAccounts → cleanupAccount (AccountManager.swift:479-531):
                     opens the account supplementary, sends auth.logOut, deletes the record and its files
```

`UnauthorizedAccount` never sets `loggedOut`, so 401s during sign-in are harmless.
Soft reset: 406 → `didReceiveSoftAuthResetError` (`Network.swift:906-908`) → `Account.postSmallLogIfNeeded`
(`Account.swift:1360-1362`).

### 2.12 Proxy switching and checking

- Initial: `apiEnvironment.withUpdatedSocksProxySettings(effectiveActiveServer.mtProxySettings)`
  (`Network.swift:483-485`); WEB proxy needs the carrier factory (`:531-539`).
- Live: `Account`/`UnauthorizedAccount` observe `SharedDataKeys.proxySettings` and call
  `Network.updateProxySettings` (`Account.swift:215-221` for `UnauthorizedAccount`, `Account.swift:1525-1535` for `Account`), which swaps the TCP factory,
  updates the API environment (only if changed) and drops the connection status
  (`Network.swift:1012-1040`). MTProto resets the transport on proxy or langPackCode change
  (`MTProto.m:2785-2812`). The initConnection hash includes the proxy, so requests re-init.
- `contextProxyId` (`Network.swift:843-846`, `:763-777`; set from `contextApiEnvironmentUpdated`) re-triggers
  `help.getPromoData` when the MTProxy changes (`TC/State/ManagedProxyInfoUpdates.swift:249-262`, the
  proxy sponsor channel).
- Checking: `ProxyServersStatusesImpl` (`ProxyServersStatuses.swift:40-134`) and macOS
  `ProxyAlert` ping each server with `MTProxyConnectivity` (independent sockets; WEB proxies
  excluded). Engine-independent; keep on MtProtoKit.

### 2.13 Backup address discovery and DC options

- `setDiscoverBackupAddressListSignal(MTBackupAddressSignals.fetchBackupIps(...))` (`Network.swift:590-591`):
  DoH TXT (`tapv3.stel.com` for test, `MPK/Sources/MTBackupAddressSignals.m:99-135`), plus CloudData
  on iOS when iCloud is enabled (`Network.swift:565-588`), plus `accessHostOverride`
  (`NetworkSettings.backupHostOverride`, `:488`).
- Triggered internally when transport schemes fail (`MTContext transportSchemeForDatacenterWithIdRequired`)
  and explicitly at unauthorized start (`Account.swift:210`).
- DC options from `help.getConfig` (`ManagedConfigurationUpdates.swift:19-36`) and from pushes
  (`Network.mergeBackupDatacenterAddress`, `Network.swift:1111-1136`).

### 2.14 Test vs production

`testingEnvironment` comes from the account state (`Account.swift:341-366`). It selects seed IPs
(`Network.swift:543-557`), RSA server keys (`MPK/Sources/MTDatacenterAuthMessageService.m:181`,
`defaultPublicKeys(!isTestingEnvironment)`), DoH names, and the pre-warmed DC set (`Account.swift:199-204`).
The initial DC for a new login is 1 (DEBUG) or 2 (`Account.swift:360-364`).

### 2.15 Temp auth keys

`useTempAuthKeys` is hard-coded `true` (`Network.swift:507`). Selector: `ephemeralMain` or
`ephemeralMedia` by address `preferForMedia`; persistent for CDN (`MTProto.m:892-952`). Lifetime
`tempKeyExpiration = 24 h` (`MTContext.m:269`). Created and bound by MTContext
(`MTContext.m:1557-1594`, `MPK/Sources/MTDatacenterAuthAction.m:108-186` with
`MTBindKeyMessageService`), persisted in the same `datacenterAuthInfoById` dictionary with
`validUntilTimestamp`; expired ones are dropped on load (`MTContext.m:476-492`).

### 2.16 App extensions

| Process | Network setup | Notes |
|---|---|---|
| iOS NotificationService | `standaloneStateManager` (`Account.swift:1721-1870`) → `initializedNetwork(supplementary: true, useRequestTimeoutTimers: false, appConfiguration: .defaultValue)` | No updates (`invokeWithoutUpdates`), no backup discovery, no WEB proxy; deadline-bounded |
| iOS Share / NotificationContent / Siri | `IOS/TelegramUI/Components/ShareExtensionContext/Sources/ShareExtensionContext.swift:418`, `IOS/TelegramUI/Sources/NotificationContentContext.swift:144`, `IOSAPP/SiriIntents/IntentHandler.swift:243` | Full `accountWithId` paths |
| macOS TelegramShare | `MAC/TelegramShare/ShareViewController.swift:123` (`SharedAccountContext`, `#if SHARE`) | Links TelegramCore |
| Detection | `Bundle.main.bundlePath.hasSuffix(".appex")` (`Network.swift:531`) | Only gates WEB proxy today |

Every one of them builds its own `NetworkInitializationArguments`, so an injected engine factory is
per-process. An extension that does not pass a factory stays on MtProtoKit automatically.

### 2.17 Time

`globalTimeDifference` lives in MTContext, persisted as `temp:globalTimeDifference`, updated from
msg_id of bad_msg/salt/pong (`MTProto.m:2425-2445`, `:2733-2759`). Reads are **synchronous** (`dispatch_sync`
onto `contextQueue`, `MTContext.m:609-628`) from any thread, including the main thread
(UI timestamps). The Rust engine must push its time corrections into MTContext
(`setGlobalTimeDifference`) so these synchronous reads stay correct.

---

## 3. Threading

| Activity | Queue / thread today | Contract to preserve |
|---|---|---|
| `initializedNetwork` body | a fresh `Queue()` that becomes `Network.queue` (`Network.swift:469-470`) | Engine construction may happen off-main; result is delivered via `Signal` |
| `Network.request` subscribe | caller's thread; `addRequest` hops to MTProto `managerQueue` (`MTRequestMessageService.m:121-139`) | Non-blocking submit from any thread |
| Dispose of a request signal | caller's thread → async on `managerQueue` | Cancel after submit must not race (serial queue order) |
| `request.completed`, `.acknowledgementReceived`, `.progressUpdated` | `managerQueue` (shared by all MTProto instances, all accounts) | Callbacks are serialized per engine; never on main; subscribers may synchronously start or dispose other requests (re-entrancy; `MTQueue dispatchOnQueue` runs inline when already on the queue, `MPK/Sources/MTQueue.m:104-129`) |
| `responseParser` (Swift TL parse) | `managerQueue` | Runs on the engine callback queue; can be heavy (big `Api.Updates`) |
| Update service callbacks | `managerQueue`; `UpdateMessageService.pipe.putNext` synchronous; `AccountStateManager.addUpdateGroups` hops with `queue.async` (`AccountStateManager.swift:497-512`) | **Strict receive order per session, `.reset` ordered relative to updates** |
| `MTProtoDelegate` status callbacks | `managerQueue` → `Promise.set` (thread-safe) | Any queue |
| MTContext state and listeners | `contextQueue`; `globalTimeDifference`, `removeChangeListener`, setters for discovery and verification are `synchronous:true` | Sync reads from arbitrary threads; listeners called on `contextQueue` |
| `NetworkHelper.fetchContextDatacenterPublicKeys` | called on `contextQueue`, issues `Network.request` | The engine must accept requests submitted from MTContext's queue |
| Keychain `get` | `Postbox.keychainEntryForKey` = `impl.syncWith` (sync hop onto the Postbox queue, `IOS/Postbox/Sources/Postbox.swift:4726-4730`); called from `contextQueue` in `setKeychain` | Never call into MTContext key loading from the Postbox queue (deadlock) |
| Keychain `set`/`remove` | async Postbox transaction (`Postbox.swift:2166-2190`) | Fire-and-forget; durability is not synchronous |
| pause/resume | `Network.queue` (main) / `Network.queue` (workers, after a main-queue `combineLatest`) | Idempotent, any order |
| MultiplexedRequestManager | own `Queue()`; worker completions `queue.async` back (`MultiplexedRequestManager.swift:291-323`) | Engine-agnostic |
| `MTTcpConnectionInterface` delegate | `delegateQueue` provided by `MTTcpConnection` | A Rust transport adapter must deliver socket callbacks on one serial queue |

SwiftSignalKit assumptions: request signals are cold, single-shot (next then completion, or
error), and cancellable. `retryRequest` (`Network.swift:1308-1311`) retries every error with
0.2..5 s backoff on `Queue.concurrentDefaultQueue()`. Errors must stay `MTRpcError` (class
identity is irrelevant, fields are read). Signals must not deliver after disposal (MtProtoKit
removes the request first; the Rust adapter should drop late callbacks for disposed tokens).

---

## 4. Persistence

### 4.1 Where it lives

- `Keychain` (`TC/Network/Network.swift:1327-1382`) implements `MTKeychain` over closures
  created by `makeExclusiveKeychain` (`TC/Account/Account.swift:11-53`). These map to
  `postbox.keychainEntryForKey/setKeychainEntryForKey/removeKeychainEntryForKey`, Postbox
  `KeychainTable` (table id 1, binary keys from the UTF-8 string, `IOS/Postbox/Sources/KeychainTable.swift:1-26`,
  `Postbox.swift:1905`). The database is `<rootPath>/account-<id>/postbox/db_sqlite` (SQLCipher), shared
  with app extensions through the app group (iOS) / group container (macOS).
- Storage key = `group + ":" + key` (`Network.swift:1344`, `:1353`, `:1368`, `:1380`).
- Value = `NSKeyedArchiver.archivedData(withRootObject:requiringSecureCoding:false)`
  (`Network.swift:1343`); read with `MTDeprecated.unarchiveDeprecated` = legacy
  `NSKeyedUnarchiver.unarchiveObjectWithData` (`MPK/Sources/MTKeychain.m:5-14`).
- **Exclusivity:** each `makeExclusiveKeychain(id:)` bumps a per-account generation; older
  `Keychain` instances become no-ops ("not current", `Account.swift:24-52`). A second Keychain created
  for a Rust engine would silently disable MtProtoKit's writes, and the reverse.
- MTContext caches everything in memory after `setKeychain` and **rewrites whole dictionaries** on
  each change (`MTContext.m:667`, `762`, `802`, `865`, `946`, `1150`, `1202`, `1218`, `1391`, `1506`).
  Two independent writers clobber each other.

### 4.2 Entries

| Storage key | Type (archived root) | Content | Written at |
|---|---|---|---|
| `persistent:datacenterAuthInfoById` | `NSDictionary<NSNumber(int64), MTDatacenterAuthInfo>` | Map key = `(selector << 32) \| dcId` (`MTContext.m:126-144`); selector 0 persistent, 1 ephemeralMain, 2 ephemeralMedia. `MTDatacenterAuthInfo` coder keys: `authKey` (NSData, 256 B), `authKeyId` (int64), `validUntilTimestamp` (int32, `INT32_MAX` for persistent), `saltSet` (NSArray of `MTDatacenterSaltInfo` {`salt`, `firstValidMessageId`, `lastValidMessageId`} int64s), `authKeyAttributes` (NSDictionary, `apiInitializationHash` → NSString) (`MPK/Sources/MTDatacenterAuthInfo.m:51-75`, `MTDatacenterSaltInfo.m:17-34`) | `MTContext.m:802`; also `Account.swift:319-320` (backup restore) |
| `persistent:authTokenById` | `NSDictionary<NSNumber(dc), id>` | Token object = the `requiredAuthToken` (`NSNumber(dcId)`, `Download.swift:61`) meaning "authorization imported for this DC's persistent key" | `MTContext.m:1202`, `1218`, `1506` |
| `persistent:datacenterAddressSetById` | `NSDictionary<NSNumber(dc), MTDatacenterAddressSet>` | `addressList: [MTDatacenterAddress]` {`ip`, `host`, `port` (int), `preferForMedia`, `restrictToTcp`, `cdn`, `preferForProxy`, `secret`} (`MTDatacenterAddress.m:24-51`) | `MTContext.m:667`, `762` |
| `persistent:datacenterManuallySelectedSchemeById_v1` | `NSDictionary<MTTransportSchemeKey, MTTransportScheme>` | key {`datacenterId`, `isProxy`, `isMedia`}; value {`transportClass` name, `address`, `media`} (`MTContext.m:62-117`, `MTTransportScheme.m:29-46`) | `MTContext.m:865` |
| `temp:globalTimeDifference` | `NSNumber(double)` | seconds, server minus local | `MTContext.m:640` |
| `temp:transportSchemeStats_v1` | `NSDictionary<NSNumber, NSDictionary<MTDatacenterAddress, MTTransportSchemeStats>>` | connection stats | `MTContext.m:1391` |
| `ephemeral:datacenterPublicKeysById` | `NSDictionary<NSNumber(dc), NSArray<NSDictionary{key, fingerprint}>>` | CDN RSA keys | `MTContext.m:1150` |
| `cleanup:cleanupSessionIdsByAuthKeyId` | `NSDictionary` | sessions pending `destroy_session` | `MTContext.m:946` |
| `primes:<hex>` | `NSNumber(bool)` | `MTCheckIsSafePrime` / `MTCheckMod` cache (`MPK/Sources/MTEncryption.m:633`, `695`, `744`, `796`) | crypto helpers |

Sessions (session_id, seqno, msg_id counters) are **not** persisted. Each MTProto starts a random
session (`MTProto.m:173`). Salts are persisted inside the auth info.

### 4.3 Other state the switch must not disturb

| Store | Location | Owner |
|---|---|---|
| Account state (`AuthorizedAccountState`: `masterDatacenterId`, `peerId`, `isTestingEnvironment`, pts/qts/seq/date) | Postbox metadata (`transaction.getState()`) | TelegramCore, engine-independent; pts state means a new session only needs getDifference |
| `NetworkSettings` (`useNetworkFramework_v2`, `useExperimentalDownload_v2`, `backupHostOverride`, ...) | Postbox preference `PreferencesKeys.networkSettings` (`TC/SyncCore/SyncCore_NetworkSettings.swift:3-41`) | Dev toggles (macOS `DeveloperViewController.swift:240-260`, iOS `IOS/DebugSettingsUI/Sources/DebugController.swift:1606-1618`) |
| `ProxySettings`, `LoggingSettings` | AccountManager shared data | global |
| `network-stats` | `<basePath>/network-stats` | 1.d |
| Account backup (iOS) | `AccountBackupData` from `persistent:datacenterAuthInfoById` (`Account.swift:1120-1176`), restored at `Account.swift:302-321` | Must stay in MTContext format |
| macOS `accounts-shared-data` | `<rootPath>/accounts-shared-data` JSON with persistent keys and addresses (`MAC/packages/TelegramUtils/Sources/TelegramUtils/ManageSharedAccountInfo.swift:8-80`) | Reads MTContext |
| TON Connect bindings | wallet stored state keyed by persistent `authKeyId` (`IOS/WalletContext/Sources/WalletTonConnect.swift:203-210`) | Breaks if the persistent key changes |

### 4.4 What the Rust engine must read/write so switching is lossless both ways

Invariants:

1. **Never create, replace or delete the persistent key of the master DC** while the account is
   authorized. A new key is an unauthorized key (401 → logout path). Only MTContext's
   `checkIfLoggedOut` decides that the key is gone.
2. **Single writer.** All writes go through MTContext's public mutators on the live `MTContext`
   instance that `Network` already owns: `updateAuthInfoForDatacenterWithId:authInfo:selector:`,
   `updateAuthTokenForDatacenterWithId:authToken:`, `setGlobalTimeDifference:`,
   `updateAddressSetForDatacenterWithId:...`, `addAddressForDatacenterWithId:...`,
   `updateTransportSchemeForDatacenterWithId:...`, `reportTransportScheme{Success,Failure}...`,
   `updatePublicKeysForDatacenterWithId:...`. Never write Postbox keychain rows directly and never
   create a second `Keychain`.
3. **Same formats, same meaning.** Salts merged into the auth info's `saltSet`
   (`-mergeSaltSet:forTimestamp:`); `apiInitializationHash` maintained per auth info exactly as in 2.3;
   temp keys stored only after a successful `auth.bindTempAuthKey` with `validUntilTimestamp` set;
   token marker `NSNumber(dc)`.

Minimum the Rust engine reads at session start (phase 1): persistent + ephemeral auth info for its
DC and selector, salts, `authTokenById[dc]` (foreign DCs), address set and transport schemes for
(dc, media, isProxy), `apiEnvironment` (initConnection fields, proxy, `disableUpdates`),
`globalTimeDifference`, CDN public keys. All of it is available via MTContext getters.

Minimum it writes: salt updates (`future_salts`, bad_server_salt), time difference,
`apiInitializationHash` after a successful init, temp keys it created (phase 2), tokens it
imported (phase 2), scheme success and failure.

If it follows (1) to (3), switching **Rust → MtProtoKit** finds the same persistent key, the
same token markers and valid salts and temp keys. Switching **MtProtoKit → Rust** is symmetric.
Neither direction needs a re-login, and at worst one extra temp-key bind and one `initConnection`.

---

## 5. Seam proposal

### 5.1 Options

| Option | Description | Verdict |
|---|---|---|
| A. ObjC drop-in | Rust behind classes that mimic `MTProto` / `MTRequestMessageService` | Rejected. `MTProto` is a concrete class with 30+ properties, a delegate soup and MTContext listener coupling; mimicking it pins Rust to MtProtoKit internals |
| **B. Swift session seam** | Protocols below `Network`/`Download`; two implementations: `MtProtoKitEngine` (wraps today's code verbatim) and `RustEngine` (FFI). MTContext stays the config and persistence owner | **Recommended.** Touches about 12 TelegramCore files, keeps `MTRpcError`, crypto and all 1,020 request sites unchanged |
| C. Full replacement incl. MTContext | Rust owns keys, discovery and persistence; MTContext removed | Later, only if MtProtoKit is deleted. Needs a Swift persistence shim that writes 4.2 formats, plus replacements for `network.context` users (1.b) |

### 5.2 Protocols (TelegramCore, new file `TC/Network/NetworkEngine.swift`)

```swift
import Foundation
import SwiftSignalKit
import MtProtoKit

public enum NetworkEngineKind: String, Codable, Equatable {
    case mtProtoKit
    case rust
}

public struct NetworkEngineRequestOptions {
    public var expectedResponseSize: Int32 = 0
    public var needsTimeoutTimer: Bool = false
    public var wantsQuickAck: Bool = false
    public var wantsProgress: Bool = false
}

public struct NetworkEngineErrorContext {
    public var floodWaitSeconds: Int
    public var floodWaitErrorText: String?
    public var internalServerErrorCount: Int
}

public final class NetworkEngineRequest {
    public let payload: Data
    public let metadata: WrappedRequestMetadata
    public let shortMetadata: WrappedRequestShortMetadata
    public let parse: (Data) -> Any?
    public let options: NetworkEngineRequestOptions
    public let shouldContinueAfterError: (NetworkEngineErrorContext) -> Bool
    public let dependsOn: ((WrappedRequestMetadata) -> Bool)?
    public let acknowledged: (() -> Void)?
    public let progress: ((Float, Int) -> Void)?
    public let completed: (Result<(Any, NetworkResponseInfo), NetworkEngineRequestFailure>) -> Void
}

public struct NetworkEngineRequestFailure: Error {
    public let error: MTRpcError
    public let timestamp: Double
}

public protocol NetworkEngineUpdateSink: AnyObject {
    func networkSessionDidReset()
    func networkSessionDidReceive(message: Any)
}

public struct NetworkEngineConnectionState: Equatable {
    public var isNetworkAvailable: Bool
    public var isConnected: Bool
    public var isUpdatingConnectionContext: Bool
    public var isPerformingServiceTasks: Bool
    public var proxyAddress: String?
    public var proxyHasConnectionIssues: Bool
}

public protocol NetworkEngineSessionDelegate: AnyObject {
    func networkSessionAuthorizationRequired()
    func networkSessionSoftAuthReset()
    func networkSessionConnectionStateChanged(_ state: NetworkEngineConnectionState)
}

public protocol NetworkEngineSession: AnyObject {
    var datacenterId: Int { get }
    var delegate: NetworkEngineSessionDelegate? { get set }
    func add(_ request: NetworkEngineRequest) -> AnyHashable
    func cancel(_ token: AnyHashable)
    func setPaused(_ paused: Bool)
    func addUpdateSink(_ sink: NetworkEngineUpdateSink)
    func stop()
}

public enum NetworkEngineSessionRole {
    case main
    case worker(masterDatacenterId: Int, isMedia: Bool, isCdn: Bool)
}

public protocol NetworkEngine: AnyObject {
    var kind: NetworkEngineKind { get }
    func makeSession(datacenterId: Int, role: NetworkEngineSessionRole, usage: MTNetworkUsageCalculationInfo?) -> NetworkEngineSession
}

public protocol NetworkEngineFactory {
    func makeEngine(context: MTContext, transportFactory: NetworkEngineTransportFactory?, isAppExtension: Bool) -> NetworkEngine?
}

public typealias NetworkEngineTransportFactory = (MTTcpConnectionInterfaceDelegate, DispatchQueue) -> MTTcpConnectionInterface
```

Notes on the shape:

- `NetworkEngineSession` is everything `Network` and `Download` need from `MTProto +
  MTRequestMessageService` (rows of 1.a). `NetworkEngine` is only a factory bound to one
  `MTContext`. Config operations (`updateApiEnvironment`, address merges, proxy updates, auth key
  pre-warm, `getAuthKeyId`) **stay on MTContext**. The Rust engine observes them as an
  `MTContextChangeListener` (`contextApiEnvironmentUpdated`, `contextDatacenterAddressSetUpdated`,
  `contextDatacenterTransportSchemesUpdated`, `contextDatacenterAuthInfoUpdated`,
  `contextDatacenterAuthTokenUpdated`, `contextDatacenterAuthInfoRequestFailed`,
  `contextDatacenterAuthTokenTransferFailed`). That is the same mechanism MTProto uses today
  (`MTProto.m:2579-2812`), so neither caller notices which engine is active.
- `parse` is today's `responseParser`; `networkSessionDidReceive(message:)` receives the
  `BoxedMessage` produced by `context.serialization.parseMessage`. The Rust engine hands raw
  bytes of any non-service constructor back to Swift for parsing. **Rust needs only the MTProto
  service TL schema, never the API schema.**
- Errors stay `MTRpcError` objects built in Swift from Rust's `(code, description)`.
- The `MtProtoKitEngine` implementation is a mechanical move of today's code:
  `MtProtoKitSession` holds `MTProto + MTRequestMessageService`, maps
  `NetworkEngineRequest` to `MTRequest` (one place instead of 7), adapts `MTProtoDelegate` to
  `networkSessionConnectionStateChanged`, adapts `MTRequestMessageServiceDelegate`, and wraps update
  sinks in a tiny `MTMessageService` shim. Worker sessions keep the 401 token re-transfer from
  `Download.swift:101-104` inside the shim.
- The `RustEngine` implementation lives outside TelegramCore (for example `IOS/MTProtoEngineRust`, a Swift
  wrapper over the static lib built from `third-party/mtproto-engine`, packaged like
  `third-party/wallet-engine` / `MAC/packages/WalletEngine` as an xcframework binary target).

### 5.3 Ownership split: what stays in MTContext, what Rust replaces

| Concern | Phase 1 (hybrid, recommended first) | Phase 2 |
|---|---|---|
| Persistence (4.2) | MTContext (single writer) | MTContext (single writer; Rust calls its mutators) |
| API environment, proxy settings, seeds, DC options, discovery (DoH, CloudData) | MTContext | MTContext |
| Auth key DH (`req_pq`...) for new keys | MTContext (`MTDatacenterAuthAction` over MtProtoKit sockets) | Rust, result stored via `updateAuthInfoForDatacenterWithId` |
| Temp key creation and `auth.bindTempAuthKey` | MTContext | Rust (must also reproduce the bind-probe semantics of `checkIfLoggedOut`) |
| Export/import authorization to foreign DCs | MTContext (`authTokenForDatacenterWithIdRequired`) | Rust, token marker via `updateAuthTokenForDatacenterWithId` |
| Transport (TCP, obfuscation, MTProxy fake-TLS, SOCKS5) | **Rust** (or injected `MTTcpConnectionInterface` for NW and WEB carrier) | Rust |
| Encryption (MTProto 2.0), session (msg_id, seqno, acks, containers, gzip, salts, time sync, resend, msgs_state) | **Rust** | Rust |
| RPC layer (wrappers 2.3, error policy 2.4, flood wait, quick ack, progress, dependency) | **Rust** | Rust |
| Updates dispatch (2.6) | **Rust** → Swift sink | Rust |
| Connection status (2.7) | **Rust** → delegate | Rust |
| Proxy ping (`MTProxyConnectivity`) | MtProtoKit (independent) | optional |
| Network usage accounting | Rust reports bytes → Swift `MTNetworkUsageManager` | same |
| Logging | Rust → `Logger.shared` sink (respect `MTLogEnabled`) | same |

In phase 1, the Rust session asks for a missing key exactly as MTProto does:
`context.authInfoForDatacenter(withIdRequired:isCdn:selector:allowUnboundEphemeralKeys:)`, then
waits for `contextDatacenterAuthInfoUpdated`. MTContext may still open MtProtoKit sockets for
key generation, but those are short-lived and use a different (or no) auth key, so they cannot
cause `AUTH_KEY_DUPLICATED`.

### 5.4 Per-file changes (TelegramCore and callers)

| File | Change |
|---|---|
| `TC/Network/NetworkEngine.swift` (new) | Protocols from 5.2 |
| `TC/Network/MtProtoKitEngine.swift` (new) | Today's `MTProto + MTRequestMessageService + MTProtoConnectionStatusDelegate + MTRequest` construction moved here; update-sink shim conforming to `MTMessageService` |
| `TC/Network/Network.swift` | `initializedNetwork` (`:467-709`): choose engine (5.5), keep MTContext setup unchanged (`:473-631`), replace `:633-661` with `engine.makeSession(datacenterId:, role: .main, ...)`; keep `NetworkHelper`. `Network` (`:816-1306`): store `mainSession: NetworkEngineSession` instead of `mtProto`/`requestService` (`:823-826`); `request` and `requestWithAdditionalInfo` (`:1154-1284`) build `NetworkEngineRequest` via one shared helper; `shouldKeepConnection` → `mainSession.setPaused` (`:981-993`); `makeWorker` passes `engine` (`:1084-1092`); `getAuthKeyId` uses `self.context` instead of `mtProto.context` (`:1139`); new `addUpdateSink(_:)`; `NetworkInitializationArguments` (`:430-462`) gains `networkEngineFactory: NetworkEngineFactory?` (default nil). `Keychain` (`:1327-1382`) unchanged |
| `TC/Network/Download.swift` | Holds `session: NetworkEngineSession` instead of `mtProto`/`requestService` (`:40-104`); the 6 builders (`:133-468`) call the same shared helper; the 401 handler moves into the engine's worker session; `wrapMethodBody` unchanged |
| `TC/Network/MultiplexedRequestManager.swift` | No change (uses `Download.rawRequest`) |
| `TC/State/UpdateMessageService.swift` | Conform to `NetworkEngineUpdateSink` instead of `MTMessageService`: `networkSessionDidReset` (= both session-change callbacks, `:25-31`), `networkSessionDidReceive(message:)` (= `:37-41`). Drop the unused `mtProto` back-pointer (`:10`, `:21-23`) |
| `TC/State/UnauthorizedAccountStateManager.swift` | Same for `UnauthorizedUpdateMessageService` (`:7-33`); `:110` uses `network.addUpdateSink` |
| `TC/State/AccountStateManager.swift` | `:443` `self.network.mtProto.add(...)` → `self.network.addUpdateSink(...)` |
| `TC/Account/Account.swift` | `:90`, `:105`, `:229` `network.mtProto.datacenterId` → `network.datacenterId`; everything else unchanged (MTContext stays) |
| `TC/SyncCore/SyncCore_NetworkSettings.swift` (or new shared-data struct, see 5.5) | Add `networkEngine: NetworkEngineKind?` under coding key `networkEngine_v1` |
| `TC/Network/ProxyServersStatuses.swift`, `TC/Settings/*.swift`, `TC/State/ManagedConfigurationUpdates.swift`, `TC/TelegramEngine/Localization/Localizations.swift` | No change (MTContext stays) |
| `TC/Network/NetworkFrameworkTcpConnectionInterface.swift`, `IOS/WebProxyTransport` | No change; passed to the Rust engine as `NetworkEngineTransportFactory` when NW or WEB proxy is active |
| `IOS/MTProtoEngineRust/` (new module) + `third-party/mtproto-engine` | `RustEngineFactory: NetworkEngineFactory`, FFI glue, callback queue, `MTContextChangeListener` bridge, transport bridge, log sink |
| `MAC/Telegram-Mac/app/AppDelegate.swift:824` | Pass `networkEngineFactory: RustEngineFactory()` (app target only) |
| `MAC/TelegramShare/ShareViewController.swift:123` | Pass nil (keeps the share extension free of the Rust lib) |
| `MAC/packages/SettingsUI/Sources/SettingsUI/DeveloperViewController.swift:135-139`, `:240-260` | New row "Network Engine: MtProtoKit / Rust (restart)" next to "Experimental Network" |
| `IOS/TelegramUI/Sources/AppDelegate.swift:581`, `IOS/DebugSettingsUI/Sources/DebugController.swift:1606-1618`, `:1890` | Same for iOS |

### 5.5 Where to read the flag

The flag must be known before the first session object is created, at `Network.swift:633`.
Everything else (workers, update sinks, `changedMasterDatacenterId`) inherits the `Network`'s engine.

`initializedNetwork` is called from 5 places, all of which already load settings in a
transaction just before:

| Call site | Settings already loaded |
|---|---|
| `Account.swift:341` (unauthorized), `:350` (authorized), `:366` (fresh) in `accountWithId` (`:268`) | AccountManager shared data `proxySettings` (`:292-298`); Postbox `networkSettings`, `appConfiguration` (`:300-327`) |
| `Account.swift:243` (`changedMasterDatacenterId`) | the same (`:234-240`) |
| `Account.swift:1797` (`standaloneStateManager`, iOS NSE) | shared `proxySettings`, Postbox `networkSettings` (`:1761-1772`) |

Recommended resolution order inside `initializedNetwork`:

1. `arguments.networkEngineFactory == nil` → MtProtoKit (extensions, macOS share, any process that
   did not opt in).
2. Kill switch: `appConfiguration.data["mtproto_engine_rust_disabled"]` → MtProtoKit (same pattern as
   `ios_killswitch_disable_downloadv2`, `Network.swift:663-666`).
3. Unsupported configuration → MtProtoKit. For example a WEB proxy without carrier support yet, or
   `isAppExtension` until the engine passes the NSE memory budget.
4. Developer choice: `networkSettings?.networkEngine` (Postbox preference, per account; the
   pattern the existing "Experimental Network" toggle uses), **or** a new AccountManager shared-data
   key (global for all accounts, readable by extensions in the same transaction as
   `proxySettings`). A shared-data key is better for a single developer switch; macOS keeps every
   account connected at once (2.8).
5. Optional launch override for testing: macOS `UserDefaults` (for example `-MTProtoEngine rust`)
   read in `AppDelegate` and passed through `NetworkInitializationArguments`.

The switch takes effect when a `Network` is created: next launch, account reload, login, or DC
migration. `Account.network` is a `let`; live swapping would need an engine host that pauses the
old session, waits for in-flight requests and migrates unsent ones. That risks duplicates (2.5)
and `AUTH_KEY_DUPLICATED` (6.1), so it is not recommended. The developer row should say
"requires restart" and offer to restart.

### 5.6 Build notes

- TelegramCore builds as SPM on macOS (`IOS/TelegramCore/Package.swift`, `-warnings-as-errors`)
  and with Bazel on iOS (`IOS/TelegramCore/BUILD`). Putting the protocols in TelegramCore and the
  Rust wrapper in a separate module that only app targets depend on keeps TelegramCore's
  dependency list unchanged.
- macOS app and TelegramShare deploy to **10.13**. The Rust static lib must be built with
  `MACOSX_DEPLOYMENT_TARGET=10.13` for arm64 + x86_64. NWConnection is only available ≥ macOS 14
  (`Network.swift:522`), so the Rust engine needs its own socket path (or the injected
  `MTTcpConnectionInterface`) on older systems.
- A new dependency on a package linked by TelegramShare can break the share extension at link
  time even when everything compiles. Inject the factory from the app target only.

---

## 6. Risks

### 6.1 Ways the switch becomes visible to users

| # | Failure | Mechanism | Mitigation |
|---|---|---|---|
| R1 | **Forced logout** (irreversible, server-side `auth.logOut`) | Any 401 except `SESSION_PASSWORD_NEEDED` on the main session leads to `Network.loggedOut` (2.11). Typical engine bugs: surfacing `AUTH_KEY_PERM_EMPTY` (temp key not bound) or a 401 that belongs to a foreign-DC worker; reporting `contextLoggedOut` from a failed bind that was not `ENCRYPTED_MESSAGE_INVALID` | Mirror `MTProto.m:2027-2043` and `MTRequestMessageService.m:850-872` exactly; workers never escalate. While the Rust engine is experimental, route its `networkSessionAuthorizationRequired` through `MTContext.checkIfLoggedOut` (bind probe) before calling `Network.loggedOut`, and log loudly |
| R2 | Re-login after switch | Persistent key regenerated or not found (wrong archive key, second Keychain, writing the master key with the wrong selector) | Invariants 4.4 (1) and (2); in phase 1 Rust never creates keys |
| R3 | `AUTH_KEY_DUPLICATED` (406, session file unusable) | Same auth key used concurrently from two IPs: old and new engine overlapping, IPv4 (one engine) vs IPv6 (the other), proxy vs direct | One live engine per `Network`; choose addresses through MTContext's transport schemes (same `preferForMedia`/IPv6 policy); no hot swap. TelegramCore only tolerates it in getDifference (`AccountStateManager.swift:874`, `:1462`) |
| R4 | Lost updates | Session change not reported (`new_session_created`, client reset, `updatesTooLong`), non-`Updates` constructors dropped, containers or gzip not unwrapped, sink attached after the first push | Emit `networkSessionDidReset` for all three cases (2.6); deliver all non-service messages; keep receive order; `AccountStateManager.reset()` polls difference on start, so a fresh engine catches up |
| R5 | Duplicated messages / actions | Resending on every reconnect; ignoring `invokeAfterMsg` (messages out of order); re-executing requests after `msgs_detailed_info` | Copy resend triggers from 2.5; implement dependency tags; rely on `random_id` only as a backstop |
| R6 | Device shows as a different session / extra `initConnection` | Different `deviceModel`/`systemVersion`/`appVersion`/`langPack`/`systemCode`, or hash not stored | Build initConnection from `context.apiEnvironment`; maintain `apiInitializationHash` (2.3) |
| R7 | Wrong message dates, TTL glitches | Time difference not pushed to MTContext (`EnqueueMessage.swift:593`) | `setGlobalTimeDifference` from Rust |
| R8 | "Connecting…"/"Updating…" stuck or flapping | Flags not mapped as in 2.7; status from workers; no actualization | Emit the same 6 fields; main session only |
| R9 | Slow downloads / upsell spam | No quick-ack; progress missing; `FLOOD_PREMIUM_WAIT` not passed to `onFloodWaitError`; `expectedResponseSize` cancel semantics (session reset on ≥512 KB) | Implement 2.2 fully |
| R10 | Proxy users lose connectivity | MTProxy (dd/ee fake-TLS secrets per `MTProxySecret`), SOCKS5 auth, WEB proxy carrier unsupported | Fall back to MtProtoKit at selection time (5.5 step 3) until supported |
| R11 | Data-usage screen frozen | Bytes not reported to `MTNetworkUsageManager` | Report per category and interface (1.d) |
| R12 | TON Connect "key mismatch" | Persistent key id changed (`WalletTonConnect.swift:203-210`) | Same as R2 |
| R13 | 2FA / passkey / login DC migration break | Error strings altered; `changedMasterDatacenterId` builds a new `Network` on the other engine | Pass errors verbatim; the engine choice is re-read with the same settings |
| R14 | Temp-key rebind storms | Two contexts (app + NSE, or both engines) binding different temp keys for the same permanent key; a new bind supersedes the old one, and the loser sees `AUTH_KEY_PERM_EMPTY` | Reuse ephemeral keys from MTContext; never create a temp key when a valid stored one exists |

### 6.2 iOS-specific constraints

- **Background suspension:** `shouldKeepConnection` turns false when the app leaves the foreground
  unless tasks are running (`IOS/TelegramUI/Sources/SharedWakeupManager.swift:1145-1151`). `setPaused(true)`
  must close sockets synchronously enough before suspension, cancel timers, and must not keep a
  background thread busy (watchdog kills). `resume` must work after arbitrary suspension: stale
  salts and time need a re-sync.
- **NotificationService:** a few seconds of wall clock, a deadline-bounded poll, tight memory
  (tens of MB), `supplementary: true` (no updates, no discovery), probes under a proxy. Keep the
  NSE on MtProtoKit (no factory) until the engine is measured there.
- **NetworkFramework path:** iOS defaults to NWConnection for beta users (`Network.swift:511-528`).
  It gives VPN, constrained-path and cellular behaviour that BSD sockets do not. Prefer the injected
  `NetworkFrameworkTcpConnectionInterface` on iOS.
- **WEB proxy carrier** (hidden WebView, `IOS/TelegramUI/Sources/WebProxyCarrierWindowHost.swift`)
  is main-app only and rides `shouldKeepConnection`. Reuse it through the transport factory.
- **APNS / reCAPTCHA verification** (`externalRequestVerificationStream`,
  `externalRecaptchaRequestVerification`) is iOS sign-in only; MTContext exposes
  `performExternalRequestVerificationWithNonce` / `performExternalRecaptchaRequestVerificationWithMethod` for the Rust engine.
- **CloudData** backup IPs (iCloud) are iOS only and stay in MTContext.
- **Shared database:** app and extensions share the account Postbox. MTContext instances in two
  processes already race on whole-dictionary keychain writes. The Rust engine must not add writes
  beyond what MtProtoKit would do (R14).
- **Bazel `-Werror`** for MtProtoKit and the strict iOS build: the Rust module needs its own
  `BUILD` like `third-party/wallet-engine/BUILD`.

### 6.3 macOS-specific constraints

- Deployment target 10.13 (5.6); NWConnection only on macOS ≥ 14.
- All accounts are connected simultaneously (`.always`), so N engine instances share one Rust
  runtime. Size the thread pool for this (MtProtoKit uses one shared manager queue).
- Sleep/wake drives a pause/resume cycle (`SharedWakeupManager.swift:99-116`). The engine must
  survive network changes during sleep.
- `accounts-shared-data` and the macOS "Experimental Network"/"Experimental Downloads" toggles
  already exist (`DeveloperViewController.swift:135-139`, `:240-260`). Add the engine row beside
  them and re-read on restart.
- Keep TelegramShare on MtProtoKit (no factory).

### 6.4 Verification hooks

- A logging prefix per session (`getLogPrefix`) and `[MTProto#...]`-style lines in `Logger.shared` so
  side-by-side logs of both engines can be diffed.
- A developer action "Switch engine and restart" that first prints the persistent key id (`getAuthKeyId`) and
  `datacenterAuthInfoById` selectors, then again after restart. They must match (4.4).
- Round-trip test: MtProtoKit → Rust → MtProtoKit with no 401, no `AUTH_KEY_DUPLICATED`, one
  getDifference per switch, the same session entry in "Active Sessions", and an unchanged TON Connect binding.

---

## Appendix A. MtProtoKit public surface used outside MtProtoKit (alphabetical)

`MTAdd`, `MTAesCtrDecrypt`, `MTAesDecrypt`, `MTAesDecryptBytesInplaceAndModifyIv`, `MTAesEncrypt`,
`MTAesEncryptBytesInplaceAndModifyIv`, `MTApiEnvironment`, `MTBackupAddressSignals`,
`MTBackupDatacenterData`, `MTBlockDisposable`, `MTCheckIsSafeB`, `MTCheckIsSafeG`,
`MTCheckIsSafeGAOrB`, `MTCheckIsSafePrime`, `MTCheckMod`, `MTContext`, `MTContextChangeListener`,
`MTDatacenterAddress`, `MTDatacenterAddressListData`, `MTDatacenterAddressSet`,
`MTDatacenterAuthInfo`, `MTDatacenterAuthInfoSelector`, `MTDeprecated`, `MTDisposable`, `MTExp`,
`MTExportAuthorizationResponseParser`, `MTExportedAuthorizationData`, `MTGzip`,
`MTHttpRequestOperation`, `MTHttpResponse`, `MTIncomingMessage`, `MTIPDataDecode`, `MTIsZero`,
`MTKeychain`, `MTLogSetEnabled`, `MTLogSetLoggingFunction`, `MTLogSetShortLoggingFunction`,
`MTMessageService`, `MTModMul`, `MTModSub`, `MTMul`, `MTNetworkSettings`,
`MTNetworkUsageCalculationInfo`, `MTNetworkUsageManager`, `MTNetworkUsageManagerInterface(WWAN|Other)`,
`MTOutputStream`, `MTPBKDF2`, `MTProto`, `MTProtoConnectionState`, `MTProtoDelegate`,
`MTProxyConnectivity`, `MTProxyConnectivityStatus`, `MTProxySecret`, `MTRequest`,
`MTRequestDatacenterAddressListParser`, `MTRequestErrorContext`, `MTRequestMessageService`,
`MTRequestMessageServiceDelegate`, `MTRequestNoopParser`, `MTRequestResponseInfo`, `MTRpcError`,
`MTRsaEncryptPKCS1OAEP`, `MTRsaFingerprint`, `MTSerialization`, `MTSha1`, `MTSha256`, `MTSignal`,
`MTSocksProxySettings`, `MTSubdataSha1`, `MTSubscriber`, `MTTcpConnectionInterface`,
`MTTcpConnectionInterfaceDelegate`, `MTTcpTransport`, `MTTransportScheme`.

Names that look like MtProtoKit but are not: `MTProtoConnectionFlags`, `MTProtoConnectionInfo`,
`MTProtoConnectionStatusDelegate` (TelegramCore-private, `Network.swift:26-158`); `MTBignum*`,
`MTPKCS` (EncryptionProvider implementations); `MTMath*`, `MTL*`, `MTK*` (math rendering and Metal).

## Appendix B. MtProtoKit internals referenced (for the Rust port)

| Behaviour | Location |
|---|---|
| Manager queue, pause/resume/stop, transport reset | `MPK/Sources/MTProto.m:140-361` |
| Session reset → services | `MTProto.m:363-393` |
| Service add/remove and service-task state | `MTProto.m:427-570` |
| Auth key selection per scheme | `MTProto.m:892-952` |
| -404 handling, AUTH_KEY_PERM_EMPTY interception | `MTProto.m:1933-2060`, `:2090-2170` |
| Incoming dispatch (bad_msg, acks, detailed info, new_session_created, generic) | `MTProto.m:2381-2577` |
| Context listeners in MTProto (schemes, auth info, tokens, API env) | `MTProto.m:2579-2812` |
| Request scheduling, decoration, error policy, quick-ack, progress, session change | `MPK/Sources/MTRequestMessageService.m:121-1293` |
| Keychain load and persistence writes | `MPK/Sources/MTContext.m:444-527`, `:609-889`, `:1496-1518` |
| Auth info map key | `MTContext.m:119-144` |
| Required key / token flows | `MTContext.m:1557-1611` |
| Logged-out probe | `MTContext.m:1774-1809`, `MPK/Sources/MTDiscoverConnectionSignals.m:353-377` |
| Key DH and temp key bind | `MPK/Sources/MTDatacenterAuthAction.m:59-186` (bind via `MTBindKeyMessageService` at `:156`) |
| Token transfer | `MPK/Sources/MTDatacenterTransferAuthAction.m:57-182` |
| initConnection hash | `MPK/Sources/MTApiEnvironment.m:422` |
| Network usage file | `MPK/Sources/MTNetworkUsageManager.m:12-97` |
