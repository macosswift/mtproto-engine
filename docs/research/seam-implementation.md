# Engine seam: implementation notes

Companion to `integration.md` (same folder). This records what the Swift seam between
TelegramCore and an MTProto engine looks like after the Option B change, why the MtProtoKit path
behaves exactly as before, and what a Rust `NetworkEngine` must honour.

Snapshot: macOS app worktree `mtproto-rust` (base `502236a04`), telegram-ios worktree
`mtproto-rust` (base `929449248d`). Changes are uncommitted. Path prefixes as in `integration.md`
(`TC/` = `submodules/telegram-ios/submodules/TelegramCore/Sources/`, `MAC/` = macOS repo root).

## 1. What changed, per file

| File | Change |
|---|---|
| `TC/Network/NetworkEngine.swift` (new) | Public seam: `NetworkEngineKind`, `NetworkEngineRequestOptions`, `NetworkEngineErrorContext`, `NetworkEngineResponseInfo`, `NetworkEngineResponse`, `NetworkEngineRequestFailure`, `NetworkEngineRequest`, `NetworkEngineUpdateSink`, `NetworkEngineConnectionState`, `NetworkEngineSessionDelegate`, `NetworkEngineRequestService`, `NetworkEngineSession`, `NetworkEngineSessionRole`, `NetworkEngine`, `NetworkEngineFactory` (full text in section 3) |
| `TC/Network/MtProtoKitEngine.swift` (new) | Default engine. `MTProtoConnectionFlags`/`MTProtoConnectionInfo`/`MTProtoConnectionStatusDelegate` moved verbatim from `Network.swift`. `MtProtoKitSession` owns `MTProto` + `MTRequestMessageService` and contains the MTProto construction moved from `initializedNetwork` (role `.main`) and from `Download.init` (role `.worker`), the worker 401 token re-transfer moved from `Download.requestMessageServiceAuthorizationRequired`, and the worker teardown moved from `Download.deinit` (`stop()`). `MtProtoKitRequestService` is the single place that turns a `NetworkEngineRequest` into an `MTRequest`. `MtProtoKitUpdateSinkService` is the `MTMessageService` shim that forwards to a `NetworkEngineUpdateSink` |
| `TC/Network/Network.swift` | `WrappedRequestMetadata`/`WrappedRequestShortMetadata` are now `public` (they travel in `NetworkEngineRequest`; initializers and the dependency `tag` stay internal). `NetworkInitializationArguments` gains `networkEngineFactory: NetworkEngineFactory?` as a trailing defaulted init parameter (`= nil`), so every existing call site compiles unchanged. `initializedNetwork` gains `networkEngineSettings:`; MTContext setup is untouched; the MTProto block is replaced by `resolveNetworkEngine(...)` + `engine.makeSession(role: .main, delegate:)`. New private `NetworkMainSessionDelegate` holds the connection-status derivation (verbatim logic, over booleans instead of flags) and forwards 401/406 to `Network`. `Network` drops `MTRequestMessageServiceDelegate`, `mtProto`, the MT `requestService` and `connectionStatusDelegate`; it holds `engine`, `mainSession`, `requestService: NetworkEngineRequestService`, `mainSessionDelegate`. New: `public var engineKind`, internal `addUpdateSink(_:)`. `request`/`requestWithAdditionalInfo` build a `NetworkEngineRequest`; shared helpers `networkRequestErrorPolicy(...)` (flood wait / server error policy) and `networkRequestDependency(tag:)`. `makeWorker` passes `engine` to `Download`. `getAuthKeyId` reads `self.context` (the same object `mtProto.context` returned). `Keychain`, `NetworkHelper`, proxy handling, usage stats: unchanged |
| `TC/Network/Download.swift` | Holds `session: NetworkEngineSession` + `requestService: NetworkEngineRequestService` instead of `mtProto`/`requestService`; no longer an `MTRequestMessageServiceDelegate`. `init` gains `engine:` and calls `makeSession(role: .worker(...), delegate: nil)`. The 6 builders build `NetworkEngineRequest`s; `wrapMethodBody` and the static `uploadPart` are unchanged |
| `TC/State/UpdateMessageService.swift` | `UpdateMessageService` conforms to `NetworkEngineUpdateSink` instead of `MTMessageService`: `networkSessionDidReset()` (was both session-change callbacks, still emits `[.reset]`), `networkSessionDidReceive(message:)` (same `BoxedMessage` -> `Api.Updates` cast). `mtProto` back-pointer removed (now held by the shim, see 2.3) |
| `TC/State/UnauthorizedAccountStateManager.swift` | Same for `UnauthorizedUpdateMessageService` (reset stays a no-op); attaches via `network.addUpdateSink` |
| `TC/State/AccountStateManager.swift` | `network.mtProto.add(updateService)` -> `network.addUpdateSink(updateService!)` |
| `TC/Account/Account.swift` | `network.mtProto.datacenterId` -> `network.datacenterId` (3 sites; `MTProto.datacenterId` is only ever assigned in `-[MTProto init...]`, from the same value). The 4 AccountManager transactions that read `proxySettings` before `initializedNetwork` also read `SharedDataKeys.networkEngineSettings`, passed to all 5 `initializedNetwork` calls |
| `TC/SyncCore/SyncCore_Namespaces.swift` | `SharedDataKeyValues.networkEngineSettings = 12`, `SharedDataKeys.networkEngineSettings` |
| `TC/SyncCore/SyncCore_NetworkEngineSettings.swift` (new) | `public struct NetworkEngineSettings: Codable, Equatable { var engine: NetworkEngineKind }` |
| `TC/Settings/NetworkEngineSettings.swift` (new) | `updateNetworkEngineSettings(accountManager:_:)` |
| `MAC/packages/SettingsUI/Sources/SettingsUI/DeveloperViewController.swift` | "Network Engine" row right after "Experimental Network": a context selector with "MtProtoKit" / "Rust (restart required)". The value shows the persisted choice, plus `(active: X)` when it differs from `context.account.network.engineKind`. Choosing writes the shared setting and, if the choice differs from the running engine, offers "Restart" (`verifyAlert` -> `restartApp()`, the pattern `InAppLinks.swift` uses for "enable logs") |

Not changed: `MultiplexedRequestManager`, `ProxyServersStatuses`, `Keychain`/`makeExclusiveKeychain`,
`MAC/Telegram-Mac/app/AppDelegate.swift`, `MAC/TelegramShare/ShareViewController.swift`, and all iOS
`NetworkInitializationArguments(...)` sites (`TelegramUI/Sources/AppDelegate.swift`,
`ShareExtensionContext.swift`, `NotificationContentContext.swift`, `NotificationService.swift`,
`SiriIntents/IntentHandler.swift`): the factory parameter is defaulted, so all of them pass nil.
No caller outside TelegramCore used `network.mtProto`, `Network.requestService`, `Download.mtProto`
or `Network.requestMessageServiceAuthorizationRequired` (grepped both repos), so no compatibility
accessor was needed. Every public `Network`/`Download` request API keeps its exact signature.

## 2. Why the MtProtoKit path is unchanged

### 2.1 Engine selection

`resolveNetworkEngine` returns `MtProtoKitEngine` whenever `arguments.networkEngineFactory == nil`,
which is every process today (no call site passes a factory). The only observable additions on the
default path are one `Logger.shared.log("Network", "Account <id>: engine mtProtoKit (no factory, preferred <x>)")`
line per `Network` creation, and one extra `getSharedData` read of a key that does not exist unless
the developer row was used.

### 2.2 Object graph, construction order, ObjC surface

`MtProtoKitSession(role: .main)` runs the statements that used to be in `initializedNetwork`
(`MTProto(... requiredAuthToken: nil, authTokenMasterDatacenterId: 0)`, `useTempAuthKeys`,
`checkForProxyConnectionIssues = true`, `MTRequestMessageService(context:)`, the status delegate,
`mtProto.delegate = ...`, `mtProto.add(requestService)`) in the same order, then sets
`didReceiveSoftAuthResetError` and `requestService.delegate`, which `Network.init` used to set a few
statements later. Nothing can call either before `initializedNetwork` returns: the MTProto is
created paused and no request exists yet. Context listeners are still registered in the same order
(MTProto, MTRequestMessageService, then `NetworkHelper`).

`MtProtoKitSession(role: .worker)` runs `Download.init`'s statements verbatim (token rule
`!isCdn && dc != master`, `getLogPrefix` over an always-nil `Atomic`, `cdn`, `useTempAuthKeys && !isCdn`,
`media`, `forceBackgroundRequests = true`, delegate, `add`). `Download.deinit` calls `session.stop()`
= `remove(requestService)`, `stop()`, `finalizeSession()`, then disposes the pause/resume
subscription, as before. The main session is still never stopped.

Objects MtProtoKit talks to implement exactly the same selectors as before (MtProtoKit dispatches
on `respondsToSelector:`):

- `MTProtoDelegate`: the same `MTProtoConnectionStatusDelegate` class, moved verbatim; set on the
  main MTProto only, as before.
- `MTRequestMessageServiceDelegate`: `MtProtoKitSession` implements only
  `requestMessageServiceAuthorizationRequired:` (as `Network` and `Download` did). Main role forwards
  to `Network.mainSessionAuthorizationRequired()` (same log line, same `loggedOut?()` call); worker
  role runs the old `Download` body (`updateAuthTokenForDatacenter(nil)` +
  `authTokenForDatacenter(withIdRequired:authToken:masterDatacenterId:)` with the MTProto's
  `requiredAuthToken` / `authTokenMasterDatacenterId`). Workers still never reach `loggedOut`.
- `MTMessageService` (updates): `MtProtoKitUpdateSinkService` implements the same four selectors the
  two Swift update services implemented: `mtProtoWillAddService:`, `mtProtoDidChangeSession:`,
  `mtProtoServerDidChangeSession:firstValidMessageId:otherValidMessageIds:`,
  `mtProto:receivedMessage:authInfoSelector:networkType:` (checked with `otool -oV` on the old
  `UpdateMessageService.o`). Calls are forwarded synchronously on the same `managerQueue`.

### 2.3 Lifetimes (the non-obvious part)

- **The update service retains the main MTProto.** `integration.md` 1.a says the Swift
  `mtProtoWillAdd(_:)` does not match `mtProtoWillAddService:`. It does: the compiled class lists
  `mtProtoWillAddService:` and `-[MTProto addMessageService:]` calls it synchronously, so both update
  services stored a strong `mtProto`, forming MTProto -> service -> MTProto. Once
  `AccountStateManager.reset()` / `UnauthorizedAccountStateManager.reset()` has attached it, the
  main MTProto (and its MTRequestMessageService) outlives `Network` and keeps whatever paused or
  resumed state it had. The shim keeps that cycle (it stores the MTProto in `mtProtoWillAdd`) so the
  default path is identical. This is a pre-existing leak worth fixing separately, with care: fixing it
  changes behaviour after logout (see the next point).
- **Request signals retain the request service, not the Network.** `Network.request` used to capture
  `MTRequestMessageService` strongly in the signal generator and weakly in the disposable; the
  service holds its MTProto weakly, so a request submitted after the MTProto died was silently
  dropped. `NetworkEngineRequestService` is a separate object for exactly this reason: Network captures
  `MtProtoKitRequestService` (which only holds the `MTRequestMessageService`) in the generator, and the
  disposable it returns captures the `MTRequestMessageService` weakly, as before. Capturing the
  session instead would have kept the MTProto alive through any retained cold signal.
- **`Download` request disposables retain the `Download`.** Five builders captured `self` in the
  disposable (`self.requestService.removeRequest`), which is what keeps a worker obtained through
  `network.download()/upload()/background()` alive until its requests finish. They now go through
  `Download.addRequest`, whose `ActionDisposable` keeps `self` alive (`withExtendedLifetime`) until
  disposed. `rawRequest` keeps its weak disposal (MultiplexedRequestManager owns those workers).
- `MtProtoKitSession` is held only by its `Network`/`Download` (MTProto and MTRequestMessageService
  reference their delegates weakly), so delegate callbacks stop when the owner goes away, as they did
  when the owner itself was the delegate. `Network` holds `NetworkMainSessionDelegate` strongly the
  way it held `connectionStatusDelegate`; the delegate references the status `Promise` weakly, like
  the old `[weak connectionStatus]` closure.

### 2.4 Request field mapping

`MtProtoKitRequestService.add` always sets `dependsOnPasswordEntry = false` (MTRequest defaults to
`true`; every builder set `false`), `needsTimeoutTimer` and `expectedResponseSize` from
`options` (assigning the default `false`/`0` equals not assigning), and
`shouldContinueExecutionWithErrorContext` (every builder set one; a nil context still returns `true`).
`acknowledgementReceived`, `progressUpdated` and `shouldDependOnRequest` are assigned only when the
request has the corresponding closure, so `needsQuickAck = acknowledgementReceived != nil` is
unchanged. Per builder:

| Builder | expectedResponseSize | needsTimeoutTimer | error policy (`networkRequestErrorPolicy`) | quick ack / progress / dependency | shortMetadata |
|---|---|---|---|---|---|
| `Network.requestWithAdditionalInfo` | 0 | false | automaticFloodWait, onFloodWaitError | ack + progress always set (quick ack is requested even when `info` lacks `.acknowledgement`, as before); dependency if `tag != nil` | short |
| `Network.request` | 0 | false | automaticFloodWait, onFloodWaitError | dependency if `tag != nil` | short |
| `Download.uploadPart` | 0 | false | `automaticFloodWait: true`, onFloodWaitError (= old "callback, then always continue") | none | short |
| `Download.webFilePart` | `Int32(length)` | `useRequestTimeoutTimers` | `true, nil, false` (= old `{ return true }`) | none | **long** description, as before |
| `Download.part` | `Int32(length)` | `useRequestTimeoutTimers` | `true, nil, false` | none | short |
| `Download.request` | `?? 0` | `useRequestTimeoutTimers` | automaticFloodWait, onFloodWaitError | none | short |
| `Download.requestWithAdditionalData` | `?? 0` | `useRequestTimeoutTimers` | + `failOnServerErrors` | none | short |
| `Download.rawRequest` | `?? 0` | `useRequestTimeoutTimers` | + `failOnServerErrors` | none | short |

`networkRequestErrorPolicy(automaticFloodWait:onFloodWaitError:failOnServerErrors:)` is the old
closure body: call `onFloodWaitError(text)` when `floodWaitSeconds > 0` and the text is set; return
`false` for a flood wait when `!automaticFloodWait`; return `false` for `internalServerErrorCount > 0`
when `failOnServerErrors`; else `true`. With `failOnServerErrors: false` the last test never fires,
with `onFloodWaitError: nil` the first never fires, so each row reproduces its old closure exactly.
The dependency closure is the old one split in two (`other.metadata as? WrappedRequestMetadata` in
the mapper, `metadata.tag` + `tag.shouldDependOn` in `networkRequestDependency`).

`completed` maps `(result, info, error)` to `.failure(error, info)` when `error != nil`, else
`.success(result, info)`. `MTRequestMessageService.m` has a single `completed(...)` call site and
always passes a non-nil `MTRequestResponseInfo` and, without an error, a non-nil parser result; the
mapper still reproduces the old outcome for the impossible nil cases (nil info becomes
`timestamp 0, networkType 1, duration 0`, which is what `info?.timestamp ?? 0`,
`info?.networkType == 0 ? .wifi : .cellular` and `info?.duration ?? 0` produced; a nil result stays
nil inside `Any`, so `as! BoxedMessage` traps where it trapped before). The builders' success/failure
bodies are otherwise verbatim, including `TL_VERIFICATION_ERROR` and the `.fileCdnRedirect` no-op.

### 2.5 Threading

No queue hop was added. Request submission, cancellation, completion, ack, progress, status and
update callbacks run on exactly the threads they ran on before (the caller's thread, then
MtProtoKit's `managerQueue`). Pause/resume still run in the same `deliverOn(queue)` subscriptions
with the same log lines.

## 3. Public protocol API (`TC/Network/NetworkEngine.swift`, final)

```swift
import Foundation
import SwiftSignalKit
import MtProtoKit

/// The MTProto implementation that carries a `Network`'s sessions.
public enum NetworkEngineKind: String, Codable, Equatable {
    case mtProtoKit
    case rust
}

/// Per-request transport options.
public struct NetworkEngineRequestOptions: Equatable {
    /// When a request with `expectedResponseSize >= 512 KB` is cancelled while it is in flight,
    /// the session is reset so that the large response is not downloaded.
    public var expectedResponseSize: Int32
    /// When set, a pending request that sees no transport activity for 5 seconds triggers a
    /// secure transport reset and a new transport transaction.
    public var needsTimeoutTimer: Bool
    
    public init(expectedResponseSize: Int32 = 0, needsTimeoutTimer: Bool = false) {
        self.expectedResponseSize = expectedResponseSize
        self.needsTimeoutTimer = needsTimeoutTimer
    }
}

/// Snapshot of the per-request error state passed to `NetworkEngineRequest.shouldContinueAfterError`.
/// The underlying state is cumulative for the lifetime of a request: a value set by an earlier
/// error (for example `floodWaitSeconds`) is still present when a later error is reported.
public struct NetworkEngineErrorContext: Equatable {
    public var floodWaitSeconds: Int
    public var floodWaitErrorText: String?
    public var internalServerErrorCount: Int
    
    public init(floodWaitSeconds: Int, floodWaitErrorText: String?, internalServerErrorCount: Int) {
        self.floodWaitSeconds = floodWaitSeconds
        self.floodWaitErrorText = floodWaitErrorText
        self.internalServerErrorCount = internalServerErrorCount
    }
}

/// Metadata of the message that completed a request.
public struct NetworkEngineResponseInfo: Equatable {
    /// Server time of the response message, in seconds since 1970.
    public var timestamp: Double
    /// Network the response arrived on: 0 means wifi or other, any other value means cellular.
    public var networkType: Int32
    /// Seconds between sending the request and receiving the response, or 0 when unknown.
    public var duration: Double
    
    public init(timestamp: Double, networkType: Int32, duration: Double) {
        self.timestamp = timestamp
        self.networkType = networkType
        self.duration = duration
    }
}

/// A successful response. `result` is the value returned by `NetworkEngineRequest.parse`.
public struct NetworkEngineResponse {
    public let result: Any
    public let info: NetworkEngineResponseInfo
    
    public init(result: Any, info: NetworkEngineResponseInfo) {
        self.result = result
        self.info = info
    }
}

/// A failed request. `error` carries the `rpc_error` code and text exactly as received,
/// or an error synthesized by the engine (for example `500 TL_PARSING_ERROR`).
public struct NetworkEngineRequestFailure: Error {
    public let error: MTRpcError
    public let info: NetworkEngineResponseInfo
    
    public init(error: MTRpcError, info: NetworkEngineResponseInfo) {
        self.error = error
        self.info = info
    }
}

/// One RPC call. Built by TelegramCore and executed by a `NetworkEngineRequestService`.
public final class NetworkEngineRequest {
    /// The TL-serialized API function. Opaque to the engine.
    public let payload: Data
    /// Description used for logging. Also the carrier of the dependency tag read by `dependsOn`.
    public let metadata: WrappedRequestMetadata
    /// Short description used for logging.
    public let shortMetadata: WrappedRequestShortMetadata
    /// Parses the body of `rpc_result` (after gzip unwrapping). A nil result must complete the
    /// request with `500 TL_PARSING_ERROR` and clear the auth key's `apiInitializationHash`.
    public let parse: (Data) -> Any?
    public let options: NetworkEngineRequestOptions
    /// Asked on `FLOOD_WAIT_X`, `FLOOD_PREMIUM_WAIT_X` and `500`/`-500` errors. `true` retries the
    /// request after the wait (2 seconds for server errors), `false` completes it with the error.
    public let shouldContinueAfterError: (NetworkEngineErrorContext) -> Bool
    /// When set, the request is sent wrapped in `invokeAfterMsg` pointing at the latest earlier
    /// pending request whose metadata this closure accepts.
    public let dependsOn: ((WrappedRequestMetadata) -> Bool)?
    /// When set, a quick ack is requested for the request and this closure is called when it arrives.
    public let acknowledged: (() -> Void)?
    /// When set, called with the receive progress of the response packet and the packet length.
    public let progress: ((Float, Int) -> Void)?
    /// Called exactly once, unless the request is cancelled first.
    public let completed: (Result<NetworkEngineResponse, NetworkEngineRequestFailure>) -> Void
    
    init(
        payload: Data,
        metadata: WrappedRequestMetadata,
        shortMetadata: WrappedRequestShortMetadata,
        parse: @escaping (Data) -> Any?,
        options: NetworkEngineRequestOptions,
        shouldContinueAfterError: @escaping (NetworkEngineErrorContext) -> Bool,
        dependsOn: ((WrappedRequestMetadata) -> Bool)?,
        acknowledged: (() -> Void)?,
        progress: ((Float, Int) -> Void)?,
        completed: @escaping (Result<NetworkEngineResponse, NetworkEngineRequestFailure>) -> Void
    ) {
        self.payload = payload
        self.metadata = metadata
        self.shortMetadata = shortMetadata
        self.parse = parse
        self.options = options
        self.shouldContinueAfterError = shouldContinueAfterError
        self.dependsOn = dependsOn
        self.acknowledged = acknowledged
        self.progress = progress
        self.completed = completed
    }
}

/// Receiver of non-RPC messages pushed by the server on a session.
public protocol NetworkEngineUpdateSink: AnyObject {
    /// The session was reset on either side (a new client session, or `new_session_created`).
    /// Updates may have been lost, so the receiver must resynchronize.
    func networkSessionDidReset()
    /// A parsed message that is not an MTProto service message or an `rpc_result`, in receive
    /// order. `message` is the value produced by `MTContext.serialization.parseMessage`.
    func networkSessionDidReceive(message: Any)
}

public struct NetworkEngineConnectionState: Equatable {
    public var isNetworkAvailable: Bool
    public var isConnected: Bool
    public var isUpdatingConnectionContext: Bool
    public var isPerformingServiceTasks: Bool
    public var proxyAddress: String?
    public var proxyHasConnectionIssues: Bool
    
    public init(isNetworkAvailable: Bool, isConnected: Bool, isUpdatingConnectionContext: Bool, isPerformingServiceTasks: Bool, proxyAddress: String?, proxyHasConnectionIssues: Bool) {
        self.isNetworkAvailable = isNetworkAvailable
        self.isConnected = isConnected
        self.isUpdatingConnectionContext = isUpdatingConnectionContext
        self.isPerformingServiceTasks = isPerformingServiceTasks
        self.proxyAddress = proxyAddress
        self.proxyHasConnectionIssues = proxyHasConnectionIssues
    }
}

/// Events of the main session. Worker sessions are created without a delegate.
public protocol NetworkEngineSessionDelegate: AnyObject {
    /// A `401` other than `SESSION_PASSWORD_NEEDED` and `AUTH_KEY_PERM_EMPTY` on the main session.
    /// This logs the account out irreversibly.
    func networkSessionAuthorizationRequired()
    /// Any `406` error.
    func networkSessionSoftAuthReset()
    func networkSessionConnectionStateChanged(_ state: NetworkEngineConnectionState)
}

/// Request scheduler of a session.
///
/// `Network` keeps a strong reference to its request service inside every cold request signal.
/// A request service must therefore not keep the session's connection alive by itself: once the
/// session is released, `add` must be a no-op whose request never completes.
public protocol NetworkEngineRequestService: AnyObject {
    /// Submits a request from any thread without blocking. Disposing the returned disposable
    /// cancels the request; it is safe from any thread, at any time, also after the session is gone.
    /// No callback of the request may run after its cancellation has been processed.
    func add(_ request: NetworkEngineRequest) -> Disposable
}

/// One MTProto session (one session id, one transport) to one datacenter.
public protocol NetworkEngineSession: AnyObject {
    var datacenterId: Int { get }
    var requestService: NetworkEngineRequestService { get }
    /// Sessions are created paused. Pausing drops the transport; resuming reconnects.
    func setPaused(_ paused: Bool)
    func addUpdateSink(_ sink: NetworkEngineUpdateSink)
    /// Tears a worker session down. The main session is never stopped explicitly.
    func stop()
}

public enum NetworkEngineSessionRole: Equatable {
    /// The account's session to its master datacenter: receives updates and drives the connection status.
    case main
    /// A download or upload session. For a foreign datacenter that is not a CDN, the session
    /// imports the authorization from `masterDatacenterId` and re-imports it after a `401`.
    case worker(masterDatacenterId: Int, isMedia: Bool, isCdn: Bool)
}

/// Creates sessions bound to one `MTContext`, which stays the owner of configuration and
/// persisted state (auth keys, salts, tokens, addresses, time difference).
public protocol NetworkEngine: AnyObject {
    var kind: NetworkEngineKind { get }
    /// `delegate` is held weakly and must be set before the session can report anything.
    func makeSession(datacenterId: Int, role: NetworkEngineSessionRole, usageCalculationInfo: MTNetworkUsageCalculationInfo?, delegate: NetworkEngineSessionDelegate?) -> NetworkEngineSession
}

/// Supplies an alternative engine. Passed through `NetworkInitializationArguments`, so a process
/// that does not pass one (extensions) stays on MtProtoKit.
public protocol NetworkEngineFactory {
    /// Returns nil when the engine cannot serve this context (for example an unsupported proxy
    /// configuration); the network then uses MtProtoKit. The TCP connection factory to use is
    /// `context.makeTcpConnectionInterface`, which changes when the proxy changes.
    func makeEngine(context: MTContext, isAppExtension: Bool) -> NetworkEngine?
}
```

Deviations from `integration.md` 5.2, and why:

- `add`/`cancel` moved off the session into `NetworkEngineRequestService.add(_:) -> Disposable`
  (lifetime rule in 2.3; a `Disposable` also lets the MtProtoKit engine return the original
  weak-capturing disposable unchanged).
- `delegate` is a `makeSession` argument instead of a settable property, so the session can never
  report state before its delegate exists (the old code assigned the status closure before
  `mtProto.delegate`).
- `completed` carries `NetworkEngineResponseInfo` (timestamp, raw networkType, duration) in both
  success and failure, because `Download.requestWithAdditionalData`/`rawRequest` read the timestamp
  of errors too.
- `wantsQuickAck`/`wantsProgress` dropped: a non-nil `acknowledged`/`progress` closure is the flag,
  exactly like MtProtoKit.
- `NetworkEngineTransportFactory` dropped from `makeEngine`: the TCP factory lives on
  `MTContext.makeTcpConnectionInterface` and `Network.updateProxySettings` swaps it at runtime (WEB
  proxy carrier on/off), so a value captured at engine creation would go stale. The engine should read
  `context.makeTcpConnectionInterface` when it opens a connection.
- `NetworkEngineRequest.init` is internal: only TelegramCore builds requests.

## 4. Persisted setting

- Store: AccountManager shared data (global for all accounts, readable by extensions), key
  `SharedDataKeys.networkEngineSettings` = `ValueBoxKey` with Int32 `12` at offset 0
  (`SharedDataKeyValues.networkEngineSettings`; 12 was never used by a shared-data key in the
  history of `SyncCore_Namespaces.swift`; app keys use `+1000`).
- Value: `NetworkEngineSettings` encoded as a `PreferencesEntry` (Postbox adapted Codable) with one
  string field `"engine_v1"` = `NetworkEngineKind.rawValue` (`"mtProtoKit"` or `"rust"`). Missing
  entry, missing field or an unknown value decode as `.mtProtoKit`.
- Writer: `updateNetworkEngineSettings(accountManager:_:)` (macOS Developer row).
- Reader: the AccountManager transactions in `accountWithId`, `UnauthorizedAccount.changedMasterDatacenterId`
  and `standaloneStateManager`, i.e. read once per `Network` creation. A change takes effect on the
  next `Network` (relaunch, account load, login, DC migration); a live `Network` never switches.
- Resolution in `initializedNetwork` (`resolveNetworkEngine`):
  1. `arguments.networkEngineFactory == nil` -> MtProtoKit (all processes today, TelegramShare and every
     iOS extension forever unless they opt in).
  2. `appConfiguration.data["mtproto_engine_rust_disabled"]` present (any value, same presence rule as
     `ios_killswitch_disable_downloadv2`) -> MtProtoKit. Note `changedMasterDatacenterId` reads the
     unauthorized account's app configuration and the NSE path passes `.defaultValue`, so the kill
     switch only reaches authorized accounts that already fetched `help.getAppConfig`.
  3. Persisted choice `.mtProtoKit` -> MtProtoKit.
  4. Persisted choice `.rust` -> `factory.makeEngine(context:isAppExtension:)`; nil -> MtProtoKit.
  Each branch logs `Network: Account <id>: engine ...` with the reason.

## 5. What the Rust engine must honour (beyond integration.md)

1. **Request service lifetime** (2.3): hold the session weakly. After the session is gone, `add` must
   accept the request and never complete it; the returned disposable must be callable from any
   thread, any time, and must not resurrect anything.
2. **No callback after cancellation.** MtProtoKit removes the request on its queue before any later
   response is matched, and drops responses for unknown requests. Dispose may race with a completion
   already being delivered on the engine queue; deliver at most one `completed`.
3. **Error context is cumulative per request** (`floodWaitSeconds` from an earlier FLOOD_WAIT is still
   set when a later 500 is reported). `shouldContinueAfterError` is asked only (a) for 500/-500 (any
   text, checked before the `500 MSG_WAIT_FAILED` branch, which is therefore unreachable) and (b) for
   errors whose text contains `FLOOD_WAIT_<n>` or `FLOOD_PREMIUM_WAIT_<n>` with a parsable `n`. Other
   420s (`FROZEN_METHOD_INVALID`, or a 420 without such a text) and FLOOD texts without a number
   complete immediately with the error, without asking.
4. **Quick ack**: `acknowledged` can fire more than once (once per matching quick-ack token; resends
   get new tokens). `requestWithAdditionalInfo` always asks for it.
5. **Dependency resolution scans all pending requests newest-first** (not only earlier ones) and takes
   the first one `dependsOn` accepts; `PendingMessageRequestDependencyTag` itself only accepts lower
   message ids. If that request has no msg_id yet, the dependency is resolved when both go out in the
   same container.
6. **`progress`** reports `(fraction, packetLength)` of the packet carrying the response, keyed by the
   msg_id of the request's current transmission.
7. **Update sinks**: emit `networkSessionDidReset` for a client-side session reset *and* for
   `new_session_created`; the unauthorized sink ignores both. `message` passed to
   `networkSessionDidReceive` must be what `context.serialization.parseMessage` returns
   (`BoxedMessage`), for every non-service message, in receive order, on one serial queue.
8. **401 handling**: `networkSessionAuthorizationRequired` only from the main session and only for a
   401 that is neither `SESSION_PASSWORD_NEEDED` nor `AUTH_KEY_PERM_EMPTY` (the latter never leaves the
   MTProto layer). On a worker every such 401 runs the token re-transfer
   (`updateAuthTokenForDatacenter(nil)` + `authTokenForDatacenter(withIdRequired:authToken:masterDatacenterId:)`
   with the session's required token and master DC); then, if the session requires a token and the
   text contains `SESSION_REVOKED` or `AUTH_KEY_UNREGISTERED`, the request is parked and resent once the
   token arrives, otherwise it completes with the 401.
9. **Connection state** is reported by the main session only; MtProtoKit reports
   `networkAvailable = false`, `connectionState = nil`, `updating = false` whenever it has no
   transport (paused), which folds to `.waitingForNetwork`.
10. **Sessions start paused**; `setPaused` is called from `Network.queue` (main) or after a main-queue
    `combineLatest` (workers) and must be idempotent.
11. **The main session is never stopped**, only released (and, through the update-sink cycle,
    not even released). A Rust main session must therefore pause/close its transport when it is
    deallocated and must not depend on `stop()`.
12. **`expectedResponseSize >= 512 KB` cancel-in-flight resets the session** (`resetSessionInfo:true`:
    new session id if the session can send, `mtProtoDidChangeSession` to every service, transport
    reset). On the main session that would also reset update sinks; only workers use large sizes today.
13. **Transport factory**: use `context.makeTcpConnectionInterface` (nil = plain sockets) at connect
    time. `Network.updateProxySettings` reassigns it on every proxy change without any MTContext
    notification; the `updateApiEnvironment` that follows notifies listeners
    (`contextApiEnvironmentUpdated`) only when the socks/MTProxy settings actually changed, which is
    when MtProtoKit resets its transport.
14. **Logging**: MtProtoKit worker sessions attach a `getLogPrefix` that is always nil today.

## 6. Build verification

All builds from the app worktree with
`xcodebuild -workspace Telegram-Mac.xcworkspace -scheme <Scheme> -configuration Debug -destination 'platform=macOS,arch=arm64' -derivedDataPath ~/Library/Developer/Xcode/DerivedData/Telegram-mtproto-rust build`
(logs in the session scratchpad, `logs/seam-build-*.log`):

| Run | Scheme | Result |
|---|---|---|
| 1 | `Telegram` | `** BUILD SUCCEEDED **`, exit 0, 0 errors |
| 1 | `TelegramShare` | `** BUILD SUCCEEDED **`, exit 0, 0 errors |
| 2 (final sources) | `Telegram` | `** BUILD SUCCEEDED **`, exit 0, 0 errors |
| 2 (final sources) | `TelegramShare` | `** BUILD SUCCEEDED **`, exit 0, 0 errors |

TelegramCore builds with `-warnings-as-errors`; no warning was reported for any TelegramCore file.
The only `SettingsUI` warning (`EditThemeController.swift:335`) predates this change. The iOS
(Bazel) build was not run; the changed TelegramCore code has no `#if os(iOS)` branches and every iOS
`NetworkInitializationArguments(...)` call compiles through the defaulted parameter.

## 7. Not done (out of scope)

- No Rust factory is passed anywhere (`AppDelegate.swift` untouched); the Developer row therefore
  shows `Rust (active: MtProtoKit)` after a restart until a factory exists.
- iOS Debug Settings row (spec 5.4) not added.
- The MTProto/update-service retain cycle (2.3) is preserved on purpose.
