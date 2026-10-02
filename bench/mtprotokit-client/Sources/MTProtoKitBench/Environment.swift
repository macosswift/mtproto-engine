import Foundation
import MtProtoKit
import OpenSSLEncryption

let benchVerbose = ProcessInfo.processInfo.environment["MTPROTOKIT_BENCH_LOG"] != nil

func installLogging() {
    if ProcessInfo.processInfo.environment["MTPROTOKIT_BENCH_NO_LOG_SINK"] != nil {
        return
    }
    MTLogSetLoggingFunction({ value in
        if benchVerbose, let value = value {
            writeStderr("MT \(value)")
        }
    })
    MTLogSetShortLoggingFunction({ value in
        if benchVerbose, let value = value {
            writeStderr("MTS \(value)")
        }
    })
    MTLogSetEnabled(benchVerbose)
}

final class InMemoryKeychain: NSObject, MTKeychain {
    private let lock = NSLock()
    private var storage: [String: Data] = [:]

    private func get(_ key: String) -> Data? {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.storage[key]
    }

    private func set(_ key: String, _ value: Data) {
        self.lock.lock()
        self.storage[key] = value
        self.lock.unlock()
    }

    private func remove(_ key: String) {
        self.lock.lock()
        self.storage.removeValue(forKey: key)
        self.lock.unlock()
    }

    func setObject(_ object: Any!, forKey aKey: String!, group: String!) {
        guard let object = object else {
            return
        }
        MTContext.perform(objCTry: {
            if let data = try? NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: false) {
                self.set(group + ":" + aKey, data)
            }
        })
    }

    func dictionary(forKey aKey: String!, group: String!) -> [AnyHashable: Any]? {
        guard let aKey = aKey, let group = group, let data = self.get(group + ":" + aKey) else {
            return nil
        }
        return (MTDeprecated.unarchiveDeprecated(with: data) as? NSDictionary) as? [AnyHashable: Any]
    }

    func number(forKey aKey: String!, group: String!) -> NSNumber? {
        guard let aKey = aKey, let group = group, let data = self.get(group + ":" + aKey) else {
            return nil
        }
        return MTDeprecated.unarchiveDeprecated(with: data) as? NSNumber
    }

    func removeObject(forKey aKey: String!, group: String!) {
        self.remove(group + ":" + aKey)
    }
}

final class BenchSerialization: NSObject, MTSerialization {
    func currentLayer() -> UInt {
        return 230
    }

    func parseMessage(_ data: Data!) -> Any! {
        guard let data = data, data.count >= 4 else {
            return nil
        }
        return BenchRawResult(data)
    }

    func exportAuthorization(_ datacenterId: Int32, data: AutoreleasingUnsafeMutablePointer<NSData?>) -> MTExportAuthorizationResponseParser! {
        var writer = TLWriter()
        writer.uint32(TL.authExportAuthorization)
        writer.int32(datacenterId)
        data.pointee = writer.data as NSData
        return { response -> MTExportedAuthorizationData? in
            guard let response = response else {
                return nil
            }
            var reader = TLReader(response)
            guard reader.uint32() == TL.authExportedAuthorization, let id = reader.int64(), let bytes = reader.bytes() else {
                return nil
            }
            return MTExportedAuthorizationData(authorizationBytes: bytes, authorizationId: id)
        }
    }

    func importAuthorization(_ authId: Int64, bytes: Data!) -> Data! {
        var writer = TLWriter()
        writer.uint32(TL.authImportAuthorization)
        writer.int64(authId)
        writer.bytes(bytes ?? Data())
        return writer.data
    }

    func requestDatacenterAddress(with data: AutoreleasingUnsafeMutablePointer<NSData?>) -> MTRequestDatacenterAddressListParser! {
        var writer = TLWriter()
        writer.uint32(TL.helpGetConfig)
        data.pointee = writer.data as NSData
        return { _ -> MTDatacenterAddressListData? in
            return nil
        }
    }

    func requestNoop(_ data: AutoreleasingUnsafeMutablePointer<NSData?>!) -> MTRequestNoopParser! {
        var writer = TLWriter()
        writer.uint32(TL.helpTest)
        data.pointee = writer.data as NSData
        return { response -> Any? in
            guard let response = response else {
                return nil
            }
            return BenchRawResult(response)
        }
    }
}

final class BenchShortMetadata: NSObject {
    private let name: String

    init(_ name: String) {
        self.name = name
    }

    override var description: String {
        return self.name
    }
}

private final class ConnectionStatusDelegate: NSObject, MTProtoDelegate {
    private let lock = NSLock()
    private var flags: [String: Bool] = [:]

    private func update(_ name: String, _ value: Bool) {
        self.lock.lock()
        let changed = self.flags[name] != value
        self.flags[name] = value
        self.lock.unlock()
        if changed && benchVerbose {
            writeStderr("[main session] \(name) = \(value)")
        }
    }

    func mtProtoNetworkAvailabilityChanged(_ mtProto: MTProto!, isNetworkAvailable: Bool) {
        self.update("networkAvailable", isNetworkAvailable)
    }

    func mtProtoConnectionStateChanged(_ mtProto: MTProto!, state: MTProtoConnectionState!) {
        self.update("connected", state?.isConnected ?? false)
        self.update("proxyHasConnectionIssues", state?.proxyHasConnectionIssues ?? false)
    }

    func mtProtoConnectionContextUpdateStateChanged(_ mtProto: MTProto!, isUpdatingConnectionContext: Bool) {
        self.update("updatingConnectionContext", isUpdatingConnectionContext)
    }

    func mtProtoServiceTasksStateChanged(_ mtProto: MTProto!, isPerformingServiceTasks: Bool) {
        self.update("performingServiceTasks", isPerformingServiceTasks)
    }
}

private final class UpdateSinkService: NSObject, MTMessageService {
    private var mtProto: MTProto?

    func mtProtoWillAdd(_ mtProto: MTProto!) {
        self.mtProto = mtProto
    }

    func mtProtoDidChangeSession(_ mtProto: MTProto!) {
    }

    func mtProtoServerDidChangeSession(_ mtProto: MTProto!, firstValidMessageId: Int64, otherValidMessageIds: [Any]!) {
    }

    func mtProto(_ mtProto: MTProto!, receivedMessage message: MTIncomingMessage!, authInfoSelector: MTDatacenterAuthInfoSelector, networkType: Int32) {
    }
}

enum SessionRole {
    case main
    case worker(isMedia: Bool)
}

final class BenchSession: NSObject, MTRequestMessageServiceDelegate {
    let index: Int
    let datacenterId: Int
    let role: SessionRole
    let context: MTContext
    let mtProto: MTProto
    let requestService: MTRequestMessageService
    private let connectionStatusDelegate: ConnectionStatusDelegate?

    init(index: Int, context: MTContext, datacenterId: Int, role: SessionRole, usageCalculationInfo: MTNetworkUsageCalculationInfo?) {
        self.index = index
        self.context = context
        self.datacenterId = datacenterId
        self.role = role

        switch role {
        case .main:
            let mtProto = MTProto(context: context, datacenterId: datacenterId, usageCalculationInfo: usageCalculationInfo, requiredAuthToken: nil, authTokenMasterDatacenterId: 0)!
            mtProto.useTempAuthKeys = context.useTempAuthKeys
            mtProto.checkForProxyConnectionIssues = true
            self.mtProto = mtProto
            self.requestService = MTRequestMessageService(context: context)!
            self.connectionStatusDelegate = ConnectionStatusDelegate()
        case let .worker(isMedia):
            let mtProto = MTProto(context: context, datacenterId: datacenterId, usageCalculationInfo: usageCalculationInfo, requiredAuthToken: nil, authTokenMasterDatacenterId: 0)!
            let prefix = "[worker \(index)] "
            mtProto.getLogPrefix = {
                return prefix
            }
            mtProto.cdn = false
            mtProto.useTempAuthKeys = context.useTempAuthKeys
            mtProto.media = isMedia
            self.mtProto = mtProto
            self.requestService = MTRequestMessageService(context: context)!
            self.requestService.forceBackgroundRequests = true
            self.connectionStatusDelegate = nil
        }

        super.init()

        switch role {
        case .main:
            self.mtProto.delegate = self.connectionStatusDelegate
            self.mtProto.add(self.requestService)
            self.requestService.didReceiveSoftAuthResetError = {
                writeStderr("[main session] soft auth reset")
            }
            self.requestService.delegate = self
            self.mtProto.add(UpdateSinkService())
        case .worker:
            self.requestService.delegate = self
            self.mtProto.add(self.requestService)
        }
    }

    func resume() {
        self.mtProto.resume()
    }

    func requestMessageServiceAuthorizationRequired(_ requestMessageService: MTRequestMessageService!) {
        switch self.role {
        case .main:
            writeStderr("[main session] authorization required")
        case .worker:
            self.context.updateAuthTokenForDatacenter(withId: self.datacenterId, authToken: nil)
            self.context.authTokenForDatacenter(withIdRequired: self.datacenterId, authToken: self.mtProto.requiredAuthToken, masterDatacenterId: self.mtProto.authTokenMasterDatacenterId)
        }
    }
}

private func usageCalculationInfo(directory: String, category: Int32) -> MTNetworkUsageCalculationInfo {
    let base = category * 4
    return MTNetworkUsageCalculationInfo(
        filePath: directory + "/network-stats",
        incomingWWANKey: base + 0,
        outgoingWWANKey: base + 1,
        incomingOtherKey: base + 2,
        outgoingOtherKey: base + 3
    )
}

final class BenchNetwork {
    let arguments: BenchArguments
    let context: MTContext
    let statsDirectory: String
    private var nextSessionIndex = 0

    init(arguments: BenchArguments) {
        self.arguments = arguments
        self.statsDirectory = NSTemporaryDirectory() + "mtprotokit-bench-\(getpid())"
        try? FileManager.default.createDirectory(atPath: self.statsDirectory, withIntermediateDirectories: true)

        let serialization = BenchSerialization()

        var apiEnvironment = MTApiEnvironment(deviceModelName: "MTProto engine benchmark")
        apiEnvironment.apiId = 9
        apiEnvironment.appVersion = "1.0"
        apiEnvironment.langPack = "macos"
        apiEnvironment.layer = NSNumber(value: Int(serialization.currentLayer()))
        apiEnvironment.disableUpdates = false
        apiEnvironment = apiEnvironment.withUpdatedLangPackCode("en")

        var secretData: Data?
        if let secret = arguments.secret {
            guard let parsed = dataFromHex(secret), MTProxySecret.parseData(parsed) != nil else {
                fail("invalid --secret \(secret)")
            }
            secretData = parsed
            apiEnvironment = apiEnvironment.withUpdatedSocksProxySettings(MTSocksProxySettings(ip: arguments.host, port: arguments.port, username: nil, password: nil, secret: parsed))
        }

        apiEnvironment = apiEnvironment.withUpdatedNetworkSettings(MTNetworkSettings(reducedBackupDiscoveryTimeout: false))

        let useTempAuthKeys = arguments.isReal ? (arguments.tempKeys ?? false) : false

        self.context = MTContext(serialization: serialization, encryptionProvider: OpenSSLEncryptionProvider(), apiEnvironment: apiEnvironment, isTestingEnvironment: false, useTempAuthKeys: useTempAuthKeys)

        let seedAddress: MTDatacenterAddress
        if secretData != nil {
            seedAddress = MTDatacenterAddress(ip: "149.154.167.51", port: 443, preferForMedia: false, restrictToTcp: false, cdn: false, preferForProxy: false, secret: nil)
        } else {
            seedAddress = MTDatacenterAddress(ip: arguments.host, port: arguments.port, preferForMedia: false, restrictToTcp: false, cdn: false, preferForProxy: false, secret: nil)
        }
        self.context.setSeedAddressSetForDatacenterWithId(arguments.dc, seedAddressSet: MTDatacenterAddressSet(addressList: [seedAddress]))

        self.context.keychain = InMemoryKeychain()

        if !arguments.isReal {
            guard let keyHex = arguments.keyHex, let key = dataFromHex(keyHex), key.count == 256 else {
                fail("--key-hex must be a 256-byte hex key")
            }
            let keyHash = MTSha1(key)
            var authKeyId: Int64 = 0
            _ = withUnsafeMutableBytes(of: &authKeyId) { buffer in
                keyHash.copyBytes(to: buffer, from: keyHash.count - 8 ..< keyHash.count)
            }
            let now = Int64(Date().timeIntervalSince1970)
            let saltInfo = MTDatacenterSaltInfo(salt: arguments.salt, firstValidMessageId: (now - 86_400) << 32, lastValidMessageId: (now + 86_400) << 32)!
            let authInfo = MTDatacenterAuthInfo(authKey: key, authKeyId: authKeyId, validUntilTimestamp: Int32.max, saltSet: [saltInfo], authKeyAttributes: [:])!
            self.context.updateAuthInfoForDatacenter(withId: arguments.dc, authInfo: authInfo, selector: .persistent)
        }

        MTContext.contextQueue().dispatch(onQueue: {}, synchronous: true)

        if benchVerbose {
            writeStderr("context ready: mode=\(arguments.mode) dc=\(arguments.dc) address=\(arguments.address) proxy=\(secretData != nil) tempKeys=\(useTempAuthKeys)")
        }
    }

    func makeSession(role: SessionRole) -> BenchSession {
        let index = self.nextSessionIndex
        self.nextSessionIndex += 1
        let category: Int32
        switch role {
        case .main:
            category = 0
        case .worker:
            category = 2
        }
        let session = BenchSession(index: index, context: self.context, datacenterId: self.arguments.dc, role: role, usageCalculationInfo: usageCalculationInfo(directory: self.statsDirectory, category: category))
        session.resume()
        return session
    }

    func cleanup() {
        try? FileManager.default.removeItem(atPath: self.statsDirectory)
    }
}
