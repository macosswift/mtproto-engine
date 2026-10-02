import Foundation
import SwiftSignalKit
import MtProtoKit
import Postbox
@testable import TelegramApi
@testable import TelegramCore
import MTProtoRustEngine
import OpenSSLEncryption

func writeStderr(_ text: String) {
    FileHandle.standardError.write((text + "\n").data(using: .utf8)!)
}

func fail(_ text: String) -> Never {
    writeStderr("telegramcore-bench: \(text)")
    exit(2)
}

struct Arguments {
    var configPath = ""
    var engine = "mtprotokit"
    var engineLabel: String?
    var workload = "tc-download"
    var concurrency = 8
    var requests = 1000
    var rate = 20.0
    var deadline = 120.0
    var cancelFraction = 0.5
    var trickle = 0.0
    var stallExit = 0.0
    var duration = 10.0
    var seed: UInt64 = 1
    var switchEngineAt: [Double] = []
    var switchEngineTo = "other"

    static func parse() -> Arguments {
        var result = Arguments()
        var iterator = CommandLine.arguments.dropFirst().makeIterator()
        while let argument = iterator.next() {
            guard let value = iterator.next() else {
                fail("missing value for \(argument)")
            }
            switch argument {
            case "--config": result.configPath = value
            case "--engine": result.engine = value
            case "--engine-label": result.engineLabel = value
            case "--workload": result.workload = value
            case "--concurrency": result.concurrency = Int(value) ?? result.concurrency
            case "--requests": result.requests = Int(value) ?? result.requests
            case "--rate": result.rate = Double(value) ?? result.rate
            case "--deadline": result.deadline = Double(value) ?? result.deadline
            case "--cancel-fraction": result.cancelFraction = Double(value) ?? result.cancelFraction
            case "--seed": result.seed = UInt64(value) ?? result.seed
            case "--trickle": result.trickle = Double(value) ?? result.trickle
            case "--stall-exit": result.stallExit = Double(value) ?? result.stallExit
            case "--duration": result.duration = Double(value) ?? result.duration
            case "--switch-engine-at": result.switchEngineAt = value.split(separator: ",").compactMap { Double($0) }.filter { $0 > 0.0 }
            case "--switch-engine-to": result.switchEngineTo = value
            default: fail("unknown argument \(argument)")
            }
        }
        if result.configPath.isEmpty {
            fail("--config is required")
        }
        return result
    }
}

struct AddressConfig {
    let host: String
    let port: Int
}

struct InjectConfig {
    let datacenterId: Int
    let after: Double
    let addresses: [AddressConfig]
}

struct ProxyConfig {
    let kind: String
    let host: String
    let port: Int
    let secret: Data
}

struct DatacenterConfig {
    let id: Int
    let addresses: [AddressConfig]
    let cdn: Bool
    let salt: Int64
    let keys: [MTDatacenterAuthInfoSelector: Data]
}

struct FileConfig {
    let id: Int64
    let datacenterId: Int
    let size: Int64
    let cdn: Bool
}

func parseAddresses(_ value: Any?) -> [AddressConfig] {
    return (value as? [[String: Any]] ?? []).map { item in
        AddressConfig(host: item["host"] as? String ?? "127.0.0.1", port: (item["port"] as? NSNumber)?.intValue ?? 0)
    }
}

struct BenchConfig {
    let mainDatacenterId: Int
    let datacenters: [DatacenterConfig]
    let files: [FileConfig]
    let injections: [InjectConfig]
    let proxy: ProxyConfig?

    static func load(_ path: String) -> BenchConfig {
        guard let data = FileManager.default.contents(atPath: path), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            fail("cannot read config \(path)")
        }
        let mainDatacenterId = (object["main_datacenter_id"] as? NSNumber)?.intValue ?? 2
        var datacenters: [DatacenterConfig] = []
        for item in object["datacenters"] as? [[String: Any]] ?? [] {
            var keys: [MTDatacenterAuthInfoSelector: Data] = [:]
            let keyObject = item["keys"] as? [String: String] ?? [:]
            for (name, selector) in [("persistent", MTDatacenterAuthInfoSelector.persistent), ("main", .ephemeralMain), ("media", .ephemeralMedia)] {
                if let hex = keyObject[name] {
                    keys[selector] = dataFromHex(hex)
                }
            }
            var addresses = parseAddresses(item["addresses"])
            if addresses.isEmpty {
                addresses = [AddressConfig(host: item["host"] as? String ?? "127.0.0.1", port: (item["port"] as? NSNumber)?.intValue ?? 0)]
            }
            datacenters.append(DatacenterConfig(
                id: (item["id"] as? NSNumber)?.intValue ?? 0,
                addresses: addresses,
                cdn: (item["cdn"] as? NSNumber)?.boolValue ?? false,
                salt: (item["salt"] as? NSNumber)?.int64Value ?? 0,
                keys: keys
            ))
        }
        var files: [FileConfig] = []
        for item in object["files"] as? [[String: Any]] ?? [] {
            files.append(FileConfig(
                id: (item["id"] as? NSNumber)?.int64Value ?? 0,
                datacenterId: (item["dc"] as? NSNumber)?.intValue ?? mainDatacenterId,
                size: (item["size"] as? NSNumber)?.int64Value ?? 0,
                cdn: (item["cdn"] as? NSNumber)?.boolValue ?? false
            ))
        }
        let injections = (object["inject"] as? [[String: Any]] ?? []).map { item in
            InjectConfig(datacenterId: (item["dc"] as? NSNumber)?.intValue ?? mainDatacenterId, after: (item["after"] as? NSNumber)?.doubleValue ?? 0, addresses: parseAddresses(item["addresses"]))
        }
        var proxy: ProxyConfig?
        if let item = object["proxy"] as? [String: Any] {
            proxy = ProxyConfig(kind: item["kind"] as? String ?? "mtp", host: item["host"] as? String ?? "127.0.0.1", port: (item["port"] as? NSNumber)?.intValue ?? 0, secret: dataFromHex(item["secret"] as? String ?? ""))
        }
        return BenchConfig(mainDatacenterId: mainDatacenterId, datacenters: datacenters, files: files, injections: injections, proxy: proxy)
    }
}

func dataFromHex(_ hex: String) -> Data {
    var result = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        result.append(UInt8(hex[index ..< next], radix: 16) ?? 0)
        index = next
    }
    return result
}

func fileWord(_ fileId: Int64, _ word: UInt64) -> UInt64 {
    var z = UInt64(bitPattern: fileId) ^ (word &* 0x9e37_79b9_7f4a_7c15)
    z = z &+ 0x9e37_79b9_7f4a_7c15
    z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
    z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
    return z ^ (z >> 31)
}

func verifyFileContent(fileId: Int64, offset: Int64, data: Data) -> Bool {
    return data.withUnsafeBytes { buffer -> Bool in
        let bytes = buffer.bindMemory(to: UInt8.self)
        var position = 0
        let count = bytes.count
        while position < count {
            let absolute = UInt64(offset) + UInt64(position)
            let shift = Int(absolute % 8)
            let word = fileWord(fileId, absolute / 8)
            if shift == 0 && position + 8 <= count {
                var value: UInt64 = 0
                withUnsafeMutableBytes(of: &value) { target in
                    target.copyMemory(from: UnsafeRawBufferPointer(rebasing: buffer[position ..< position + 8]))
                }
                if UInt64(littleEndian: value) != word {
                    return false
                }
                position += 8
            } else {
                if bytes[position] != UInt8(truncatingIfNeeded: word >> (8 * UInt64(shift))) {
                    return false
                }
                position += 1
            }
        }
        return true
    }
}

final class MemoryStore {
    private let lock = NSLock()
    private var storage: [String: Data] = [:]

    func get(_ key: String) -> Data? {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.storage[key]
    }

    func set(_ key: String, _ value: Data) {
        self.lock.lock()
        self.storage[key] = value
        self.lock.unlock()
    }

    func remove(_ key: String) {
        self.lock.lock()
        self.storage.removeValue(forKey: key)
        self.lock.unlock()
    }
}

func seedKeychain(config: BenchConfig, keychain: Keychain, provider: EncryptionProvider) {
    let serialization = Serialization()
    var apiEnvironment = MTApiEnvironment(deviceModelName: "TelegramCore bench seed")
    apiEnvironment.layer = NSNumber(value: Int(serialization.currentLayer()))
    let context = MTContext(serialization: serialization, encryptionProvider: provider, apiEnvironment: apiEnvironment, isTestingEnvironment: false, useTempAuthKeys: true)
    context.keychain = keychain
    let now = Int64(Date().timeIntervalSince1970)
    for datacenter in config.datacenters {
        let addresses = datacenter.addresses.map { MTDatacenterAddress(ip: $0.host, port: UInt16($0.port), preferForMedia: false, restrictToTcp: false, cdn: datacenter.cdn, preferForProxy: false, secret: nil) }
        context.updateAddressSetForDatacenter(withId: datacenter.id, addressSet: MTDatacenterAddressSet(addressList: addresses), forceUpdateSchemes: true)
        for (selector, key) in datacenter.keys {
            let hash = MTSha1(key)
            var authKeyId: Int64 = 0
            _ = withUnsafeMutableBytes(of: &authKeyId) { buffer in
                hash.copyBytes(to: buffer, from: hash.count - 8 ..< hash.count)
            }
            let salt = MTDatacenterSaltInfo(salt: datacenter.salt, firstValidMessageId: (now - 86_400) << 32, lastValidMessageId: (now + 86_400) << 32)!
            let authInfo = MTDatacenterAuthInfo(authKey: key, authKeyId: authKeyId, validUntilTimestamp: Int32.max, saltSet: [salt], authKeyAttributes: [:])!
            context.updateAuthInfoForDatacenter(withId: datacenter.id, authInfo: authInfo, selector: selector)
        }
    }
    MTContext.contextQueue().dispatch(onQueue: {}, synchronous: true)
}

func waitRunningMainLoop(_ semaphore: DispatchSemaphore, timeout: Double = .infinity) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while semaphore.wait(timeout: .now()) == .timedOut {
        if Date() >= deadline {
            return false
        }
        RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.005))
    }
    return true
}

func openTemporaryPostbox(basePath: String) -> Postbox {
    let semaphore = DispatchSemaphore(value: 0)
    var result: Postbox?
    let key = ValueBoxEncryptionParameters.Key(data: Data(count: 32))!
    let salt = ValueBoxEncryptionParameters.Salt(data: Data(count: 16))!
    let disposable = openPostbox(basePath: basePath + "/postbox", seedConfiguration: telegramPostboxSeedConfiguration, encryptionParameters: ValueBoxEncryptionParameters(forceEncryptionIfNoSet: false, key: key, salt: salt), timestampForAbsoluteTimeBasedOperations: Int32(Date().timeIntervalSince1970), isMainProcess: true, isTemporary: true, isReadOnly: false, useCopy: false, useCaches: true, removeDatabaseOnError: true).start(next: { value in
        if case let .postbox(postbox) = value {
            result = postbox
            semaphore.signal()
        }
    })
    if !waitRunningMainLoop(semaphore, timeout: 30) {
        fail("postbox did not open")
    }
    disposable.dispose()
    return result!
}

func makeNetwork(arguments: Arguments, config: BenchConfig, keychain: Keychain, basePath: String, provider: EncryptionProvider) -> Network {
    let engineKind: NetworkEngineKind = arguments.engine == "rust" ? .rust : .mtProtoKit
    let initialization = NetworkInitializationArguments(
        apiId: 9,
        apiHash: "",
        languagesCategory: "macos",
        appVersion: "1.0",
        voipMaxLayer: 92,
        voipVersions: [],
        appData: .single(nil),
        externalRequestVerificationStream: .never(),
        externalRecaptchaRequestVerification: { _, _ in .never() },
        autolockDeadine: .single(nil),
        encryptionProvider: provider,
        deviceModelName: "TelegramCore bench",
        useBetaFeatures: false,
        isICloudEnabled: false,
        networkEngineFactory: RustNetworkEngineFactory()
    )
    let semaphore = DispatchSemaphore(value: 0)
    var result: Network?
    var proxySettings: ProxySettings?
    if let proxy = config.proxy {
        let connection: ProxyServerConnection = proxy.kind == "socks5" ? .socks5(username: nil, password: nil) : .mtp(secret: proxy.secret)
        let server = ProxyServerSettings(host: proxy.host, port: Int32(proxy.port), connection: connection)
        proxySettings = ProxySettings(enabled: true, servers: [server], activeServer: server, useForCalls: false)
    }
    let disposable = initializedNetwork(accountId: AccountRecordId(rawValue: 1), arguments: initialization, supplementary: true, datacenterId: config.mainDatacenterId, keychain: keychain, basePath: basePath, testingEnvironment: false, languageCode: "en", proxySettings: proxySettings, networkSettings: nil, networkEngineSettings: NetworkEngineSettings(engine: engineKind), phoneNumber: nil, useRequestTimeoutTimers: true, appConfiguration: AppConfiguration.defaultValue).start(next: { network in
        result = network
        semaphore.signal()
    })
    if !waitRunningMainLoop(semaphore, timeout: 30) {
        fail("network did not initialize")
    }
    disposable.dispose()
    guard let network = result else {
        fail("network did not initialize")
    }
    if network.engineKind != engineKind {
        fail("engine \(engineKind) was declined, got \(network.engineKind)")
    }
    return network
}

struct Latency {
    var p50 = 0.0
    var p95 = 0.0
    var p99 = 0.0
    var max = 0.0

    init(samples: [Double]) {
        if samples.isEmpty {
            return
        }
        let sorted = samples.sorted()
        func at(_ quantile: Double) -> Double {
            return sorted[Int((Double(sorted.count - 1) * quantile).rounded())]
        }
        self.p50 = at(0.50)
        self.p95 = at(0.95)
        self.p99 = at(0.99)
        self.max = sorted[sorted.count - 1]
    }
}

func formatNumber(_ value: Double) -> String {
    return value.isFinite ? String(format: "%.6f", value) : "null"
}

let callConstructor: UInt32 = 0x7e57_0001
let callResultConstructor: UInt32 = 0x7e57_0002

struct CallResult {
    let tag: UInt32
    let index: UInt64
}

func makeCall(tag: UInt32, index: UInt64) -> (FunctionDescription, Buffer, DeserializeFunctionResponse<CallResult>) {
    let buffer = Buffer()
    buffer.appendInt32(Int32(bitPattern: callConstructor))
    buffer.appendInt32(Int32(bitPattern: tag))
    var payload = Data(count: 8)
    payload.withUnsafeMutableBytes { $0.storeBytes(of: index.littleEndian, as: UInt64.self) }
    serializeBytes(Buffer(data: payload), buffer: buffer, boxed: false)
    return (FunctionDescription(name: "bench.call", parameters: []), buffer, DeserializeFunctionResponse { response in
        let reader = BufferReader(response)
        guard let constructor = reader.readInt32(), UInt32(bitPattern: constructor) == callResultConstructor, let tag = reader.readInt32(), let bytes = parseBytes(reader) else {
            return nil
        }
        let data = bytes.makeData()
        guard data.count == 8 else {
            return nil
        }
        return CallResult(tag: UInt32(bitPattern: tag), index: data.withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(as: UInt64.self)) })
    })
}

final class Recorder {
    private let lock = NSLock()
    private let start = DispatchTime.now().uptimeNanoseconds
    private var sent: [Double] = []
    private var done: [Double?] = []
    private var probes: [Int] = []
    private(set) var completed = 0
    private(set) var failed = 0
    private(set) var bytes: UInt64 = 0
    var verifyFailures = 0
    var cancellations = 0
    var doubleCompletions = 0
    var compact = false
    private(set) var lastProgressAt = 0.0
    var stalled = false
    var engineSwitched = false

    func elapsed() -> Double {
        return Double(DispatchTime.now().uptimeNanoseconds &- self.start) / 1e9
    }

    func begin(probe: Bool = false) -> Int {
        self.lock.lock()
        defer { self.lock.unlock() }
        let index = self.sent.count
        if self.sent.count == self.completed + self.failed {
            self.lastProgressAt = self.elapsed()
        }
        self.sent.append(self.elapsed())
        self.done.append(nil)
        if probe {
            self.probes.append(index)
        }
        return index
    }

    func finish(_ index: Int, success: Bool, bytes: UInt64 = 0) {
        let at = self.elapsed()
        self.lock.lock()
        defer { self.lock.unlock() }
        if success {
            if self.done[index] == nil {
                self.done[index] = at
                self.completed += 1
                self.bytes += bytes
                self.lastProgressAt = at
            } else {
                self.doubleCompletions += 1
            }
        } else {
            self.failed += 1
        }
    }

    func addVerifyFailure() {
        self.lock.lock()
        self.verifyFailures += 1
        self.lock.unlock()
    }

    func addCancellation() {
        self.lock.lock()
        self.cancellations += 1
        self.lock.unlock()
    }

    var pendingCount: Int {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.sent.count - self.completed - self.failed
    }

    func report(engine: String, workload: String, latencyFromProbes: Bool) -> String {
        self.lock.lock()
        defer { self.lock.unlock() }
        let elapsed = self.elapsed()
        let indices = latencyFromProbes ? self.probes : Array(self.sent.indices)
        let samples = indices.compactMap { index in self.done[index].map { ($0 - self.sent[index]) * 1000.0 } }
        let latency = Latency(samples: samples)
        let failed = self.failed + (self.sent.count - self.completed - self.failed)
        let throughput = elapsed > 0 ? Double(self.bytes) / 1e6 / elapsed : 0
        var output = "{\"engine\":\"\(engine)\",\"workload\":\"\(workload)\",\"completed\":\(self.completed),\"failed\":\(failed),\"elapsed\":\(formatNumber(elapsed)),"
        output += "\"latency_ms\":{\"p50\":\(formatNumber(latency.p50)),\"p95\":\(formatNumber(latency.p95)),\"p99\":\(formatNumber(latency.p99)),\"max\":\(formatNumber(latency.max))},"
        output += "\"bytes\":\(self.bytes),\"throughput_mbps\":\(formatNumber(throughput)),\"verify_failures\":\(self.verifyFailures),\"cancellations\":\(self.cancellations),\"double_completions\":\(self.doubleCompletions),\"stalled\":\(self.stalled ? 1 : 0),\"engine_switched\":\(self.engineSwitched ? 1 : 0),\"issued\":\(self.sent.count),\"requests\":["
        if !self.compact {
            output += zip(self.sent, self.done).map { "[\(formatNumber($0)),\($1.map(formatNumber) ?? "null")]" }.joined(separator: ",")
        }
        output += "]}"
        writeStderr("[\(engine)] \(workload): completed \(self.completed), failed \(failed), verify failures \(self.verifyFailures), elapsed \(formatNumber(elapsed)) s, p50 \(formatNumber(latency.p50)) ms, p99 \(formatNumber(latency.p99)) ms, \(self.bytes) bytes")
        return output
    }
}

final class FileDownload {
    let file: FileConfig
    let recorder: Recorder
    let index: Int
    private let queue: Queue
    private let disposable = MetaDisposable()
    private var covered = IndexSet()
    private var finished = false
    private let completion: (FileDownload, Bool) -> Void

    init(file: FileConfig, recorder: Recorder, index: Int, queue: Queue, completion: @escaping (FileDownload, Bool) -> Void) {
        self.file = file
        self.recorder = recorder
        self.index = index
        self.queue = queue
        self.completion = completion
    }

    func start(postbox: Postbox, network: Network) {
        let file = self.file
        let resource = CloudDocumentMediaResource(datacenterId: file.datacenterId, fileId: file.id, accessHash: 1, size: file.size, fileReference: Data([1, 2, 3, 4]), fileName: nil)
        let peerId = PeerId(namespace: Namespaces.Peer.CloudUser, id: PeerId.Id._internalFromInt64Value(1))
        let signal = multipartFetchV2(
            accountPeerId: peerId,
            postbox: postbox,
            network: network,
            mediaReferenceRevalidationContext: nil,
            resource: resource,
            datacenterId: file.datacenterId,
            size: file.size,
            intervals: .single([(0 ..< file.size, .default)]),
            parameters: nil,
            encryptionKey: nil,
            decryptedSize: nil,
            continueInBackground: false,
            useMainConnection: false
        )
        self.disposable.set((signal |> deliverOn(self.queue)).start(next: { [weak self] result in
            self?.handle(result)
        }, error: { [weak self] _ in
            self?.finish(success: false)
        }))
    }

    func cancel() {
        self.disposable.dispose()
    }

    private func handle(_ result: MediaResourceDataFetchResult) {
        if self.finished {
            return
        }
        switch result {
        case let .dataPart(resourceOffset, data, range, _):
            let slice = data.subdata(in: Int(range.lowerBound) ..< Int(range.upperBound))
            if !verifyFileContent(fileId: self.file.id, offset: resourceOffset, data: slice) {
                self.recorder.addVerifyFailure()
                self.finish(success: false)
                return
            }
            if !slice.isEmpty {
                self.covered.insert(integersIn: Int(resourceOffset) ..< Int(resourceOffset) + slice.count)
            }
            if self.covered.contains(integersIn: 0 ..< Int(self.file.size)) {
                self.finish(success: true)
            }
        case .reset:
            self.covered.removeAll()
        case let .resourceSizeUpdated(size):
            if size != self.file.size {
                self.recorder.addVerifyFailure()
            }
        default:
            break
        }
    }

    private func finish(success: Bool) {
        if self.finished {
            return
        }
        self.finished = true
        self.disposable.dispose()
        self.recorder.finish(self.index, success: success, bytes: success ? UInt64(self.file.size) : 0)
        self.completion(self, success)
    }
}

final class Bench {
    let arguments: Arguments
    let config: BenchConfig
    let network: Network
    let postbox: Postbox
    let recorder = Recorder()
    let queue = Queue(name: "TelegramCoreBench")
    private var active: [Int: FileDownload] = [:]
    private var nextFile = 0
    private var finishedFiles = 0
    private var rng: UInt64

    init(arguments: Arguments, config: BenchConfig, network: Network, postbox: Postbox) {
        self.arguments = arguments
        self.config = config
        self.network = network
        self.postbox = postbox
        self.rng = arguments.seed &* 0x9e37_79b9_7f4a_7c15 | 1
    }

    private func random() -> Double {
        self.rng ^= self.rng << 13
        self.rng ^= self.rng >> 7
        self.rng ^= self.rng << 17
        return Double(self.rng % 1_000_000) / 1_000_000.0
    }

    private func startNextFiles(scroll: Bool) {
        while self.active.count < self.arguments.concurrency && self.nextFile < self.config.files.count {
            let file = self.config.files[self.nextFile]
            self.nextFile += 1
            self.startFile(file, scroll: scroll)
        }
    }

    private func startFile(_ file: FileConfig, scroll: Bool) {
        let index = self.recorder.begin()
        if scroll && self.random() < self.arguments.cancelFraction {
            let doomed = FileDownload(file: file, recorder: self.recorder, index: index, queue: self.queue, completion: { _, _ in })
            doomed.start(postbox: self.postbox, network: self.network)
            let delay = 0.05 + self.random() * 0.35
            self.queue.after(delay, { [weak self] in
                doomed.cancel()
                self?.recorder.addCancellation()
                self?.launch(file, index: index, scroll: scroll)
            })
            self.active[index] = doomed
            return
        }
        self.launch(file, index: index, scroll: scroll)
    }

    private func launch(_ file: FileConfig, index: Int, scroll: Bool) {
        let download = FileDownload(file: file, recorder: self.recorder, index: index, queue: self.queue, completion: { [weak self] download, _ in
            guard let self = self else {
                return
            }
            self.active.removeValue(forKey: download.index)
            self.finishedFiles += 1
            self.startNextFiles(scroll: scroll)
        })
        self.active[index] = download
        download.start(postbox: self.postbox, network: self.network)
    }

    private func probe() {
        let index = self.recorder.begin(probe: true)
        let recorder = self.recorder
        let _ = (self.network.request(Api.functions.help.getNearestDc())
        |> deliverOn(self.queue)).start(next: { _ in
            recorder.finish(index, success: true)
        }, error: { _ in
            recorder.finish(index, success: false)
        })
    }

    private var downloadsDone: Bool {
        return self.finishedFiles >= self.config.files.count
    }

    func run() -> String {
        let deadline = Date().addingTimeInterval(self.arguments.deadline)
        let workload = self.arguments.workload
        let done = DispatchSemaphore(value: 0)
        var latencyFromProbes = false
        self.queue.async {
            self.scheduleInjections()
            self.scheduleEngineSwitch()
            switch workload {
            case "tc-download", "tc-scroll":
                self.startNextFiles(scroll: workload == "tc-scroll")
                self.poll(deadline: deadline, done: done) { $0.downloadsDone }
            case "tc-mixed":
                latencyFromProbes = true
                self.startNextFiles(scroll: false)
                self.scheduleProbes(interval: 1.0 / max(self.arguments.rate, 0.1), deadline: deadline)
                self.poll(deadline: deadline, done: done) { $0.downloadsDone && $0.recorder.pendingCount == 0 }
            case "tc-small":
                self.smallBurst(remaining: self.arguments.requests, deadline: deadline, done: done)
            case "tc-steady":
                self.steady(interval: 1.0 / max(self.arguments.rate, 0.1), until: Date().addingTimeInterval(self.arguments.duration), deadline: deadline, done: done)
            case "tc-torture":
                self.recorder.compact = self.arguments.requests > 200_000
                if self.arguments.trickle > 0 {
                    self.trickle(interval: self.arguments.trickle, deadline: deadline)
                }
                self.torture(total: self.arguments.requests, deadline: deadline, done: done)
            default:
                fail("unknown workload \(workload)")
            }
        }
        waitRunningMainLoop(done)
        let label = self.arguments.engineLabel ?? self.arguments.engine
        return self.recorder.report(engine: label, workload: workload, latencyFromProbes: latencyFromProbes)
    }

    private func poll(deadline: Date, done: DispatchSemaphore, condition: @escaping (Bench) -> Bool) {
        if condition(self) || Date() >= deadline {
            done.signal()
            return
        }
        if self.arguments.stallExit > 0 && self.recorder.pendingCount > 0 && self.recorder.elapsed() - self.recorder.lastProgressAt > self.arguments.stallExit {
            self.recorder.stalled = true
            done.signal()
            return
        }
        self.queue.after(0.01, { [weak self] in
            self?.poll(deadline: deadline, done: done, condition: condition)
        })
    }

    private func scheduleProbes(interval: Double, deadline: Date) {
        if self.downloadsDone || Date() >= deadline {
            return
        }
        self.probe()
        self.queue.after(interval, { [weak self] in
            self?.scheduleProbes(interval: interval, deadline: deadline)
        })
    }

    private func steady(interval: Double, until: Date, deadline: Date, done: DispatchSemaphore) {
        var index: UInt64 = 0
        var tick: (() -> Void)!
        tick = { [weak self] in
            guard let self = self else {
                return
            }
            if Date() >= until {
                self.poll(deadline: deadline, done: done) { $0.recorder.pendingCount == 0 }
                return
            }
            let record = self.recorder.begin()
            let recorder = self.recorder
            let tag = UInt32(1 + index % 900)
            let call = index
            index += 1
            let _ = (self.network.request(makeCall(tag: tag, index: call))
            |> deliverOn(self.queue)).start(next: { result in
                if result.tag != tag || result.index != call {
                    recorder.addVerifyFailure()
                }
                recorder.finish(record, success: true)
            }, error: { _ in
                recorder.finish(record, success: false)
            })
            self.queue.after(interval, tick)
        }
        tick()
    }

    func scheduleEngineSwitch() {
        let times = self.arguments.switchEngineAt.sorted()
        if times.isEmpty {
            return
        }
        let network = self.network
        let recorder = self.recorder
        let fixedTarget: NetworkEngineKind?
        switch self.arguments.switchEngineTo {
        case "rust":
            fixedTarget = .rust
        case "mtprotokit":
            fixedTarget = .mtProtoKit
        default:
            fixedTarget = nil
        }
        var accepted = 0
        for time in times {
            self.queue.after(time, {
                let from = network.engineKind
                let target = fixedTarget ?? (from == .rust ? .mtProtoKit : .rust)
                if network.switchEngine(to: target, reason: "bench") && network.engineKind == target {
                    accepted += 1
                }
                recorder.engineSwitched = accepted == times.count
                writeStderr("engine switch \(from.rawValue) -> \(target.rawValue), now \(network.engineKind.rawValue), \(accepted)/\(times.count) accepted")
            })
        }
    }

    func scheduleInjections() {
        for injection in self.config.injections {
            let network = self.network
            self.queue.after(injection.after, {
                let addresses = injection.addresses.map { MTDatacenterAddress(ip: $0.host, port: UInt16($0.port), preferForMedia: false, restrictToTcp: false, cdn: false, preferForProxy: false, secret: nil) }
                network.context.updateAddressSetForDatacenter(withId: injection.datacenterId, addressSet: MTDatacenterAddressSet(addressList: addresses), forceUpdateSchemes: true)
                writeStderr("injected \(addresses.count) addresses for dc\(injection.datacenterId)")
            })
        }
    }

    private func trickle(interval: Double, deadline: Date) {
        if Date() >= deadline {
            return
        }
        let _ = self.network.request(makeCall(tag: 999, index: UInt64.max)).start()
        self.queue.after(interval, { [weak self] in
            self?.trickle(interval: interval, deadline: deadline)
        })
    }

    private func torture(total: Int, deadline: Date, done: DispatchSemaphore) {
        var issued = 0
        var inFlight = 0
        let recorder = self.recorder
        let network = self.network
        let queue = self.queue
        let concurrency = self.arguments.concurrency
        var issue: (() -> Void)!
        issue = {
            while inFlight < concurrency && issued < total {
                let index = recorder.begin()
                issued += 1
                inFlight += 1
                let tag = UInt32(1 + index % 900)
                let _ = (network.request(makeCall(tag: tag, index: UInt64(index)))
                |> deliverOn(queue)).start(next: { result in
                    if result.tag != tag || result.index != UInt64(index) {
                        recorder.addVerifyFailure()
                    }
                    recorder.finish(index, success: true)
                }, error: { _ in
                    recorder.finish(index, success: false)
                    inFlight -= 1
                    issue()
                }, completed: {
                    inFlight -= 1
                    issue()
                })
            }
            if issued >= total && inFlight == 0 {
                done.signal()
            }
        }
        issue()
        self.poll(deadline: deadline, done: done) { _ in false }
    }

    private func smallBurst(remaining: Int, deadline: Date, done: DispatchSemaphore) {
        var issued = 0
        let total = remaining
        let recorder = self.recorder
        let network = self.network
        let queue = self.queue
        let concurrency = self.arguments.concurrency
        var inFlight = 0
        var issue: (() -> Void)!
        issue = {
            while inFlight < concurrency && issued < total {
                issued += 1
                inFlight += 1
                let index = recorder.begin()
                let _ = (network.request(Api.functions.help.getNearestDc())
                |> deliverOn(queue)).start(next: { _ in
                    recorder.finish(index, success: true)
                    inFlight -= 1
                    issue()
                }, error: { _ in
                    recorder.finish(index, success: false)
                    inFlight -= 1
                    issue()
                })
            }
            if issued >= total && inFlight == 0 {
                done.signal()
            }
        }
        issue()
        self.poll(deadline: deadline, done: done) { _ in false }
    }
}

let arguments = Arguments.parse()
let config = BenchConfig.load(arguments.configPath)
let basePath = NSTemporaryDirectory() + "telegramcore-bench-\(getpid())"
try? FileManager.default.createDirectory(atPath: basePath, withIntermediateDirectories: true)

let logger = Logger(rootPath: basePath, basePath: basePath)
logger.logToFile = false
logger.logToConsole = ProcessInfo.processInfo.environment["TELEGRAMCORE_BENCH_LOG"] != nil
Logger.setSharedLogger(logger)
if ProcessInfo.processInfo.environment["TELEGRAMCORE_BENCH_LOG"] == nil {
    MTLogSetEnabled(false)
}

let provider = OpenSSLEncryptionProvider()
let store = MemoryStore()
let keychain = Keychain(get: { store.get($0) }, set: { store.set($0, $1) }, remove: { store.remove($0) })
seedKeychain(config: config, keychain: keychain, provider: provider)
let postbox = openTemporaryPostbox(basePath: basePath)
let network = makeNetwork(arguments: arguments, config: config, keychain: keychain, basePath: basePath, provider: provider)
network.shouldKeepConnection.set(.single(true))

let bench = Bench(arguments: arguments, config: config, network: network, postbox: postbox)
let output = bench.run()
print(output)
fflush(stdout)
try? FileManager.default.removeItem(atPath: basePath)
exit(0)
