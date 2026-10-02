import Foundation
import MtProtoKit

enum CallKind {
    case small(tag: UInt32)
    case sized(size: UInt32)
    case real
}

struct RequestFlags {
    var needsTimeoutTimer: Bool
    var expectedResponseSize: Int32

    static let small = RequestFlags(needsTimeoutTimer: false, expectedResponseSize: 0)

    static func media(partSize: UInt32) -> RequestFlags {
        return RequestFlags(needsTimeoutTimer: true, expectedResponseSize: Int32(clamping: partSize))
    }
}

func requestErrorPolicy(_ errorContext: MTRequestErrorContext) -> Bool {
    let automaticFloodWait = true
    let failOnServerErrors = false
    if errorContext.floodWaitSeconds > 0 && !automaticFloodWait {
        return false
    }
    if errorContext.internalServerErrorCount > 0 && failOnServerErrors {
        return false
    }
    return true
}

private struct Record {
    var sent: Double
    var done: Double?
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

final class Driver {
    private let condition = NSCondition()
    private var records: [Record] = []
    private var probes: [Int] = []
    private var pending = Set<Int>()
    private var outstandingBySession: [Int: Int] = [:]
    private var completedCount = 0
    private var failedCount = 0
    private var receivedBytes: UInt64 = 0
    private var eventCounter: UInt64 = 0
    private var seenCounter: UInt64 = 0
    private var closed = false
    private var loggedFailures = 0
    private var startNanos: UInt64

    init() {
        self.startNanos = DispatchTime.now().uptimeNanoseconds
    }

    func restart() {
        self.startNanos = DispatchTime.now().uptimeNanoseconds
    }

    func elapsed() -> Double {
        return Double(DispatchTime.now().uptimeNanoseconds &- self.startNanos) / 1e9
    }

    func outstanding(_ session: BenchSession) -> Int {
        self.condition.lock()
        defer { self.condition.unlock() }
        return self.outstandingBySession[session.index] ?? 0
    }

    func issue(_ session: BenchSession, kind: CallKind, probe: Bool, flags: RequestFlags) {
        self.condition.lock()
        let index = self.records.count
        self.condition.unlock()

        let payload: Data
        let name: String
        switch kind {
        case let .small(tag):
            payload = smallCallBody(tag: tag, index: index)
            name = "bench.call"
        case let .sized(size):
            payload = sizedCallBody(size: size)
            name = "bench.getPart"
        case .real:
            payload = realCallBody(index: index)
            name = index % 2 == 0 ? "help.getConfig" : "help.getNearestDc"
        }

        let request = MTRequest()
        let metadata = BenchShortMetadata(name)
        switch kind {
        case .small, .sized:
            request.setPayload(payload, metadata: metadata, shortMetadata: metadata, responseParser: { response in
                guard let response = response else {
                    return nil
                }
                return BenchCallResult.parse(response)
            })
        case .real:
            request.setPayload(payload, metadata: metadata, shortMetadata: metadata, responseParser: { response in
                guard let response = response, response.count >= 4 else {
                    return nil
                }
                return BenchRawResult(response)
            })
        }
        request.dependsOnPasswordEntry = false
        request.needsTimeoutTimer = flags.needsTimeoutTimer
        request.expectedResponseSize = flags.expectedResponseSize
        request.shouldContinueExecutionWithErrorContext = { errorContext in
            guard let errorContext = errorContext else {
                return true
            }
            return requestErrorPolicy(errorContext)
        }
        let sessionIndex = session.index
        request.completed = { [weak self] result, _, error in
            guard let self = self else {
                return
            }
            let at = self.elapsed()
            self.finish(index: index, sessionIndex: sessionIndex, kind: kind, result: result, error: error, at: at)
        }

        self.condition.lock()
        self.records.append(Record(sent: self.elapsed(), done: nil))
        if probe {
            self.probes.append(index)
        }
        self.pending.insert(index)
        self.outstandingBySession[sessionIndex, default: 0] += 1
        self.condition.unlock()

        session.requestService.add(request)
    }

    private func finish(index: Int, sessionIndex: Int, kind: CallKind, result: Any?, error: MTRpcError?, at: Double) {
        var valid = false
        var bytes: UInt64 = 0
        if error == nil {
            switch kind {
            case let .small(tag):
                valid = (result as? BenchCallResult)?.tag == tag
            case let .sized(size):
                if let result = result as? BenchCallResult, result.tag == TL.sizedTag, result.payload.count == Int(size) {
                    valid = true
                    bytes = UInt64(size)
                }
            case .real:
                if let result = result as? BenchRawResult, result.data.count >= 4 {
                    valid = true
                }
            }
        }

        self.condition.lock()
        defer { self.condition.unlock() }
        if self.closed || self.pending.remove(index) == nil {
            return
        }
        self.outstandingBySession[sessionIndex, default: 1] -= 1
        if valid {
            self.completedCount += 1
            self.records[index].done = at
            self.receivedBytes += bytes
        } else {
            self.failedCount += 1
            if benchVerbose || self.loggedFailures < 5 {
                self.loggedFailures += 1
                let reason = error.map { "\($0.errorCode): \($0.errorDescription ?? "")" } ?? "unexpected response \(String(describing: result))"
                writeStderr("request \(index) failed: \(reason)")
            }
        }
        self.eventCounter &+= 1
        self.condition.broadcast()
    }

    func pump(timeout: Double) {
        self.condition.lock()
        if self.eventCounter == self.seenCounter && timeout > 0 {
            _ = self.condition.wait(until: Date(timeIntervalSinceNow: timeout))
        }
        self.seenCounter = self.eventCounter
        self.condition.unlock()
    }

    func report(arguments: BenchArguments, elapsed: Double) -> String {
        self.condition.lock()
        self.closed = true
        let records = self.records
        let probes = self.probes
        let completed = self.completedCount
        let failed = self.failedCount + self.pending.count
        let bytes = self.receivedBytes
        self.condition.unlock()

        let latencyIndices: [Int] = arguments.workload == "mixed" ? probes : Array(records.indices)
        let samples = latencyIndices.compactMap { index -> Double? in
            let record = records[index]
            return record.done.map { ($0 - record.sent) * 1000.0 }
        }
        let latency = Latency(samples: samples)
        let throughput = elapsed > 0 ? Double(bytes) / 1e6 / elapsed : 0.0

        writeStderr("[\(arguments.engineLabel)] \(arguments.workload): completed \(completed), failed \(failed), elapsed \(formatNumber(elapsed)) s, p50 \(formatNumber(latency.p50)) ms, bytes \(bytes)")

        var output = "{\"engine\":\"\(jsonEscape(arguments.engineLabel))\",\"workload\":\"\(jsonEscape(arguments.workload))\",\"completed\":\(completed),\"failed\":\(failed),\"elapsed\":\(formatNumber(elapsed)),"
        output += "\"latency_ms\":{\"p50\":\(formatNumber(latency.p50)),\"p95\":\(formatNumber(latency.p95)),\"p99\":\(formatNumber(latency.p99)),\"max\":\(formatNumber(latency.max))},"
        output += "\"bytes\":\(bytes),\"throughput_mbps\":\(formatNumber(throughput)),\"requests\":["
        var first = true
        for record in records {
            if !first {
                output += ","
            }
            first = false
            output += "[\(formatNumber(record.sent)),\(record.done.map(formatNumber) ?? "null")]"
        }
        output += "]}"
        return output
    }
}

func formatNumber(_ value: Double) -> String {
    if !value.isFinite {
        return "null"
    }
    return String(format: "%.6f", value)
}

func jsonEscape(_ value: String) -> String {
    var result = ""
    for scalar in value.unicodeScalars {
        switch scalar {
        case "\"":
            result += "\\\""
        case "\\":
            result += "\\\\"
        case "\n":
            result += "\\n"
        case "\t":
            result += "\\t"
        default:
            if scalar.value < 0x20 {
                result += String(format: "\\u%04x", scalar.value)
            } else {
                result.unicodeScalars.append(scalar)
            }
        }
    }
    return result
}
