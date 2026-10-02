import Foundation

struct BenchArguments {
    var engineLabel = "mtprotokit"
    var mode = "fake"
    var address = ""
    var dc = 2
    var keyHex: String?
    var salt: Int64 = 0
    var secret: String?
    var workload = "small"
    var requests = 1000
    var concurrency = 32
    var partSize: UInt32 = 512 * 1024
    var totalBytes: UInt64 = 32 * 1024 * 1024
    var sessions = 4
    var sessionConcurrency = 3
    var rate = 10.0
    var duration = 10.0
    var deadline = 120.0
    var tempKeys: Bool?

    var isReal: Bool {
        return self.mode == "real"
    }

    var host: String {
        guard let separator = self.address.lastIndex(of: ":") else {
            return self.address
        }
        var host = String(self.address[..<separator])
        if host.hasPrefix("[") && host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        return host
    }

    var port: UInt16 {
        guard let separator = self.address.lastIndex(of: ":") else {
            return 443
        }
        return UInt16(self.address[self.address.index(after: separator)...]) ?? 443
    }

    static func parse(_ arguments: [String]) -> BenchArguments {
        var result = BenchArguments()
        var iterator = arguments.makeIterator()
        while let flag = iterator.next() {
            func value() -> String {
                guard let value = iterator.next() else {
                    fail("\(flag) needs a value")
                }
                return value
            }
            func number<T: LosslessStringConvertible>(_ type: T.Type) -> T {
                let text = value()
                guard let parsed = T(text) else {
                    fail("\(flag): invalid value \(text)")
                }
                return parsed
            }
            switch flag {
            case "--engine-label":
                result.engineLabel = value()
            case "--mode":
                result.mode = value()
            case "--address":
                result.address = value()
            case "--dc":
                result.dc = number(Int.self)
            case "--key-hex":
                result.keyHex = value()
            case "--salt":
                result.salt = number(Int64.self)
            case "--secret":
                result.secret = value()
            case "--workload":
                result.workload = value()
            case "--requests":
                result.requests = number(Int.self)
            case "--concurrency":
                result.concurrency = number(Int.self)
            case "--part-size":
                result.partSize = number(UInt32.self)
            case "--total-bytes":
                result.totalBytes = number(UInt64.self)
            case "--sessions":
                result.sessions = number(Int.self)
            case "--session-concurrency":
                result.sessionConcurrency = number(Int.self)
            case "--rate":
                result.rate = number(Double.self)
            case "--duration":
                result.duration = number(Double.self)
            case "--deadline":
                result.deadline = number(Double.self)
            case "--temp-keys":
                result.tempKeys = number(Int.self) != 0
            default:
                fail("unknown argument \(flag)")
            }
        }
        if result.address.isEmpty {
            fail("--address is required")
        }
        if result.mode != "fake" && result.mode != "real" {
            fail("--mode must be fake or real")
        }
        if result.mode == "fake" && result.keyHex == nil {
            fail("--key-hex is required in fake mode")
        }
        return result
    }
}

func fail(_ message: String) -> Never {
    writeStderr("mtprotokit-bench: \(message)")
    exit(2)
}

func writeStderr(_ message: String) {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
}

func dataFromHex(_ text: String) -> Data? {
    let characters = Array(text.utf8)
    if characters.count % 2 != 0 {
        return nil
    }
    func nibble(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return character - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"):
            return character - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"):
            return character - UInt8(ascii: "A") + 10
        default:
            return nil
        }
    }
    var result = Data(capacity: characters.count / 2)
    var index = 0
    while index < characters.count {
        guard let high = nibble(characters[index]), let low = nibble(characters[index + 1]) else {
            return nil
        }
        result.append(high << 4 | low)
        index += 2
    }
    return result
}
