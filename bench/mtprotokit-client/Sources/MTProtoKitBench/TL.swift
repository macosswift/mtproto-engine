import Foundation

enum TL {
    static let call: UInt32 = 0x7e57_0001
    static let callResult: UInt32 = 0x7e57_0002
    static let sizedTag: UInt32 = 1012
    static let helpGetConfig: UInt32 = 0xc4f9_186b
    static let helpGetNearestDc: UInt32 = 0x1fb3_3026
    static let helpTest: UInt32 = 0xc0e2_02f7
    static let authExportAuthorization: UInt32 = 0xe5bf_ffcd
    static let authExportedAuthorization: UInt32 = 0xb434_e2b8
    static let authImportAuthorization: UInt32 = 0xa57a_7dad
}

struct TLWriter {
    private(set) var data = Data()

    mutating func uint32(_ value: UInt32) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { self.data.append(contentsOf: $0) }
    }

    mutating func int32(_ value: Int32) {
        self.uint32(UInt32(bitPattern: value))
    }

    mutating func int64(_ value: Int64) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { self.data.append(contentsOf: $0) }
    }

    mutating func bytes(_ value: Data) {
        let length = value.count
        var header: Int
        if length < 254 {
            self.data.append(UInt8(length))
            header = 1
        } else {
            self.data.append(254)
            self.data.append(UInt8(length & 0xff))
            self.data.append(UInt8((length >> 8) & 0xff))
            self.data.append(UInt8((length >> 16) & 0xff))
            header = 4
        }
        self.data.append(value)
        let padding = (4 - (header + length) % 4) % 4
        if padding != 0 {
            self.data.append(contentsOf: [UInt8](repeating: 0, count: padding))
        }
    }
}

struct TLReader {
    private let data: Data
    private var offset: Int

    init(_ data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    mutating func uint32() -> UInt32? {
        guard self.offset + 4 <= self.data.endIndex else {
            return nil
        }
        var value: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &value) { buffer in
            self.data.copyBytes(to: buffer, from: self.offset ..< self.offset + 4)
        }
        self.offset += 4
        return UInt32(littleEndian: value)
    }

    mutating func int64() -> Int64? {
        guard self.offset + 8 <= self.data.endIndex else {
            return nil
        }
        var value: Int64 = 0
        _ = withUnsafeMutableBytes(of: &value) { buffer in
            self.data.copyBytes(to: buffer, from: self.offset ..< self.offset + 8)
        }
        self.offset += 8
        return Int64(littleEndian: value)
    }

    mutating func bytes() -> Data? {
        guard self.offset < self.data.endIndex else {
            return nil
        }
        var length = Int(self.data[self.offset])
        var header = 1
        if length == 254 {
            guard self.offset + 4 <= self.data.endIndex else {
                return nil
            }
            length = Int(self.data[self.offset + 1]) | Int(self.data[self.offset + 2]) << 8 | Int(self.data[self.offset + 3]) << 16
            header = 4
        }
        let start = self.offset + header
        guard start + length <= self.data.endIndex else {
            return nil
        }
        let result = Data(self.data[start ..< start + length])
        self.offset = start + length + (4 - (header + length) % 4) % 4
        return result
    }
}

func callBody(tag: UInt32, payload: Data) -> Data {
    var writer = TLWriter()
    writer.uint32(TL.call)
    writer.uint32(tag)
    writer.bytes(payload)
    return writer.data
}

func smallCallBody(tag: UInt32, index: Int) -> Data {
    var index = UInt64(index).littleEndian
    return callBody(tag: tag, payload: withUnsafeBytes(of: &index) { Data($0) })
}

func sizedCallBody(size: UInt32) -> Data {
    var size = size.littleEndian
    return callBody(tag: TL.sizedTag, payload: withUnsafeBytes(of: &size) { Data($0) })
}

func realCallBody(index: Int) -> Data {
    var writer = TLWriter()
    writer.uint32(index % 2 == 0 ? TL.helpGetConfig : TL.helpGetNearestDc)
    return writer.data
}

final class BenchCallResult: NSObject {
    let tag: UInt32
    let payload: Data

    init(tag: UInt32, payload: Data) {
        self.tag = tag
        self.payload = payload
    }

    static func parse(_ data: Data) -> BenchCallResult? {
        var reader = TLReader(data)
        guard reader.uint32() == TL.callResult, let tag = reader.uint32(), let payload = reader.bytes() else {
            return nil
        }
        return BenchCallResult(tag: tag, payload: payload)
    }
}

final class BenchRawResult: NSObject {
    let data: Data

    init(_ data: Data) {
        self.data = data
    }
}
