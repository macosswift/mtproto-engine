import Foundation

private var keptAlive: [AnyObject] = []

func runBench(_ arguments: BenchArguments) -> String {
    let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(max(0.0, arguments.deadline) * 1e9)
    func remaining() -> Double {
        let now = DispatchTime.now().uptimeNanoseconds
        return now >= deadline ? 0.0 : Double(deadline - now) / 1e9
    }
    func beforeDeadline() -> Bool {
        return DispatchTime.now().uptimeNanoseconds < deadline
    }

    let network = BenchNetwork(arguments: arguments)
    defer {
        network.cleanup()
    }
    let driver = Driver()
    let main = network.makeSession(role: .main)
    keptAlive.append(main)
    driver.restart()

    func tag(_ index: Int) -> UInt32 {
        return 1 + UInt32(index % 900)
    }
    func pump(_ timeout: Double) {
        driver.pump(timeout: min(max(0.0, timeout), remaining()))
    }

    switch arguments.workload {
    case "latency":
        for index in 0 ..< arguments.requests {
            driver.issue(main, kind: .small(tag: tag(index)), probe: false, flags: .small)
            while driver.outstanding(main) > 0 && beforeDeadline() {
                pump(0.1)
            }
            if !beforeDeadline() {
                break
            }
        }
    case "small", "real-config":
        let real = arguments.workload == "real-config"
        var issued = 0
        while (issued < arguments.requests || driver.outstanding(main) > 0) && beforeDeadline() {
            while issued < arguments.requests && driver.outstanding(main) < arguments.concurrency {
                driver.issue(main, kind: real ? .real : .small(tag: tag(issued)), probe: false, flags: .small)
                issued += 1
            }
            pump(0.1)
        }
    case "media", "mixed":
        let workers = (0 ..< arguments.sessions).map { _ in network.makeSession(role: .worker(isMedia: true)) }
        keptAlive.append(contentsOf: workers as [AnyObject])
        let partSize = max(arguments.partSize, 1)
        let parts = Int((arguments.totalBytes + UInt64(partSize) - 1) / UInt64(partSize))
        let mediaFlags = RequestFlags.media(partSize: partSize)
        let mixed = arguments.workload == "mixed"
        let probeInterval = arguments.rate > 0 ? 1.0 / arguments.rate : Double.infinity
        var nextProbe = 0.0
        var probeCount = 0
        var issued = 0
        while beforeDeadline() {
            for worker in workers {
                while issued < parts && driver.outstanding(worker) < arguments.sessionConcurrency {
                    driver.issue(worker, kind: .sized(size: partSize), probe: false, flags: mediaFlags)
                    issued += 1
                }
            }
            let mediaDone = issued >= parts && workers.allSatisfy { driver.outstanding($0) == 0 }
            if mixed && !mediaDone && driver.elapsed() >= nextProbe {
                driver.issue(main, kind: .small(tag: tag(probeCount)), probe: true, flags: .small)
                probeCount += 1
                nextProbe += probeInterval
            }
            if mediaDone && driver.outstanding(main) == 0 {
                break
            }
            if mixed && !mediaDone {
                pump(min(0.01, nextProbe - driver.elapsed()))
            } else {
                pump(0.01)
            }
        }
    case "steady":
        let interval = 1.0 / max(arguments.rate, 0.1)
        var next = 0.0
        var index = 0
        while beforeDeadline() {
            let now = driver.elapsed()
            if now < arguments.duration && now >= next {
                driver.issue(main, kind: .small(tag: tag(index)), probe: false, flags: .small)
                index += 1
                next += interval
            }
            if now >= arguments.duration && driver.outstanding(main) == 0 {
                break
            }
            if now < arguments.duration {
                pump(min(0.005, next - driver.elapsed()))
            } else {
                pump(0.005)
            }
        }
    default:
        fail("unknown workload \(arguments.workload)")
    }

    let elapsed = driver.elapsed()
    return driver.report(arguments: arguments, elapsed: elapsed)
}
