import Foundation

let reportDescriptor = dup(STDOUT_FILENO)
dup2(STDERR_FILENO, STDOUT_FILENO)

let benchArguments = BenchArguments.parse(Array(CommandLine.arguments.dropFirst()))
installLogging()

let benchThread = Thread {
    let output = runBench(benchArguments)
    FileHandle(fileDescriptor: reportDescriptor, closeOnDealloc: false).write((output + "\n").data(using: .utf8)!)
    exit(0)
}
benchThread.name = "mtprotokit-bench.driver"
benchThread.stackSize = 8 << 20
benchThread.start()

dispatchMain()
