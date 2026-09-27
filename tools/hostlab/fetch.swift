import Foundation
let sem = DispatchSemaphore(value: 0)
var code = 1
URLSession.shared.dataTask(with: URL(string: CommandLine.arguments[1])!) { _, r, e in
    if let h = r as? HTTPURLResponse { print("swift URLSession status", h.statusCode); code = 0 } else { print("swift URLSession error:", e?.localizedDescription ?? "?") }
    sem.signal()
}.resume()
_ = sem.wait(timeout: .now() + 20)
exit(Int32(code))
