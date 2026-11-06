import CoreGraphics
import Foundation

let wanted = CommandLine.arguments.dropFirst().first ?? ""
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
for window in list {
    let owner = window[kCGWindowOwnerName as String] as? String ?? ""
    let name = window[kCGWindowName as String] as? String ?? ""
    if owner.lowercased() == "t2t", !name.isEmpty, name == wanted || name.hasPrefix(wanted), let number = window[kCGWindowNumber as String] as? Int {
        print(number)
    }
}
