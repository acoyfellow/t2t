import Foundation
import Network

@MainActor
final class Control {
    private var listener: NWListener?
    var handle: (String, [String: String]) -> String = { _, _ in "{}" }

    func start(port: UInt16) {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return }
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: nwPort)
        guard let listener = try? NWListener(using: parameters) else { return }
        listener.newConnectionHandler = { [weak self] connection in
            connection.start(queue: .main)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, _ in
                let raw = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                let line = raw.split(separator: "\r\n").first.map(String.init) ?? ""
                let target = line.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
                let components = URLComponents(string: target)
                let path = components?.path ?? "/"
                var query: [String: String] = [:]
                for item in components?.queryItems ?? [] { query[item.name] = item.value ?? "" }
                MainActor.assumeIsolated {
                    let body = self?.handle(path, query) ?? "{}"
                    let response = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \(body.utf8.count)\r\nconnection: close\r\n\r\n\(body)"
                    connection.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in connection.cancel() })
                }
            }
        }
        listener.start(queue: .main)
        self.listener = listener
    }
}
