import CryptoKit
import Foundation

guard CommandLine.arguments.count == 3 else {
    fputs("Uso: sign-providers.swift providers.json providers.json.sig\n", stderr)
    exit(2)
}

guard let encodedKey = ProcessInfo.processInfo.environment[
    "PROVIDERS_SIGNING_PRIVATE_KEY"
]?.trimmingCharacters(in: .whitespacesAndNewlines),
      let keyData = Data(base64Encoded: encodedKey) else {
    fputs("Falta el secreto PROVIDERS_SIGNING_PRIVATE_KEY.\n", stderr)
    exit(3)
}

let privateKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: keyData
)
let manifestURL = URL(fileURLWithPath: CommandLine.arguments[1])
let signatureURL = URL(fileURLWithPath: CommandLine.arguments[2])
let manifest = try Data(contentsOf: manifestURL)
let signature = try privateKey.signature(for: manifest)
try signature.base64EncodedData().write(
    to: signatureURL,
    options: .atomic
)
