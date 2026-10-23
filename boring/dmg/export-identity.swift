// Export ONE code-signing identity as PKCS#12 to stdout, never to a file.
//   printf '%s' "$passphrase" | swift export-identity.swift <common name> <SHA-1 pin> [keychain path]
// `security export -t identities` exports every identity in a keychain; this asks the
// Security framework for identities, keeps the one whose certificate has exactly this
// common name AND this SHA-1, and exports just that SecIdentity. Anything else (none,
// two, name without the pin) is refused. The passphrase comes on stdin, so it is never
// in argv. Called by export-signing-secret.sh; macOS shows its keychain prompt here.
import CryptoKit
import Foundation
import Security

func die(_ s: String) -> Never {
    FileHandle.standardError.write("export-identity: \(s)\n".data(using: .utf8)!)
    exit(1)
}

let args = CommandLine.arguments.dropFirst()
guard args.count == 2 || args.count == 3 else { die("usage: export-identity.swift <name> <sha1> [keychain]") }
let name = args[args.startIndex]
let pin = args[args.startIndex + 1].uppercased()
let pass = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
guard pass.count >= 20 else { die("passphrase on stdin is missing or too short") }

var query: [String: Any] = [
    kSecClass as String: kSecClassIdentity,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnRef as String: true,
]
if args.count == 3 {
    var kc: SecKeychain?
    guard SecKeychainOpen(args[args.startIndex + 2], &kc) == errSecSuccess, let kc else { die("cannot open keychain") }
    query[kSecMatchSearchList as String] = [kc]
}
var found: CFTypeRef?
let st = SecItemCopyMatching(query as CFDictionary, &found)
guard st == errSecSuccess || st == errSecItemNotFound else { die("keychain search failed (\(st))") }
let all = (found as? [SecIdentity]) ?? []

func sha1(_ id: SecIdentity) -> String? {
    var cert: SecCertificate?
    guard SecIdentityCopyCertificate(id, &cert) == errSecSuccess, let cert else { return nil }
    let der = SecCertificateCopyData(cert) as Data
    return Insecure.SHA1.hash(data: der).map { String(format: "%02X", $0) }.joined()
}
func commonName(_ id: SecIdentity) -> String? {
    var cert: SecCertificate?
    guard SecIdentityCopyCertificate(id, &cert) == errSecSuccess, let cert else { return nil }
    var cn: CFString?
    return SecCertificateCopyCommonName(cert, &cn) == errSecSuccess ? cn as String? : nil
}

let named = all.filter { commonName($0) == name }
guard named.count == 1 else { die("\(named.count) identities named \"\(name)\" (need exactly 1; \(all.count) identities in all)") }
let id = named[0]
guard sha1(id) == pin else { die("\"\(name)\" has SHA-1 \(sha1(id) ?? "?"), not the pinned \(pin)") }

var params = SecItemImportExportKeyParameters()
params.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
let cfPass = pass as CFString
params.passphrase = Unmanaged.passUnretained(cfPass)
var out: CFData?
let ex = SecItemExport(id, .formatPKCS12, [], &params, &out)
withExtendedLifetime(cfPass) {}
guard ex == errSecSuccess, let out else { die("export refused (\(ex)); allow it at the keychain prompt") }
FileHandle.standardOutput.write(out as Data)
