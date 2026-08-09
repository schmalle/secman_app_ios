import Foundation

/// Every failure the kit can produce.
///
/// The messages are written to be shown to a user. Two rules:
///
///  - never echo a server error verbatim into the UI beyond the relay's own
///    short, deliberately generic text — the relay is careful about what it
///    discloses, and the app must not undo that by rendering internals;
///  - distinguish "you are not allowed" from "something broke", because the
///    remedies are completely different and a user who sees the wrong one will
///    retry forever.
public enum RelayError: Error, Sendable {
    /// The device's Secure Enclave key could not be created, read or used.
    case deviceKey(String)
    /// A Keychain call failed.
    case keychain(status: OSStatus, operation: String)
    /// The user dismissed the biometric prompt or a browser sheet.
    case userCancelled
    /// The relay could not be reached.
    case transport(Error)
    /// The relay answered, but not with what this build expects.
    case malformedResponse(String)
    /// 401 — the session is gone. The app re-authenticates silently.
    case unauthenticated
    /// 403 — the account or device is not permitted. Re-authenticating will
    /// not help; a human has to change something in secman.
    case forbidden(String)
    /// 503 — the relay is up but has no snapshot yet.
    case noSnapshotYet
    /// 429 — slow down.
    case rateLimited(retryAfter: TimeInterval?)
    /// Any other HTTP status.
    case http(status: Int, message: String?)
    /// The relay speaks a snapshot version this build does not.
    case unsupportedSchema(found: Int, supported: Int)
    /// A sign-in provider failed or returned something unusable.
    case signIn(String)
    /// The relay is not configured in this build/installation yet.
    case notConfigured
}

extension RelayError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .deviceKey(let detail):
            return "This device's security key is unavailable. \(detail)"
        case .keychain(let status, let operation):
            return "Keychain error \(status) while \(operation)."
        case .userCancelled:
            return "Cancelled."
        case .transport:
            return "The secman relay could not be reached. Check your connection."
        case .malformedResponse(let detail):
            return "The relay sent an unexpected response. \(detail)"
        case .unauthenticated:
            return "Your session expired."
        case .forbidden(let message):
            return message
        case .noSnapshotYet:
            return "The relay has not received a status update from secman yet."
        case .rateLimited:
            return "Too many attempts. Please wait a moment and try again."
        case .http(let status, let message):
            return message ?? "The relay returned an error (HTTP \(status))."
        case .unsupportedSchema(let found, let supported):
            return "This relay speaks status format \(found); this app understands \(supported). Update the app."
        case .signIn(let detail):
            return "Sign-in did not complete. \(detail)"
        case .notConfigured:
            return "No relay has been configured for this app yet."
        }
    }

    /// Whether re-running the sign-in flow could plausibly fix this.
    ///
    /// `forbidden` is deliberately false: a device whose principal was removed,
    /// or an admin bound by a weak provider, will fail identically every time,
    /// and a retry loop just burns the rate limit.
    public var isRecoverableBySigningInAgain: Bool {
        switch self {
        case .unauthenticated: return true
        case .forbidden, .unsupportedSchema, .notConfigured: return false
        default: return false
        }
    }
}
