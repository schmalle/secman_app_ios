import Foundation

/// The two byte strings this device's Secure Enclave key ever signs.
///
/// Both mirror `src/relay/internal/auth/device.go` in the secman repository and
/// are reproduced here rather than taken from the response, for one reason:
/// **the app must never sign bytes the server chose.**
///
/// The relay does return `signingInput` and `bindingInput` — a convenience so a
/// client cannot get the format subtly wrong — but signing them verbatim would
/// hand any party who can answer as the relay an oracle: present a device with
/// arbitrary bytes, get them signed by a key the user believes only ever
/// authenticates them. TLS makes that a narrow window, and the two context
/// prefixes below make the signature useless outside its purpose, but neither
/// is a reason to sign a blank cheque. So the app derives the input itself and
/// treats the server's copy as something to *check*, via `agrees(with:)`.
///
/// The prefixes are the domain separation: a signature produced for a binding
/// must never be replayable as a session authentication, and vice versa.
public enum RelayProtocol {

    /// `secman-relay-device-auth-v1` — proves possession of the device key when
    /// exchanging a challenge for an access token.
    static let authContext = "secman-relay-device-auth-v1"

    /// `secman-relay-device-bind-v1` — proves possession of the key being
    /// registered, so a captured identity token cannot enrol somebody else's
    /// public key.
    static let bindContext = "secman-relay-device-bind-v1"

    /// The signing input for a per-session challenge.
    ///
    /// Mirrors `auth.DeviceSigningInput(deviceID, nonce)`.
    public static func signingInput(deviceId: String, nonce: String) -> String {
        "\(authContext)|\(deviceId)|\(nonce)"
    }

    /// The signing input for a device binding.
    ///
    /// Mirrors `auth.DeviceBindingInput(nonce, keyFingerprint)`, where the
    /// fingerprint is lowercase hex SHA-256 of the SPKI DER — `idp.Fingerprint`.
    ///
    /// `nonce` is the login nonce for the Apple/Google flows and the *ticket*
    /// for GitHub: the GitHub state travels through a browser and must not
    /// double as the challenge, so the relay signs over what came back instead.
    public static func bindingInput(nonce: String, keyFingerprint: String) -> String {
        "\(bindContext)|\(nonce)|\(keyFingerprint)"
    }
}

extension RelayProtocol {
    /// Whether a value the relay proposed matches what we derived.
    ///
    /// Compared in full rather than by prefix: a relay that agrees about the
    /// context string but disagrees about the nonce is exactly the case worth
    /// refusing.
    static func agrees(derived: String, proposed: String?) -> Bool {
        guard let proposed, !proposed.isEmpty else {
            // Nothing to disagree with. The relay is not obliged to echo the
            // input back, and older builds of it may not.
            return true
        }
        return derived == proposed
    }
}
