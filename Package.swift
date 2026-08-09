// swift-tools-version: 6.0
//
// SecmanRelayKit is the whole security surface of the app: the Secure Enclave
// key, the relay protocol, and the three sign-in flows. It is a library rather
// than app code so it can be unit-tested without a simulator and reviewed
// without reading SwiftUI.
//
// No third-party dependencies. Everything below is Apple's own frameworks —
// CryptoKit, Security, AuthenticationServices — which keeps the supply chain of
// a security product to Apple plus this repository. In particular there is no
// GoogleSignIn SDK: the Google flow is plain OAuth 2.0 + PKCE over
// ASWebAuthenticationSession, which is ~120 lines and no vendor runtime.

import PackageDescription

let package = Package(
    name: "SecmanRelayKit",
    platforms: [
        // iOS 26 is the floor the product targets; iPadOS ships the same
        // version numbers, so one platform line covers iPhone and iPad.
        .iOS(.v26),
        .macOS(.v15)
    ],
    products: [
        .library(name: "SecmanRelayKit", targets: ["SecmanRelayKit"])
    ],
    targets: [
        .target(
            name: "SecmanRelayKit",
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
        .testTarget(
            name: "SecmanRelayKitTests",
            dependencies: ["SecmanRelayKit"],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        )
    ]
)
