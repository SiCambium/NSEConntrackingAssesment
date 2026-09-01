// Package version holds ConnTrack's release version — one constant, kept
// in sync with macos/Info.plist's CFBundleShortVersionString by hand,
// since the two are read by different toolchains (Go vs. the macOS
// bundler) and there isn't a single natural source of truth to derive
// both from without adding a build-step dependency neither currently has.
package version

const Version = "0.3.0"
