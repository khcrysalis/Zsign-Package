// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Zsign",
	platforms: [
		.iOS(.v12),
		.macOS(.v10_15),
		.tvOS(.v12),
		.watchOS(.v8),
		.custom("xros", versionString: "1.3")
	],
	products: [
		.library(
			name: "zsign",
			targets: ["Zsign"]
		),
	],
	dependencies: [
		.package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", from: "3.3.1000")
	],
	targets: [
		.target(
			name: "Zsign",
			dependencies: [
				.product(name: "OpenSSL", package: "OpenSSL-Package")
			],
			path: "src",
			exclude: [
				"common/archive.cpp",
				"zsign.cpp"
			],
			sources: [
				"archo.cpp",
				"bundle.cpp",
				"macho.cpp",
				"openssl.cpp",
				"signing.cpp",
				"zsign.mm",
				"common/base64.cpp",
				"common/fs.cpp",
				"common/json.cpp",
				"common/log.cpp",
				"common/sha.cpp",
				"common/timer.cpp",
				"common/util.cpp"
			],
			publicHeadersPath: "include",
			cxxSettings: [
				.headerSearchPath("."),
				.headerSearchPath("common"),
				.unsafeFlags(["-std=c++17"])
			]
		)
	]
)
