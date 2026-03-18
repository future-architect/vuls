package scanner

import (
	"os"
	"testing"
)

func TestDetectParserType(t *testing.T) {
	tests := []struct {
		path     string
		filemode os.FileMode
		want     parserType
	}{
		// === Node.js ===
		{"package-lock.json", 0644, parserNpm},
		{"app/package-lock.json", 0644, parserNpm},
		{"node_modules/foo/package-lock.json", 0644, parserNone}, // excluded
		{"yarn.lock", 0644, parserYarn},
		{"node_modules/yarn.lock", 0644, parserNone}, // excluded
		{".yarn/yarn.lock", 0644, parserNone},        // excluded
		{"pnpm-lock.yaml", 0644, parserPnpm},
		{"node_modules/pnpm-lock.yaml", 0644, parserNone}, // excluded
		{"bun.lock", 0644, parserBun},

		// === Python ===
		{"requirements.txt", 0644, parserPip},
		{"Pipfile.lock", 0644, parserPipenv},
		{"poetry.lock", 0644, parserPoetry},
		{"uv.lock", 0644, parserUv},

		// === Ruby ===
		{"Gemfile.lock", 0644, parserBundler},

		// === Rust ===
		{"Cargo.lock", 0644, parserCargo},

		// === PHP ===
		{"composer.lock", 0644, parserComposer},

		// === Go ===
		{"go.mod", 0644, parserGoMod},
		{"go.sum", 0644, parserNone}, // go.sum alone returns nothing; processed with go.mod

		// === Java ===
		{"pom.xml", 0644, parserPom},
		{"gradle.lockfile", 0644, parserGradle},
		{"custom-gradle.lockfile", 0644, parserGradle},
		{"app.jar", 0644, parserJar},
		{"app.war", 0644, parserJar},
		{"app.ear", 0644, parserJar},
		{"app.par", 0644, parserJar},
		{"APP.JAR", 0644, parserJar}, // case-insensitive extension

		// === .NET ===
		{"packages.lock.json", 0644, parserNugetLock},
		{"packages.config", 0644, parserNugetConfig},
		{"myapp.deps.json", 0644, parserDotnetDeps},
		{"datacollector.deps.json", 0644, parserDotnetDeps},
		{"Directory.Packages.props", 0644, parserPackagesProps},
		{"directory.packages.props", 0644, parserPackagesProps}, // case-insensitive

		// === C/C++ ===
		{"conan.lock", 0644, parserConan},

		// === Dart ===
		{"pubspec.lock", 0644, parserPub},

		// === Elixir ===
		{"mix.lock", 0644, parserMix},

		// === Swift ===
		{"Podfile.lock", 0644, parserCocoapods},
		{"Package.resolved", 0644, parserSwift},

		// === Executable binaries ===
		{"gobinary", 0755, parserExecutable},
		{"hello-rust", 0755, parserExecutable}, // detected as executable, type determined at parse time
		{"myapp", 0755, parserExecutable},
		{"myapp", 0644, parserNone}, // not executable

		// === Not recognized ===
		{"README.md", 0644, parserNone},
		{"Dockerfile", 0644, parserNone},
		{"main.go", 0644, parserNone},
		{".gitignore", 0644, parserNone},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectParserType(tt.path, tt.filemode)
			if got != tt.want {
				t.Errorf("detectParserType(%q, %04o) = %q, want %q", tt.path, tt.filemode, got, tt.want)
			}
		})
	}
}
