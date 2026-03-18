# scripts/

Development scripts for testing and validation.

## diff-lockfile: Lockfile parsing regression test

Compares `AnalyzeLibrary()` output between two Git refs using real-world lockfiles from popular OSS projects. Use this to verify that changes to the library scanning code (scanner package, Trivy parser integration) do not introduce regressions.

### When to run

- Refactoring `scanner/base.go` (`AnalyzeLibrary`, `scanLibraries`)
- Changing `scanner/dispatch.go` (file-to-parser mapping)
- Updating Trivy dependency version in `go.mod`
- Modifying `scanner/trivy/jar/` (JAR/WAR parsing)
- Adding or removing a language parser

### Usage

```bash
# Compare current branch against master
make diff-lockfile

# Compare against a specific commit or tag
make diff-lockfile BASE=abc1234
make diff-lockfile BASE=v0.27.0
```

### What it does

1. Downloads 17 lockfiles/binaries from the internet (GitHub, Maven Central)
2. Creates a `git worktree` for the base ref and builds the comparison tool there
3. Runs `AnalyzeLibrary()` on both refs for all fixtures
4. Compares JSON output (sorted by name+version for deterministic comparison)
5. Prints results and writes detailed log to `/tmp/diet-compare/comparison.log`

### Fixtures

Defined in `scripts/lockfile-fixtures.json`. All URLs use pinned tags for reproducibility.

| Type | Project | Source |
|------|---------|--------|
| npm | nestjs/nest | GitHub |
| yarn | facebook/react | GitHub |
| pnpm | vitejs/vite | GitHub |
| pip | home-assistant/core | GitHub |
| pipenv | pypa/pipenv | GitHub |
| poetry | python-poetry/poetry | GitHub |
| bundler | rails/rails | GitHub |
| cargo | BurntSushi/ripgrep | GitHub |
| composer | matomo-org/matomo | GitHub |
| go.mod | kubernetes/kubernetes | GitHub |
| pom.xml | apache/spark | GitHub |
| mix | phoenixframework/phoenix | GitHub |
| swift | swift-composable-architecture | GitHub |
| jar (x2) | log4j-core, commons-lang3 | Maven Central |
| gobinary | mikefarah/yq | GitHub Releases |
| rustbinary | cargo-bins/cargo-binstall | GitHub Releases |

### Adding fixtures

Edit `scripts/lockfile-fixtures.json`. Each entry:

```json
{
  "type": "npm",
  "project": "expressjs/express",
  "tag": "v5.1.0",
  "filename": "package-lock.json",
  "url": "https://raw.githubusercontent.com/expressjs/express/v5.1.0/package-lock.json"
}
```

For binaries, add `filemode` (493 = 0755) and optionally `archivePath` for tar.gz:

```json
{
  "type": "gobinary",
  "project": "mikefarah/yq",
  "tag": "v4.44.6",
  "filename": "yq",
  "filemode": 493,
  "url": "https://github.com/mikefarah/yq/releases/download/v4.44.6/yq_linux_amd64"
}
```

### Output

```
=== Summary ===
Total: 17 fixtures
Identical: 16
Different: 1
Skipped: 0
```

Exit code 0 = all identical, 1 = differences found.

Detailed log: `/tmp/diet-compare/comparison.log`
