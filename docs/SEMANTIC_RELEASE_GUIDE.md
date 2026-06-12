# Semantic Release Guide for LaRuche

This guide explains how to set up and use semantic release for LaRuche.

## 🎯 Overview

LaRuche uses **semantic-release** for automated version management and package publishing. It follows the [Conventional Commits](https://www.conventionalcommits.org/) specification to determine version bumps and generate changelogs automatically.

## 🔧 Setup

### Prerequisites

1. **Node.js 20+** installed
2. **npm** installed
3. **GitHub repository** with SSH access configured
4. **GitHub Personal Access Token** with repo permissions

### Installation

```bash
# Install dependencies
npm install

# Verify installation
npx semantic-release --help
```

## 📝 Configuration Files

### `package.json`

Contains project metadata and semantic release configuration:
- Repository URL (SSH format)
- Current version (`0.0.0-development`)
- Semantic release plugins configuration

### `.releaserc`

Semantic release configuration:
- **Branches**: `main` and `prod`
- **Plugins**:
  - `@semantic-release/commit-analyzer` - Analyzes commits
  - `@semantic-release/release-notes-generator` - Generates release notes
  - `@semantic-release/changelog` - Updates CHANGELOG.md
  - `@semantic-release/git` - Commits release changes
  - `@semantic-release/exec` - Runs custom commands
  - `@semantic-release/github` - Publishes GitHub releases

### `CHANGELOG.md`

Automatically updated changelog following [Keep a Changelog](https://keepachangelog.com/) format.

## 🚀 Usage

### Local Testing (Dry Run)

```bash
# Set your GitHub token
export GH_TOKEN="your_github_personal_access_token"

# Run dry-run to test without publishing
npx semantic-release --dry-run
```

### CI/CD Integration

The GitHub Actions workflow (`.github/workflows/ci.yml`) automatically runs semantic release:

1. **Triggers**: On pushes to `main` or `prod` branches
2. **Requirements**: All tests and scans must pass
3. **Process**:
   - Analyzes commits since last release
   - Determines version bump (patch, minor, major)
   - Updates CHANGELOG.md
   - Creates Git tag
   - Publishes GitHub release

### Required GitHub Secrets

- `GH_TOKEN`: GitHub Personal Access Token with `repo` permissions
- `NPM_TOKEN`: Only needed if publishing to npm registry

## 📝 Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Commit Types

| Type | Description | Release Impact |
|------|-------------|----------------|
| `feat` | New feature | Minor version bump |
| `fix` | Bug fix | Patch version bump |
| `docs` | Documentation changes | No release |
| `style` | Code style/formatting | No release |
| `refactor` | Code refactoring | No release |
| `perf` | Performance improvements | No release |
| `test` | Test additions/updates | No release |
| `chore` | Build process/maintenance | No release |
| `BREAKING CHANGE` | Breaking changes | Major version bump |

### Examples

```bash
# Minor version (new feature)
git commit -m "feat(ssh): add malware detection capability"

# Patch version (bug fix)
git commit -m "fix(ftp): correct authentication logic bug"

# Major version (breaking change)
git commit -m "feat(api): add new endpoint (BREAKING CHANGE)"

# No release (documentation)
git commit -m "docs: update README with semantic release guide"

# No release (refactoring)
git commit -m "refactor(detection): improve module structure"
```

## 🔄 Release Process

1. **Commit Changes**: Make changes following conventional commits
2. **Push to Branch**: Push to `main` or `prod` branch
3. **CI Runs**: GitHub Actions runs tests and builds
4. **Semantic Release**:
   - Analyzes commits
   - Determines version bump
   - Updates CHANGELOG.md
   - Creates Git tag (e.g., `v1.2.3`)
   - Publishes GitHub release
5. **Done!** 🎉

## 🛠️ Troubleshooting

### "Repository not found" Error

**Cause**: GitHub authentication failed

**Solution**:
1. Ensure SSH keys are set up: `ssh -T git@github.com`
2. Set GH_TOKEN: `export GH_TOKEN="your_token_here"`
3. Check repository URL in package.json matches your remote

### "Cannot find module" Error

**Cause**: npm packages not installed

**Solution**:
```bash
npm install
```

### No Release Created

**Cause**: Commits don't follow conventional format or are on wrong branch

**Solution**:
1. Check you're on `main` or `prod` branch
2. Use proper commit message format
3. Ensure at least one `feat:` or `fix:` commit

## 📋 Version Format

Versions follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## 🎉 Benefits

- ✅ **Automated version management** - No manual version bumping
- ✅ **Consistent changelogs** - Generated from commit messages
- ✅ **Professional releases** - GitHub releases with notes
- ✅ **Standardized commits** - Clear commit message format
- ✅ **CI Integration** - Only releases after tests pass

## 📚 Resources

- [Semantic Release Documentation](https://semantic-release.gitbook.io/semantic-release/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic Versioning](https://semver.org/)