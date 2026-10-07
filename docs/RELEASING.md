# Releasing Praxis

The CLI/npm package, GitHub Action, Claude Code plugin, and VS Code extension
have separate distribution surfaces. A GitHub release does not publish npm or
the VS Code extension.

## Prepare

1. Choose the CLI patch version and update `package.json`, both root lockfile
   version fields, and `docs/RELEASE-<version>.md`.
2. Update public examples to the intended Action tag. Keep independently
   versioned integrations consistent with their own manifests and lockfiles.
3. Run `npm ci` and `npm run release:check`. This checks CLI tests, lint,
   production dependency advisories, scan determinism, a complete zero-critical
   self-scan, editor compilation/runtime tests, package exclusions, and an
   installed-package scan with redaction and cache parity.
4. Review `git diff --check` and the package contents. Keep `docs/internal/`,
   runtime state, credentials, test fixtures, and local binaries out of Git and
   the npm package.

## GitHub and Marketplace

1. Commit the complete release and push it. Wait for CI to pass on that exact
   commit, including all four Node versions, determinism, package/editor checks,
   and the local Action smoke test.
2. Create an annotated immutable version tag, such as `v1.2.4`, on that commit.
   Never replace a previously published version tag with different source.
3. Pack the committed source with `npm pack`. Attach the tarball and its SHA-256
   checksum to the GitHub release, using the reviewed release notes.
4. Advance the floating `v1` Action tag deliberately to the same commit. Check
   the prior remote value first and protect the update against concurrent changes.
5. Verify the release, version tag, floating tag, assets, and successful CI all
   refer to the reviewed source. Consumers can use the exact version tag or
   commit instead of the floating tag.

## npm publication

The maintainer publishes npm separately from the same clean, committed checkout:

```bash
git checkout v1.2.4
npm ci
npm publish
```

`prepublishOnly` reruns the release gates and rejects an uncommitted working
tree or a version different from the committed package metadata. Authentication
and npm account requirements must be satisfied by the publishing maintainer.
After publication, confirm `npm view praxis-sec version dist-tags` and install
that exact registry version in a clean project. GitHub and npm may legitimately
show different versions until this step completes.
