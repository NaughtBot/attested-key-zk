# OpenSSL Provenance

`build-artifactbundle.sh` fetches OpenSSL from upstream at build time. The
source is pinned by commit SHA, not by tag, so a compromised upstream mirror
cannot redirect us to a different tree by repointing the tag.

## Pinned commit

| Field   | Value                                                                 |
|---------|-----------------------------------------------------------------------|
| Commit  | `fe686e15d84334b284f883118ed92f64b409b3aa`                            |
| Tag     | corresponds to `openssl-3.6.2`                                        |
| Repo    | https://github.com/openssl/openssl                                    |
| Pinned  | 2026-04-26                                                            |

## Verifying the pin

```bash
$ git ls-remote https://github.com/openssl/openssl refs/tags/openssl-3.6.2^{}
fe686e15d84334b284f883118ed92f64b409b3aa  refs/tags/openssl-3.6.2^{}
```

The `^{}` suffix dereferences the annotated tag to the commit object — this
is the value we pin against. The annotated tag object SHA (the unpeeled form)
differs and is not what we use.

## Bumping the pin

1. Pick a new release tag from https://github.com/openssl/openssl/tags.
2. Resolve the peeled commit: `git ls-remote https://github.com/openssl/openssl
   refs/tags/<tag>^{}`.
3. Update `OPENSSL_COMMIT` in `build-artifactbundle.sh`.
4. Update this file (commit SHA, tag, "Pinned" date).
5. Verify the build still produces working artifact bundles for all targets.

## Build override

For local experimentation, the values are also overridable via env vars:

- `ATTESTED_KEY_ZK_OPENSSL_COMMIT` — alternate commit SHA.
- `ATTESTED_KEY_ZK_OPENSSL_REPO_URL` — alternate fetch URL (e.g. local mirror).

These overrides exist for development; the build script's defaults are the
authoritative pin.
