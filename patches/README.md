# Security patches

mdx-deck 4 pins Gatsby 2 / webpack 4, so some vulnerable packages cannot be
upgraded. Each `<name>@<version>.patch` here is a plain unified diff that
`scripts/security-patches.cjs` applies (postinstall, and again before every
`yarn start`/`yarn build`) to **every** installed copy of that exact version.

- No fuzz or offsets: a patch that does not match exactly fails the install.
- A patch with no installed target fails the install (lockfile drift).
- `node scripts/security-patches.cjs --check` verifies without writing.
- `yarn audit:security` runs `yarn audit` and hides only advisories listed in
  a patch's `Advisories:` header for the patched version.

Production serves only the static `public/` output through nginx; `Scope:`
says where the patched code actually runs.

## Adding or updating a patch

```sh
cp -r node_modules/<pkg> /tmp/a && cp -r node_modules/<pkg> /tmp/b
# edit /tmp/b, then:
(cd /tmp && diff -ruN a b | sed -E 's#^(---|\+\+\+) ([ab]/[^\t]*)\t.*#\1 \2#') > patches/<pkg>@<ver>.patch
```

Prepend the `Package:`, `Advisories:`, `Scope:`, `Why:` header (scoped names
use `+` in the file name, e.g. `@graphql-tools+utils@7.2.5.patch`). The files
also work with `patch -p1` run inside the package directory.

Keep `../mahjong-quickstart-anon/patches` identical.
