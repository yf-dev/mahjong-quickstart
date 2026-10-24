'use strict';
// Re-verify patches/ (no-op when already applied) so a node_modules installed
// with --ignore-scripts can never run unpatched.
require('./security-patches.cjs')();
// Webpack 4 (used by mdx-deck/Gatsby 2) uses MD4 hashes. OpenSSL 3 requires
// its legacy provider; leave the presentation CLI and all its arguments intact.
const {spawn} = require('node:child_process');
const env = {...process.env};
if (Number(process.versions.node.split('.')[0]) >= 17 &&
    !(env.NODE_OPTIONS || '').includes('--openssl-legacy-provider')) {
  env.NODE_OPTIONS = `${env.NODE_OPTIONS || ''} --openssl-legacy-provider`.trim();
}
const child = spawn(process.execPath, [require.resolve('mdx-deck/cli.js'), ...process.argv.slice(2)], {
  env, stdio: 'inherit',
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => child.kill(signal));
}
child.on('error', error => {console.error(error.message); process.exitCode = 1;});
child.on('exit', (code, signal) => {
  if (signal) process.exitCode = 128 + (require('node:os').constants.signals[signal] || 1);
  else process.exitCode = code;
});
