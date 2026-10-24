'use strict';
// Applies patches/<name>@<version>.patch (unified diffs) to EVERY installed
// copy of that exact package version, however deeply yarn nests it. Fail
// closed: no fuzz, no line offsets, and a patch with no installed target is an
// error. Files already in the patched state are left alone, so this is safe to
// re-run (postinstall, then again from scripts/mdx-deck.cjs).
//
//   node scripts/security-patches.cjs           apply (postinstall)
//   node scripts/security-patches.cjs --check   verify only, never write
//   node scripts/security-patches.cjs audit     yarn audit minus advisories the
//                                               patches mitigate
const fs = require('node:fs');
const path = require('node:path');
const appRoot = path.resolve(__dirname, '..');
const patchDir = path.join(appRoot, 'patches');

function parsePatch(filename) {
  const text = fs.readFileSync(filename, 'utf8');
  const field = name => (text.match(new RegExp(`^${name}: (.*)$`, 'm')) || [])[1];
  const spec = field('Package');
  if (!spec) throw Error(`${filename}: missing "Package: name@version" header`);
  const at = spec.lastIndexOf('@');
  const patch = {
    filename: path.basename(filename),
    package: spec.slice(0, at),
    version: spec.slice(at + 1),
    advisories: (field('Advisories') || '').split(/\s+/).filter(id => id.startsWith('GHSA-')),
    files: [],
  };
  const lines = text.split('\n');
  let file;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('--- a/') && (lines[i + 1] || '').startsWith('+++ b/')) {
      file = {name: lines[++i].slice(6), hunks: []};
      patch.files.push(file);
      continue;
    }
    const m = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(lines[i]);
    if (!m) continue; // free-form header text or "diff -ruN" separators
    if (!file) throw Error(`${filename}:${i + 1}: hunk before any file header`);
    const [oldCount, newCount] = [m[2] ?? '1', m[4] ?? '1'].map(Number);
    // A zero-length side is numbered by the line *before* it.
    const hunk = {old: [], new: [], oldEOF: false, newEOF: false,
      oldStart: Number(m[1]) + (oldCount ? 0 : 1), newStart: Number(m[3]) + (newCount ? 0 : 1)};
    while (hunk.old.length < oldCount || hunk.new.length < newCount || (lines[i + 1] || '').startsWith('\\')) {
      const line = lines[++i];
      if (line === undefined) throw Error(`${filename}: truncated hunk`);
      if (line.startsWith('\\')) {
        // "\ No newline at end of file" applies to the side(s) of the line above.
        if (lines[i - 1][0] !== '+') hunk.oldEOF = true;
        if (lines[i - 1][0] !== '-') hunk.newEOF = true;
        continue;
      }
      const kind = line === '' ? ' ' : line[0]; // editors may strip a blank context line's space
      if (!' +-'.includes(kind)) throw Error(`${filename}:${i + 1}: bad hunk line`);
      if (kind !== '+') hunk.old.push(line.slice(1));
      if (kind !== '-') hunk.new.push(line.slice(1));
    }
    if (hunk.old.length !== oldCount || hunk.new.length !== newCount) throw Error(`${filename}:${i + 1}: hunk length mismatch`);
    file.hunks.push(hunk);
  }
  if (!patch.files.length) throw Error(`${filename}: contains no file diffs`);
  return patch;
}

// Applies hunks bottom-up at their exact recorded lines; null if any mismatch.
function applyHunks(text, hunks, reverse) {
  const lines = text.split('\n');
  let finalNewline = lines[lines.length - 1] === '';
  if (finalNewline) lines.pop();
  for (const hunk of [...hunks].reverse()) {
    const [from, to] = reverse ? [hunk.new, hunk.old] : [hunk.old, hunk.new];
    const [fromEOF, toEOF] = reverse ? [hunk.newEOF, hunk.oldEOF] : [hunk.oldEOF, hunk.newEOF];
    const start = (reverse ? hunk.newStart : hunk.oldStart) - 1;
    if (from.some((line, i) => lines[start + i] !== line)) return null;
    if (start + from.length === lines.length) {
      if (fromEOF === finalNewline) return null;
      finalNewline = !toEOF;
    } else if (fromEOF) return null;
    lines.splice(start, from.length, ...to);
  }
  return lines.join('\n') + (finalNewline ? '\n' : '');
}

function findCopies(modules, wanted, found = new Map()) {
  if (!fs.existsSync(modules)) return found;
  for (const entry of fs.readdirSync(modules, {withFileTypes: true})) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const directory = path.join(modules, entry.name);
    if (entry.name.startsWith('@')) { findCopies(directory, wanted, found); continue; }
    const manifest = path.join(directory, 'package.json');
    if (!fs.existsSync(manifest)) continue;
    const {name, version} = JSON.parse(fs.readFileSync(manifest, 'utf8'));
    const key = `${name}@${version}`;
    if (wanted.has(key)) found.set(key, [...(found.get(key) || []), directory]);
    findCopies(path.join(directory, 'node_modules'), wanted, found);
  }
  return found;
}

function loadPatches() {
  return fs.readdirSync(patchDir).filter(f => f.endsWith('.patch')).sort()
    .map(f => parsePatch(path.join(patchDir, f)));
}

function apply(root = path.join(appRoot, 'node_modules'), checkOnly = false) {
  const patches = loadPatches();
  const copies = findCopies(root, new Set(patches.map(p => `${p.package}@${p.version}`)));
  const result = {patches: patches.length, copies: 0, applied: 0, alreadyApplied: 0};
  const missing = patches.filter(p => !copies.has(`${p.package}@${p.version}`));
  if (missing.length) throw Error('Missing security patch targets: ' + missing.map(p => p.filename).join(', '));
  for (const patch of patches) {
    for (const directory of copies.get(`${patch.package}@${patch.version}`)) {
      result.copies++;
      for (const file of patch.files) {
        const filename = path.join(directory, file.name);
        const text = fs.readFileSync(filename, 'utf8');
        if (applyHunks(text, file.hunks, true) !== null) { result.alreadyApplied++; continue; }
        const patched = checkOnly ? null : applyHunks(text, file.hunks, false);
        if (patched === null) {
          throw Error(`Security patch ${checkOnly ? 'not applied' : 'does not apply'}: ${patch.filename} -> ${filename}`);
        }
        fs.writeFileSync(filename, patched);
        result.applied++;
      }
    }
  }
  return result;
}

// yarn audit matches by version only, so it keeps reporting advisories the
// patches fix. Hide an advisory only when every vulnerable version it found is
// a patched version whose patch lists that GHSA id.
function audit() {
  const {spawnSync} = require('node:child_process');
  const mitigated = new Map(loadPatches().map(p => [`${p.package}@${p.version}`, new Set(p.advisories)]));
  const run = spawnSync('yarn', ['audit', '--json'], {cwd: appRoot, encoding: 'utf8', maxBuffer: 1 << 28});
  const advisories = new Map();
  for (const line of run.stdout.split('\n')) {
    if (!line.includes('"auditAdvisory"')) continue;
    const {advisory} = JSON.parse(line).data;
    advisories.set(advisory.github_advisory_id, advisory);
  }
  if (!advisories.size && run.status !== 0) throw Error('yarn audit failed: ' + run.stderr.trim());
  const open = [], hidden = [];
  for (const [id, a] of advisories) {
    const versions = [...new Set(a.findings.map(f => f.version))];
    const fixed = versions.every(v => (mitigated.get(`${a.module_name}@${v}`) || new Set()).has(id));
    (fixed ? hidden : open).push(`${a.severity.padEnd(8)} ${id} ${a.module_name}@${versions.join(',')} ${a.title}`);
  }
  const order = ['critical', 'high', 'moderate', 'low', 'info'];
  open.sort((x, y) => order.indexOf(x.split(' ')[0]) - order.indexOf(y.split(' ')[0]));
  console.log(`Mitigated by patches/ (${hidden.length}):\n  ` + hidden.join('\n  '));
  console.log(`Still open (${open.length}):\n  ` + open.join('\n  '));
}

module.exports = apply;
if (require.main === module) {
  if (process.argv[2] === 'audit') audit();
  else console.log(JSON.stringify(apply(undefined, process.argv.includes('--check'))));
}
