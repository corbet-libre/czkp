import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath, pathToFileURL} from 'node:url';

const worker = realpathSync(fileURLToPath(new URL('../runtime/node-verifier.mjs', import.meta.url)));
const packageDirectory = dirname(dirname(worker));

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'czkp-worker-entry-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  const packageAlias = join(directory, 'node_modules', '@corbet-labs', 'czkp');
  mkdirSync(dirname(packageAlias), {recursive: true});
  symlinkSync(packageDirectory, packageAlias, 'dir');
  const directoryEntry = join(packageAlias, 'runtime', 'node-verifier.mjs');
  const fileEntry = join(directory, 'worker-alias.mjs');
  symlinkSync(worker, fileEntry, 'file');
  const invalidConfig = join(directory, 'invalid-config.json');
  writeFileSync(invalidConfig, '{');
  return {
    directory,
    invalidConfig,
    missingConfig: join(directory, 'missing-config.json'),
    entries: [
      {name: 'direct file', path: worker, flags: []},
      {name: 'npm-style directory symlink', path: directoryEntry, flags: []},
      {name: 'file alias', path: fileEntry, flags: []},
      // The directory alias preserves the worker's relative module imports too.
      {name: 'preserved main symlink', path: directoryEntry, flags: ['--preserve-symlinks-main']},
    ],
  };
}

function run(directory, arguments_, input) {
  const result = spawnSync(process.execPath, arguments_, {
    cwd: directory,
    input,
    encoding: 'utf8',
    timeout: 5000,
    maxBuffer: 64 * 1024,
    killSignal: 'SIGKILL',
    // Exercise the real worker without an inherited Node preload or loader.
    env: {...process.env, NODE_OPTIONS: ''},
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, 'worker must terminate itself within the bound');
  return result;
}

test('actual worker refuses invalid requests through direct and symlink entries', async t => {
  const state = fixture(t);
  const cases = [
    {name: 'missing configuration argument', arguments: [], input: '{}'},
    {name: 'missing absolute configuration file', arguments: [state.missingConfig], input: '{}'},
    {name: 'invalid absolute configuration JSON', arguments: [state.invalidConfig], input: '{}'},
    {name: 'relative configuration path', arguments: ['invalid-config.json'], input: '{}'},
    {name: 'malformed bounded JSON input', arguments: [state.invalidConfig], input: '{'},
    {name: 'empty bounded input', arguments: [state.invalidConfig], input: ''},
  ];
  for (const entry of state.entries) {
    for (const vector of cases) {
      await t.test(`${entry.name}: ${vector.name}`, () => {
        const result = run(state.directory,
          [...entry.flags, entry.path, ...vector.arguments], vector.input);
        assert.equal(result.status, 1, 'invalid requests must not silently exit successfully');
        assert.equal(result.stdout, '', 'refusal must not emit a verification verdict');
        assert.equal(result.stderr, '', 'refusal must not leak configuration or input details');
      });
    }
  }
});

test('importing the actual worker exports verify without taking over the driver', async t => {
  const state = fixture(t);
  const marker = 'czkp-import-driver-ok';
  for (const [index, entry] of state.entries.entries()) {
    await t.test(entry.name, () => {
      const driver = join(state.directory, `import-driver-${index}.mjs`);
      writeFileSync(driver, [
        "import assert from 'node:assert/strict';",
        "Object.defineProperty(process, 'stdin', {configurable: true, get() {",
        "  throw new Error('import must not read stdin');",
        '}});',
        `const imported = await import(${JSON.stringify(pathToFileURL(entry.path).href)});`,
        "assert.equal(typeof imported.verify, 'function');",
        'assert.equal(process.exitCode, undefined);',
        `console.log(${JSON.stringify(marker)});`,
        '',
      ].join('\n'));
      const result = run(state.directory, [...entry.flags, driver], 'not a proof record\n');
      assert.equal(result.status, 0, 'import must leave the driver in control');
      assert.equal(result.stdout, `${marker}\n`);
      assert.equal(result.stderr, '');
    });
  }
});
