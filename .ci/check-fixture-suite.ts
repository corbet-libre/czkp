// The fixture proof suite must run the exact SDKs its lockfile resolved. Third-party
// dependencies are declared as semver ranges; exactness comes from the lockfile, so
// this checks what actually runs: the installed identity of each SDK equals the
// version the fixture lockfile resolved, and the proving SDK equals the exact version
// that czkp's own native SDK declaration pins.
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname, join, resolve} from 'node:path';

const fixture = resolve(process.argv[2] ?? '.');
const lock = JSON.parse(readFileSync(join(fixture, 'package-lock.json'), 'utf8'));
const sdk = JSON.parse(readFileSync(new URL('./native-sdk.json', import.meta.url), 'utf8'));
const origins = [join(fixture, 'package.json'), join(fixture, 'runtime/accounting/package.json')];
for (const origin of origins) {
  for (const name of ['@aztec/bb.js', '@noir-lang/noir_js']) {
    const resolved = lock.packages?.[`node_modules/${name}`]?.version;
    assert.ok(resolved, `${name} missing from the fixture lockfile`);
    let directory = dirname(createRequire(origin).resolve(name));
    let found = false;
    for (;;) {
      const path = join(directory, 'package.json');
      if (existsSync(path)) {
        const metadata = JSON.parse(readFileSync(path, 'utf8'));
        if (metadata.name === name) {
          assert.equal(metadata.version, resolved, `${name} fixture suite drift`);
          if (name === '@aztec/bb.js') {
            assert.equal(metadata.version, sdk.version, `${name} differs from the pinned native SDK`);
          }
          console.log(`Fixture SDK ${name} ${metadata.version}`);
          found = true;
          break;
        }
      }
      const parent = dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
    assert.ok(found, `Missing installed package identity: ${name}`);
  }
}
