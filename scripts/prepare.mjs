// `prepare` runs after `pnpm install` in this repository and when the package is installed from a
// git URL (pnpm/npm build git dependencies that declare it). It compiles `dist/` so a git install
// works like a registry install. A registry install never runs it: `dist/` is in the tarball.
import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc')

if (!existsSync(tsc)) {
  // Production installs (`pnpm install --prod`) of a registry tarball have no TypeScript: nothing to do.
  process.exit(0)
}

const result = spawnSync(process.execPath, [tsc, '-p', path.join(root, 'tsconfig.build.json')], {
  cwd: root,
  stdio: 'inherit',
})
process.exit(result.status ?? 1)
