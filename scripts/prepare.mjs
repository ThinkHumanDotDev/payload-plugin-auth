// `prepare` runs after `pnpm install` in this repository and when the package is installed from a
// git URL or a GitHub tarball (package managers build such dependencies). It compiles `dist/` so a
// git install works like a registry install; a registry tarball already contains `dist/` and never
// runs this script.
import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc')
const dist = path.join(root, 'dist', 'index.js')

if (!existsSync(tsc)) {
  if (existsSync(dist)) process.exit(0) // already built (a production re-install of a built checkout)
  console.error(
    '[payload-auth] prepare: TypeScript is not installed, so dist/ cannot be built. Git installs need ' +
      'the development dependencies (install without --prod, then prune), or use the npm release.',
  )
  process.exit(1)
}

const result = spawnSync(process.execPath, [tsc, '-p', path.join(root, 'tsconfig.build.json')], {
  cwd: root,
  stdio: 'inherit',
})
process.exit(result.status ?? 1)
