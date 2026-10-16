// Learn more https://docs.expo.io/guides/customizing-metro
const path = require('node:path')
const { getDefaultConfig } = require('expo/metro-config')

// The example is part of the pnpm workspace, so Expo configures watchFolders and nodeModulesPaths for the workspace
// root automatically. The library and the example share one lockfile, so react / react-native resolve to a single copy.
const config = getDefaultConfig(__dirname)

// Bundle the library from its source. Its workspace link points to the repo root, an ancestor of the link, which Metro
// doesn't follow. `expo start` maps it with the tsconfig paths, but React Native Harness runs Metro without Expo's CLI.
const librarySource = path.resolve(__dirname, '../src/index.ts')
config.watchFolders = [...config.watchFolders, path.dirname(librarySource)]
const resolveRequest = config.resolver.resolveRequest
config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === '@animo-id/expo-secure-environment') return { type: 'sourceFile', filePath: librarySource }
  return (resolveRequest ?? context.resolveRequest)(context, moduleName, platform)
}

// Expo serves the bundle from the workspace root (`/example/index.bundle`), but React Native Harness resolves its entry
// point and test files from the server root. Under Harness, which sets RN_HARNESS, serve from the example instead.
if (process.env.RN_HARNESS) {
  const examplePrefix = `/${path.relative(config.server.unstable_serverRoot, __dirname)}/`
  const rewriteRequestUrl = config.server.rewriteRequestUrl

  config.server.unstable_serverRoot = __dirname
  config.server.rewriteRequestUrl = (url) => {
    const rewritten = new URL(rewriteRequestUrl(url), 'http://localhost')
    if (rewritten.pathname.startsWith(examplePrefix)) {
      rewritten.pathname = `/${rewritten.pathname.slice(examplePrefix.length)}`
    }
    return url.startsWith('/') ? `${rewritten.pathname}${rewritten.search}` : rewritten.toString()
  }
}

config.transformer.getTransformOptions = async () => ({
  transform: {
    experimentalImportSupport: false,
    inlineRequires: true,
  },
})

module.exports = config
