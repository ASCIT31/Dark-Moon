// Darkmoon branding — logo art data.
//
// Upstream opencode moved the logo into a pure-data module
// (packages/tui/src/logo.ts), rendered by packages/tui/src/component/logo.tsx
// and by packages/opencode/src/cli/ui.ts (as `glyphs`). This file replaces
// ONLY the `logo` art with the DARK MOON wordmark and keeps `go`/`marks`
// byte-identical to upstream, because `go` is imported elsewhere
// (component/bg-pulse-render.ts, cli/cmd/run/splash.ts).
//
// The renderer treats the chars `_ ^ ~ ,` as shadow markers; every other
// char (including the box-drawing glyphs below) renders as plain text, so
// this art needs no markers. `left` renders muted, `right` renders bold.

export const logo = {
  left: [
    `██████╗  █████╗ ██████╗ ██╗  ██╗`,
    `██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝`,
    `██║  ██║███████║██████╔╝█████╔╝ `,
    `██║  ██║██╔══██║██╔══██╗██╔═██╗ `,
    `██████╔╝██║  ██║██║  ██║██║  ██╗`,
    `╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝`,
  ],
  right: [
    `███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗`,
    `████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║`,
    `██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║`,
    `██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║`,
    `██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║`,
    `╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝`,
  ],
}

export const go = {
  left: ["    ", "█▀▀▀", "█_^█", "▀▀▀▀"],
  right: ["    ", "█▀▀█", "█__█", "▀▀▀▀"],
}

export const marks = "_^~,"
