// Package embedded provides the embedded filesystem containing the CLI manifest,
// audit scripts, and Python helpers. Used when the binary runs outside a repo.
package embedded

import "embed"

// EmbeddedFS contains cli/, audit/mac/, and core/ files for standalone distribution.
// Paths are relative to the module root.
//
//go:embed cli/commands.json cli/commands.schema.json audit/mac audit/linux core/probe_failures_summary.py core/render_heatmaps.py
var EmbeddedFS embed.FS
