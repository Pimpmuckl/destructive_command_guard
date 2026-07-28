#!/usr/bin/env bats

@test "Codex plugin matches the fork release and contains only its hook contract" {
    run python3 - "$BATS_TEST_DIRNAME/../.." <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
plugin = root / "plugins/destructive-command-guard"
manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text())
marketplace = json.loads((root / ".agents/plugins/marketplace.json").read_text())
hooks = json.loads((plugin / "hooks/hooks.json").read_text())
package_version = re.search(r'^version = "([^"]+)"$', (root / "Cargo.toml").read_text(), re.M).group(1)

assert manifest["name"] == "destructive-command-guard"
assert manifest["version"] == package_version
assert marketplace["name"] == "pimpmuckl-dcg"
assert marketplace["plugins"][0]["source"]["path"] == "./plugins/destructive-command-guard"
handler = hooks["hooks"]["PreToolUse"][0]
assert handler["matcher"] == "Bash"
assert handler["hooks"][0]["command"] == '"${PLUGIN_DATA}/dcg"'
assert handler["hooks"][0]["commandWindows"] == '"${PLUGIN_DATA}\\dcg.exe"'
assert sorted(path.relative_to(plugin).as_posix() for path in plugin.rglob("*") if path.is_file()) == [
    ".codex-plugin/plugin.json",
    "hooks/hooks.json",
]
PY
    [ "$status" -eq 0 ]
}
