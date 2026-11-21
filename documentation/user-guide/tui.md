# Interactive DevSecOps Dashboard (TUI)

Vigil includes a productivity-focused terminal dashboard designed for fast security auditing and vulnerability triage.

```
🛡️ VIGIL DEVSECOPS DASHBOARD | 14 VULNS | 2 SECRETS | 1 IAC RISKS
[1] Vulns (SCA)  [2] Secrets  [3] IaC Security  [4] Licenses  [5] Dep Graph
●CRIT ●HIGH ○MED ○LOW | Findings: 14 | Hidden: 0
╭─────────────────────────────────────────────────────────────────────────────────────────────────╮
│  Security Findings (Enter to expand details)                                                    │
│ DOMAIN  SEVERITY   TARGET / PACKAGE           ID / RULE         REASON SUMMARY                  │
│─────────────────────────────────────────────────────────────────────────────────────────────────│
│ SCA     CRITICAL   lodash@4.17.20             CVE-2021-23337    Prototype pollution...          │
│ SCA     HIGH       axios@0.21.1               CVE-2021-3749     SSRF vulnerability...           │
│ SECRET  HIGH       .env                       AWS_ACCESS_KEY    Hardcoded AWS key...            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────╯
 [↑/↓] Navigate | [Enter] Details | [y] Copy | [x/X] Mark Fixed | [1-5] Tab | [c/h/m/l] Filter | [/] Search | [e] Export | [q] Quit
```

**Smart Defaults**: Starts with Critical+High filter only. Press `a` to show all severities.

---

## 📐 Layout Architecture

**Single-Pane Focus**: Full-screen findings table optimized for speed.

- **Table View**: All findings in sortable 5-column layout (`DOMAIN`, `SEVERITY`, `TARGET`, `ID/RULE`, `REASON`)
- **Detail Expansion**: Press `Enter` to toggle detail pane below selected finding (Package info, Reason, Dependency chain, Remediation)
- **Visual Filter Badges**: Active severity filters shown as colored badges (●CRIT ●HIGH ○MED ○LOW)
- **Status Bar**: Context-aware keybindings always visible

---

## ⌨️ Keybindings & Controls

### Navigation

| Key | Action |
| --- | --- |
| `↑` / `↓` / `k` / `j` | Navigate table rows |
| `Enter` | Toggle detail pane expansion (collapsed by default) |

### Quick Actions

| Key | Action |
| --- | --- |
| `y` | Copy CVE/Rule ID to clipboard |
| `x` | Mark finding as fixed (hides from view) |
| `X` | Unmark finding (unhide) |

### Tabs (Security Domains)

| Key | Domain | Content |
| --- | --- | --- |
| `1` | Vulns (SCA) | Software Composition Analysis vulnerabilities |
| `2` | Secrets | Hardcoded AWS keys, PAT tokens, SSH keys, DB credentials |
| `3` | IaC Security | Dockerfile & GitHub Actions security linting issues |
| `4` | Licenses | Permissive vs Copyleft (GPL/AGPL) license risk analysis |
| `5` | Dep Graph | Complete dependency graph nodes |

### Filtering & Search

| Key | Action |
| --- | --- |
| `c` | Filter: `CRITICAL` severity only |
| `h` | Filter: `HIGH` severity only |
| `m` | Filter: `MEDIUM` severity only |
| `l` | Filter: `LOW` severity only |
| `a` / `Esc` | Reset all filters and search (show all) |
| `/` | Open live search prompt (filter by text) |

**Smart Default**: TUI starts with Critical+High filter active. Visual badges show active filters.

### Export & Quit

| Key | Action |
| --- | --- |
| `e` | Open Export Report Dialog (`JSON`, `CSV`, `Markdown`, `CycloneDX`, `SPDX`) |
| `q` / `Ctrl+C` | Exit dashboard |

## 🔧 Configuration

**Worker Pool**: Control parallel scan performance via environment variable:
```bash
VIGIL_WORKERS=20 vigil scan  # Default: 10, Max: 100
```
