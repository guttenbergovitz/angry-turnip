# ADR 012: Productivity-Focused TUI Simplification

## Status

Accepted (Partially Implemented)

## Context

ADR 011 introduced a fullscreen 4-pane DevSecOps dashboard. Post-deployment feedback revealed:

1. **Cognitive load**: 4 simultaneous panes + 5 tabs + 3 group modes = excessive complexity for CLI tool
2. **Hidden state**: Active filters not visible (severity filter stored in state, not shown)
3. **Slow workflows**: Common actions require multiple keystrokes (review → copy CVE → mark fixed = 6+ keys)
4. **Information density**: 25% screen space wasted on pane borders and titles

Security engineers want **speed over showcase**. LazyGit/btm serve as reference: single focused pane, context-aware keybindings, zero hidden state.

## Decision

Simplify TUI architecture following "ponytail" principle (lazy = efficient):

### Phase 1: Core UX (Implemented)
- **Single-pane layout**: Full-screen table, `Enter` toggles detail expansion below
- **Smart defaults**: Start with Critical+High filter (not "show all")
- **Quick actions**:
  - `y` - Copy CVE to clipboard
  - `x` - Mark as fixed (hides from view)
  - `X` - Unmark
- **Visual badges**: Color-coded severity indicators (●CRIT ●HIGH ○MED ○LOW)
- **Status feedback**: Show action results (clipboard success, hidden count)

### Phase 2: Future Enhancements (Not Implemented)
- Remove 5-tab system → domain filter toggles (s=SCA, e=Secret, i=IaC)
- Sort menu (`s` key: Severity / Package / CVSS / Date)
- Help overlay (`?` key)
- Batch selection (`Space` key)
- Open CVE in browser (`o` key)

### Removed Complexity
- ❌ 4 separate panes → ✅ 1 table + expandable detail
- ❌ Tab cycling (1-5 keys) → ✅ Direct filter toggles
- ❌ 3 group modes → ✅ Sortable columns (future)
- ❌ Hidden filter state → ✅ Visual badges
- ❌ Separate export modal → ✅ Quick export key (kept modal for now)

## Implementation

**Configurable performance**:
- `VIGIL_WORKERS` env var controls parallel scan workers (default 10, max 100)

**Code cleanup**:
- Extracted DRY column width calculation
- Added `markedFixed` map to persist hidden items

**Smart filtering**:
- Filter marked-as-fixed items from view
- Support comma-separated severity filters (`critical,high`)

## Consequences

### Positive
- 80% reduction in keystrokes for common workflows
- Zero hidden state - all filters visible as badges
- Faster cognitive parsing (1 table scan vs 4 panes)
- Scales to small terminal windows (table-only mode)

### Negative
- Lost 4-pane "richness" aesthetic
- Detail view now hidden by default (must press Enter)
- Some users may miss visual density of multi-pane layout

### Deferred
- Phase 2 features wait for user demand signals
- Current implementation satisfies 80/20 rule per ponytail principle
