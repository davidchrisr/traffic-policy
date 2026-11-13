# Traffic Policy design system

This is the design system for the Debian/nftables application. Product pages and
the development catalog in `apps/controller/catalog/` use the same tokens and
owned components. This document owns visual presentation and component states.
[Architecture](docs/ARCHITECTURE.md) owns system and policy behavior;
[API_CONTRACT.md](API_CONTRACT.md) owns wire formats.

## Overview

Traffic Policy helps an administrator understand traffic, review unknown
destinations, and edit instance permissions. Use a compact grouped-list layout
with the Inter type scale and neutral selection. The Monitor uses an indented
hierarchy above a timeline, with a contextual inspector beside it.

Use the installed shadcn-svelte component base with owned variants. The catalog
demonstrates the actual shared components; its illustrative data is labeled and
never appears as production observations.

## Colors and themes

The required theme is dark. `apps/controller/src/app.css` owns all tokens;
`apps/controller/catalog/catalog.css` contains only catalog layout and static
state specimens.

| Role                          | Value                 | Use                                          |
| ----------------------------- | --------------------- | -------------------------------------------- |
| Background / foreground       | `#000000` / `#f4f4f4` | Canvas and main text                         |
| Card, popover / foreground    | `#080808` / `#f4f4f4` | Panels and overlays                          |
| Primary / foreground          | `#126df0` / `#ffffff` | Main actions, 4.70:1 contrast                |
| Primary hover / foreground    | `#1b70ef` / `#ffffff` | Hover, 4.55:1 contrast                       |
| Primary pressed               | `#105dcf`             | Pressed main action                          |
| Muted, secondary / foreground | `#161616` / `#aaaaaa` | Metadata and secondary surfaces              |
| Secondary foreground          | `#f4f4f4`             | Secondary control labels                     |
| Hover                         | `#191919`             | Quiet row and control hover                  |
| Accent / foreground           | `#262626` / `#f4f4f4` | Selected rows, navigation, options           |
| Border / input                | `#292929` / `#767676` | Separators / essential field boundaries      |
| Focus                         | `#649ff0`             | Keyboard focus                               |
| Destructive                   | `#ff6767`             | Errors and destructive actions               |
| Received / sent               | `#6fb6fe` / `#f0995b` | Blue download / orange upload                |
| Traffic pill / foreground     | `#080808` / `#ffffff` | Outlined measurements, 20.03:1 text contrast |
| Allow / pending               | `#78d85f` / `#f4c75d` | Status text and icons                        |
| Text selection / foreground   | `#2464b8` / `#ffffff` | Selected text, 5.85:1 contrast               |

Traffic colors are independent of keyboard focus and destructive actions.
`--chart-1` uses `--traffic-received`; `--chart-2` uses `--traffic-sent`.
Received/Sent labels and arrows identify the series. Sent traffic color does not
encode a blocked connection or failed operation. Both traffic colors share about
OKLCH lightness 0.76 and chroma 0.13 (hues 250 and 55), so neither direction
looks heavier; keep that match when changing either color. `TrafficMeasure` uses
side-by-side pills with blue/orange outlines and arrows, white values, and a
dark background. Pill text is 12px / 18px, with 6px horizontal padding, 1px
borders, 5px corners, and a 4px gap.

Use neutral selection fills. Primary hover preserves readable label contrast.
Essential control boundaries are brighter than decorative separators.

## Typography

Self-host Inter 4.1. Its variable upright WOFF2 and license are in
`apps/controller/static/fonts/inter/`, from the
[official Inter release](https://github.com/rsms/inter/releases/tag/v4.1). Use
`"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`. Enable
optical sizing. Use system monospace for addresses and code and tabular figures
for exact numeric comparisons.

| Role              | Size / line height | Weight |
| ----------------- | ------------------ | ------ |
| Page title        | 24px / 32px        | 700    |
| Section title     | 16px / 24px        | 600    |
| Body              | 14px / 20px        | 400    |
| Control           | 14px / 20px        | 500    |
| Supporting text   | 12px / 18px        | 400    |
| Emphasized metric | 22px / 28px        | 700    |

`metric-value` owns emphasized totals. ECharts uses the same font and 12px
labels. Time axes use at least one-minute tick spacing, show hours/minutes for
short ranges and dates for longer ranges; tooltips retain exact timestamps and
byte values. The catalog's 20-minute timeline is illustrative. Its system-font
toggle is a comparison tool confined to the catalog.

## Brand mark

The mark is a fork for allow and block: one line splits, the upper branch passes
with an arrowhead, and the lower branch stops short of a bar. `LogoMark` draws
it with round 2.5-unit strokes on Lucide's 24-unit grid, a step heavier than the
navigation icons, in the current text color beside the product name: 20px in
navigation and 30px in the sign-in title.

The favicon and installed-app icons use the same drawing, white on black.
`apps/controller/static/favicon.svg` is the rounded-tile source for the favicon
and the 192px and 512px icons. `apps/controller/brand/` holds the full-square
sources: the maskable icon keeps the mark inside the central 80% circle, and the
Apple touch icon is opaque.

## Layout and geometry

Use a 4px spacing base with 4, 8, 12, 16, 24, and 32px steps. Page gutters and
inspector padding are 16px. Related controls have 8px gaps. Standard controls
are 36px high; compact and large variants are 32px and 40px. Monitor Allow/Block
actions use the shared `icon-compact` button size, 24px wide and 32px high, with
16px Check/Ban icons and a 4px gap. Their centers are 28px apart on desktop.
Monitor rows use 3px vertical padding, keeping instance rows at 44px and
two-line destination/service rows at 45px on desktop. Coarse-pointer targets
remain at least 44px. Rows have a 44px minimum and grow for wrapped text.
Controls use 5px radii, small marks 4px, and overlays 8px. Ordinary rows and
panels are flat.

Page headers put the title on the left and a wrapping, right-aligned
`header-actions` group on the right. The compact Status indicator appears beside
page actions. Its icon summarizes rule application and the gateway services: a
green check when the current policy is applied and every service runs, an amber
spinner while changes apply, an amber alert for stale, transitional, stopped or
unreadable states, and a red alert for failures or unconfirmed changes. Clicking
it opens a card with three rows: Rules, Gateway (the gateway service and its
enforcement service), and Suricata (Suricata and its log rotation). Each row
shows its own icon colored by state: green when fine, amber while waiting,
stale, stopped or unreadable, red on failure, and grey while checking. A row
with problems lists them as bullets beneath it, such as "Log rotation: Stopped";
an unreadable gateway is one bullet. Rows without problems reserve no space, and
the card is only as wide as its longest line, wrapping bullets at 288px. A row's
tooltip describes what it covers. "Updated" with the relative check time
follows. The indicator uses 12px / 18px text and the standard 36px control
height.

UI text is impersonal. Labels, layout, and context carry meaning: help text
appears only where a field or control cannot explain itself, in one short
sentence, and limits and internals belong in Architecture rather than on the
page. Pending, stale, and failed updates use plain descriptions and distinct
visual states. The catalog includes status examples with failed log rotation.
Update timing belongs to Architecture.

The app shell fills the viewport and the page itself never scrolls. Navigation
and the page header stay in place; content scrolls inside its pane. Desktop
navigation defaults to 188px and resizes from 176px to 280px. The inspector
defaults to 30% of the split view, resizes from 320px to half of it, and scrolls
independently of the list. Resizable pane borders have no handle: hovering
lightens the 1px border to the input color under a resize cursor, and keyboard
focus shows a 2px focus-ring line. Arrow keys resize in 16px steps, Home or a
double-click restores the default, and widths persist per browser. Below 900px
the inspector opens as a bottom sheet when a row is selected; it closes with its
Close button, Escape, or the backdrop, keeps the selection, and returns focus to
the row. Below 700px navigation becomes a wrapping top row, setting fields
stack, and Monitor rows keep actions beside the name with measurements on a
second line. Coarse-pointer controls provide at least 44px interaction targets.

Sign out is the last section of Settings. Activating it opens a confirmation
dialog. Cancel receives initial focus. The dialog warns that unsaved changes
will be lost, prevents duplicate requests, and shows failed sign-out inside the
dialog.

Leaving Settings with unsaved changes asks first. In-app navigation opens a
"Discard unsaved changes?" dialog where Keep editing receives initial focus;
closing or reloading the tab shows the browser's own prompt. While there are
unsaved changes, Discard changes sits beside Save changes; it opens the same
dialog and, once confirmed, loads the saved settings. Refresh keeps unsaved
changes. A save refused because the settings were changed elsewhere keeps them
too, and its error says to discard them to load the saved settings.

Monitor lists instances, destinations, and services above the timeline. The
desktop list scrolls within 55dvh and supports keyboard scrolling; narrow
layouts scroll the list with the rest of the Monitor pane. Selection updates
totals, the chart, and inspector, and the selected row shows its selected state.
When the service roster is truncated, label sums as covering visible services;
selection totals and timeline cover the complete selection. Below the timeline,
an Unregistered drops section appears when the period has any: a field-help line
with the client-interface and upstream packet counts, then compact rows of the
newest samples with time, source → destination in monospace, and service and
side in muted text.

Refreshes preserve selection and editor drafts. New scope totals and new-period
lists remain loading or unavailable until matching measurements arrive. A failed
refresh marks retained measurements as not updated. Refresh ownership and
cancellation are documented in
[Architecture](docs/ARCHITECTURE.md#runtime-boundaries).

`TrafficPeriodPicker` uses the shared compact choice control and keeps the
selected period visible beside the timeline.

## Shared controls and forms

Pages compose owned controls under `src/lib/components/ui/`. Use shared variants
for dimensions, colors, hover, focus, pressed and disabled states. Keep
accessible names, Bits UI keyboard behavior, and focus management.

Dialogs, popovers, menus, selects, and tooltips fade and zoom over 100ms as they
open and close, using `tw-animate-css` classes. Bits UI reports state through
`data-state`, so `app.css` maps the `data-open` and `data-closed` variants to
it. Reduced motion turns all animation and transitions off. Modal backdrops dim
the page by 40% with a 1px blur.

`field-group` puts a 4px gap between label, control, and helper/error text.
Supporting messages use 12px / 18px. Responsive form grids stack narrow fields
before labels or inputs overflow.

Shared field labels use a 20px line height. Settings groups related fields into
sections with 32px between sections and a divider below each section header.
Headers have 16px bottom padding; setting rows leave 16px above their fields.
Other content under a header sits in `settings-section-body`, which leaves the
same 16px and puts 8px between its lines. Labels and helper text have a 4px gap.
Keep the layout flat.

Active navigation, filters, tabs, and selected rows share `--accent` /
`--accent-foreground`. Use the `selected` button variant for active filters;
`secondary` remains an action variant. Active navigation has no colored left
stripe. The blue focus outline identifies keyboard focus separately. The
Requests navigation item shows the number of requests waiting for review in a
neutral count (foreground at 12% opacity behind foreground numerals), hidden
when zero or unavailable. Requests filters show their counts in muted numerals.

`Choice` fills form fields through `fullWidth`; compact toolbar choices use a
stable width. Popups match the trigger width and align to its start edge. Long
labels truncate visually while preserving their full accessible label.

RuleEditor shares creation and editing fields. Preserve drafts on conflicts and
failed saves and distinguish saving, confirmed success, and errors. Unsaved
drafts prevent accidental Escape/outside dismissal. Cancellation is explicit.
Requests and Monitor use this same editor. Its Applies to choice lists Any, each
instance, Address in an instance, and each rule set with the rule set icon.
Address in an instance reveals an address field with field help explaining that
the address keeps its instance's rules and moves to an instance registered for
it. A rule set shows one line below the choice stating how many instances use
it.

Settings provides Add and Edit instance actions through one dialog. Validation
errors remain in the dialog with field descriptions. Failed saves preserve the
draft, and unsaved edits prevent Escape/outside dismissal. Cancel explicitly
discards the draft.

History uses compact Changes, Traffic events, and System status views. A change
shows its action, then what it was about, then who made it. Expandable What
changed details display each field as label and before → after value, followed
by the resulting revision and the recorded identifier; a change title names its
rule only when that is not the entry's own rule.

Rules and Requests use compact instance groups with a contextual inspector.
Rules filters place High priority before Temporary and keep Disabled and Expired
separate. Global rules appear under Any; address rules are grouped by range,
named "192.0.2.70 in example-network". Rule rows have no inline enable toggle;
the inspector contains labeled controls. Requests uses Needs review, Applying,
and Failed filters with muted counts. A DNS row places the question on its first
line, with the root question labeled DNS root, and its latest query type, such
as `A` or `HTTPS`, below it; the inspector labels it Query type. A connection
row places the IP above its direction and service. Keep both row types aligned
with the same selection fill and Allow/Block pair. Long names wrap without
moving the actions outside the row. The inspector lists Recent clients with
their time and, for an address that is not exactly the instance's, an outline
Allow for this address button. Needs review starts with an Unregistered hosts
group: each row shows the address in monospace, its sampled drop count and
newest looked-up name, and an outline Register button in place of the
Allow/Block pair. Register opens a dialog choosing New instance or Add to an
instance, with name and address fields, and states how many rules for exactly
that address move to the instance.

Rules lists the rule sets attached to a group below the group's own rules, each
as one row: a toggle labeled From and the set's name with its rule count, an
Edit action that opens the set, and Detach. The toggle expands the set's rules
as indented rows, which select and inspect like other rules; while a filter is
active the matching rules stay expanded and sets without a match are hidden.
Sets attached to every instance appear under Any. An instance group's heading
has a menu with Attach rule set, listing the sets not yet attached, and Save as
rule set when the instance has permanent rules. Save as rule set asks for a name
and states how many rules move, that they rank below the rules the instance
keeps, and, when the instance has other rule sets, that they no longer rank
above those.

Rule sets lists each set as a group of its rules with Add rule below them and
Edit and Delete on each row. The group heading shows the set's name, its rule
count, and Every instance, the number of instances, or Not attached. Selecting a
set opens its inspector: Attached to, listing each instance or Any with a remove
action; an Attach to choice with no default, listing instances before Any; and
Export, Rename, and Delete. Deleting a set asks for confirmation that names the
instances its rules stop applying to. The page header has Import and Create rule
set. Import shows the file's rule count and an editable name, and creates an
unattached set.

## Charts, data and states

Charts use the shared font, foreground, border, and series roles. Respect
reduced motion and provide an accessible summary.

Chart loading is announced through a status message. Failed charts show "Chart
is unavailable. Reload the page to try again."

Traffic totals, pills, axes, inspector values, and tooltips use decimal
`KB / MB / GB / TB / PB / EB`, where 1 KB is 1,000 bytes. Values below 1,000
bytes use B. Scaled values truncate to two fractional digits. Storage sizes
retain the separate binary `KiB / MiB / GiB` formatter.

Storage fields show their value in the shortest exact unit and use helper text
to distinguish storage units from traffic units.

The timeline has a split baseline: orange Sent above zero and blue Received
below. Both halves use the same symmetric byte scale. Signed coordinates are
only a rendering convention; axis labels, totals and tooltips show positive
amounts with directional labels. Bars have a 2px minimum and 10px maximum width
so isolated samples stay visible in long ranges; their heights remain
proportional to measured bytes. Faint vertical guides provide context. No
minimum bar height or synthetic samples are added.

Monitor rows carry a bar under their traffic pills on a fixed-width track. Its
length is the row's share of its instance's total, so the instance row fills the
track and no row is longer than its parent. The fill grows from the track's
right end, beside the decision controls. It splits Received (blue, left) and
Sent (orange, right) by each direction's proportion of the row total, in the
pills' order, with a 2px gap. A row with any traffic shows at least a 6px fill;
a row with none shows only the track.

Charts approximate pixel positions; formatted values use the truncation
described above. Tooltips retain original decimal byte counts. Missing
measurements are gaps rather than zeros. Distinguish loading, empty, failed,
stale and partial-coverage states.

Use Check for Allow and Ban for Block in Monitor, Rules, Requests, and the
catalog. Keep accessible Allow/Block names alongside green/red status colors.
Monitor rows and inspector rule rows show the pair as Ban then Check, 24px
square buttons on one grey fill, with the current decision in the icon colors:
Check green for allowed, Ban red for blocked, Ban amber while waiting for
review, and both grey when services differ or the outcome depends on DNS. A pair
without measured traffic is dimmed. Its accessible name states the decision in
words; it has no hover tooltip.

The Settings-owned catch-all recedes like an inactive rule and offers no Edit,
Disable, Delete, or decision buttons: the Rules list and inspector point to
Settings, and the Monitor inspector shows its pair as non-interactive icons
whose tooltip names Settings. Rule action errors stay beside the inspector
actions until the next action or selection, with the server's field messages.

The override warning in the rule editor is a bordered note in the pending color
with a warning icon at the top of the form, so it stays in view while Action and
High priority change. Rules another rule overrides recede like inactive rules
and show "No effect" as their state line.

Rule text is `peer · service`, for example `198.51.100.20 · TCP/UDP 18081` or
`example.com · TCP 443`; an unrestricted service is omitted. Hostnames and
addresses wrap after a dot. Icons replace words for direction (→ outgoing, ←
incoming, ⇄ both), Temporary (clock), High priority (double chevron), and DNS
dependence (globe); each has a tooltip and screen-reader text. The built-in
values Any and Gateway appear in a grey box in rule text, History values,
Monitor rows, and editor options, so they stand apart from names people enter.
Date fields show the chosen day and time and open a calendar with times in
15-minute steps beside it; the editor offers them only under Custom lifetime. A
filled date field shows a clear button; an empty Starts reads Now and an empty
Ends reads No end. Picking only a time on an empty field takes the next time it
comes around. The rule editor keeps High priority and Enabled as switches beside
its title. Its fields read in the order of a rule: Action and Direction, then
Instance, Peer, and Service, each with its value beside its dropdown, then
Lifetime. Hostname and domain rules show a Limit to networks switch under Peer,
and the network list only while it is on. Scrollable panes use a thin scrollbar
in `#3a3a3a`. Times read "just now", "N min ago", or "in N min" within an hour,
"N hr ago" or "in N hr" within a day, then "Yesterday", "Tomorrow", "N days
ago", or "in N days" through six calendar days. From seven days they show the
month and day with the time this year, and the month, day, and year otherwise.
The full time is in a tooltip. Chart axes and chart tooltips keep their own
scale formats. Pending application uses the waiting state rather than a success
icon.

## Catalog and verification

Run `bun run catalog` to open the development catalog. The catalog includes
semantic color pairs with measured contrast, typography, spacing, geometry, the
brand mark, state matrices, fields, working overlays, ECharts and a Monitor
composition. Fixtures are labeled. Production pages use configured data and
explicit empty/unavailable states.

Verify representative screens at 1280px and 375px, long names, overflow,
keyboard focus and dismissal, measured alignment, font loading, and contrast.
Run formatting, lint, type checks, tests and the production build in an isolated
development environment. Check selection preservation, empty states, editor
draft protection and focus restoration after editor dismissal when changing
shared components. The Allow editor must open for the selected service.
