# The interface

A small web page for a person to review afw and act on it. Three static files inside the afw binary, no build step, nothing loaded from anywhere else.

## Try it without installing anything

```sh
go run ./cmd/afw demo        # simulated traffic, no root, touches nothing
```

Open the address it prints.

## Turn it on

```yaml
ui:
  listen: 127.0.0.1:7844     # empty (the default) means off
```

Then `sudo afw ui` prints the address, which carries an access token. From another device, tunnel first: `ssh -L 7844:127.0.0.1:7844 <machine>`.

To let other devices on the network look without a tunnel, listen on a LAN address and set `read_only: true`. That page is unencrypted, so it can only show, never act.

## What is on each view, and why

Built to be read at a glance. It looks like a ruled ledger, not a stack of cards.

| View | The one question | What you see |
|---|---|---|
| **Now** | Is everything all right? | One large headline. Three numbers: blocked, slowed, watched. A strip of the last hour, one bar a minute. What needs you, each with one button. One line per restricted source, whose underline drains as its time runs out |
| **Activity** | What has afw decided? | One line per attacker: time, a square for how hard afw acted, the address, a pictogram and two words for the kind of attack |
| **A source** (opens over any view) | What is this address? | Its state and time left, the attack as a path with arrows, each piece of evidence with a bar for how much it counted (striped when it could be faked), then its history |
| **Coverage** | What can afw not do? | A headline count of gaps. One square per attack type: green handled, half-amber partly, red a gap, with a number where it has been seen here. Your most targeted services as bars |
| **System** | Is afw itself healthy? | One headline, one line per part, switches for blocking and emergency mode, and the off switch |

Left out on purpose: settings (the config file is the one place for those) and the test momentum report (it describes the code, not this machine).

## The visual system

- **One mark for state.** A small square whose fill is the severity: hollow is watching, half is slowed, solid is blocked. Hatched means "would have", in watch-only mode. It is used in every list, the headline, the filters and the map key, so it is learnt once.
- **One row grammar.** Every list is the same ruled row with columns that line up down the page (CSS subgrid).
- **Colour is state only.** Red, amber, green. Controls are ink on paper, in light and dark; there is no brand colour.
- **Pictograms name the kind of attack and nothing else.** They come from Phosphor Icons (MIT, see [NOTICE.md](NOTICE.md)), embedded as path data.
- **Short labels, detail on tap.** Risky actions take two presses in place; the off switch also needs a typed word.
- **Time is a shape.** A draining underline, not "ends in 35 minutes".
- Works on a phone, keeps your place on refresh and Back, 4.5:1 contrast, visible focus, reduced motion respected.

## What it refuses to look like

The first two versions looked machine-made. A test now fails the build if the stylesheet brings any of these back: a coloured stripe down one edge of a box, pill-shaped badges and soft rounded cards, spaced capital-letter labels, soft shadows and glows, frosted glass, or a stock purple or blue accent. Tinted icon chips, identical card grids and centred icon-in-a-dashed-box empty states are gone too. The checklist these came from is a public catalogue of AI design tells ([unslop-ui-skill TELLS.md](https://github.com/claudiusararu/unslop-ui-skill/blob/main/TELLS.md)); the colour-as-a-stripe pattern is called out there as one of the most reliable.

It leans on current CSS instead of decoration: `light-dark()` and OKLCH colours mixed with `color-mix()` in OKLab, cascade layers, subgrid rows, `:has()`, `@starting-style` for the panel, and `interpolate-size` for opening details.

## Why it is safe to run on a firewall

- Off by default, loopback by default.
- Every data request needs the token; the page checks the Host header (stops DNS rebinding) and refuses cross-site requests.
- Actions exist only on loopback. A LAN listener is read-only, and the config refuses anything else.
- A strict content policy: no inline script, nothing from other origins, cannot be framed.
- Much of what it shows was written by attackers, so the script only ever sets text. A test fails the build if `innerHTML` or anything like it appears.
- The adviser's words never reach it at all.
