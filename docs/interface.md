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

Built to be read at a glance. State is carried by colour, size and position; words are short; detail is one tap away and never in the way.

| View | The one question | What you see |
|---|---|---|
| **Now** | Is everything all right? | One big coloured status. Three numbers: blocked, slowed, watched. A strip of the last hour, one bar a minute. Cards for what needs you, each with one button. A card per restricted source with a bar that drains as its block runs out |
| **Activity** | What has afw decided? | A timeline. One line per attacker: a picture for the kind of attack, the address, and three dots for how far it was escalated |
| **A source** (opens over any view) | What is this address? | Its state and time left, the attack as steps with arrows, each piece of evidence as a strength bar (striped when it could be faked), then its history |
| **Coverage** | What can afw not do? | A map: one square per attack type, green handled, amber partly, red a gap, with a count where it has been seen here. Bars for your most targeted services |
| **System** | Is afw itself healthy? | A light per part. Switches for blocking and emergency mode, and the off switch |

Left out on purpose: settings (the config file is the one place for those) and the test momentum report (it describes the code, not this machine).

## Design rules it follows

- **One look, one answer.** Every view opens with the thing that answers its question, large.
- **Pictures before words.** Each attack type has one picture, used everywhere, so it is recognised before it is read.
- **Colour means one thing.** Red is blocked or needs action, amber is slowed or worth a check, green is fine, grey is watching or off.
- **Short labels, detail on tap.** Long explanations sit behind "Details"; nothing is a wall of text.
- **Show time as a shape.** A draining bar, not "ends in 35 minutes".
- **Only stated facts.** No empty tiles; an empty section says so in one line.
- **Risky actions take two presses, in place.** The off switch also needs a typed word.
- **Works on a phone**: four items in a bottom bar, 44 px targets, no sideways scrolling.
- **Keeps your place.** Refreshes never move focus or scroll; Back closes a panel and returns you to the same row.
- **Readable**: contrast of at least 4.5:1, one focus ring, a label on every control and picture, reduced motion respected, light and dark.

## Why it is safe to run on a firewall

- Off by default, loopback by default.
- Every data request needs the token; the page checks the Host header (stops DNS rebinding) and refuses cross-site requests.
- Actions exist only on loopback. A LAN listener is read-only, and the config refuses anything else.
- A strict content policy: no inline script, nothing from other origins, cannot be framed.
- Much of what it shows was written by attackers, so the script only ever sets text. A test fails the build if `innerHTML` or anything like it appears.
- The adviser's words never reach it at all.
