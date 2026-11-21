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

| View | The question it answers | What is there |
|---|---|---|
| **Now** | Is everything all right, and does anything need me? | The mode in one sentence. "Needs you": only things a person must decide (confirm blocking, a break-in chain, a device inside the network misbehaving, emergency mode, a suspended adviser, a broken part). What is restricted right now, why, when it ends, and Unblock. One sentence for the last 24 hours |
| **Activity** | What has afw decided? | Every decision, newest first, one row per attacker showing where it ended up. Filters and a search by address |
| **A source** (opens over any view) | What do we know about this address? | Its state, why (each piece of evidence, marked if it could be faked), everything it has done, its history, Unblock |
| **Coverage** | What can afw not do? | Attacks seen here. The attack types afw cannot fully see or stop, listed on purpose. Which of your services are being targeted |
| **System** | Is afw itself healthy? | Sensors, firewall counters, decoys, adviser, linked nodes, threat lists, the never-blocked list. The controls: blocking on or off, emergency mode, the off switch |

Left out on purpose: charts (nothing here is better read as a chart than as a sentence or a list), settings (the config file is the one place for those), and the test momentum report (it describes the code, not this machine).

## Design rules it follows

Taken from audits of earlier software on this machine:

- **Lead with what needs the person.** Everything else is below it.
- **Colour means something, and only one thing.** Red is blocked or needs action, amber is slowed or worth a check, green is fine, grey is watching.
- **Only stated facts.** No empty tiles or dashes; an empty section says what is empty and the way out.
- **Words a person would say.** "Password guessing", "ends in 8 min", "could be faked"; no class codes, no ISO dates.
- **Risky actions take two presses, in place.** The off switch also needs a typed word. Rare controls live on System, not on every page.
- **Works on a phone**: four items in a bottom bar, 44 px targets, no sideways scrolling.
- **Keeps your place.** Refreshes never move focus or scroll; Back closes a panel and returns you to the same row.
- **Readable**: contrast of at least 4.5:1, one focus ring, labels on every control, reduced motion respected, light and dark.

## Why it is safe to run on a firewall

- Off by default, loopback by default.
- Every data request needs the token; the page checks the Host header (stops DNS rebinding) and refuses cross-site requests.
- Actions exist only on loopback. A LAN listener is read-only, and the config refuses anything else.
- A strict content policy: no inline script, nothing from other origins, cannot be framed.
- Much of what it shows was written by attackers, so the script only ever sets text. A test fails the build if `innerHTML` or anything like it appears.
- The adviser's words never reach it at all.
