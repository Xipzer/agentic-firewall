# Testing at home safely

Four stages. Each one can only fail open: if anything goes wrong, traffic flows as if afw were not there.

## 0. On any Linux laptop, no root

```sh
go test ./...          # unit tests: heuristics, rails, protocol, feeds, crosstalk
lab/run.sh             # real kernel in a throwaway network namespace (no sudo)
lab/rails.sh           # the full gate: all of the above with no internet, plus a check that no safety test was skipped
```

The lab creates a private network namespace, installs the real nftables ruleset, starts the real sensors and attacks itself: a port scan, an SSH brute force, a "protected" host misbehaving, an unblock, shadow mode, probation and panic. Nothing touches your real network.

To see the interface first, with simulated attacks and nothing touched: `go run ./cmd/afw demo`.

## 1. Shadow mode on the Pi

```sh
GOOS=linux GOARCH=arm64 go build -o afw ./cmd/afw     # or GOARCH=arm GOARM=7 for 32-bit Pi OS
scp afw pi:/usr/local/bin/ && scp configs/afw.example.yaml pi:/etc/afw/afw.yaml
scp deploy/afw.service pi:/etc/systemd/system/
ssh pi 'sudo systemctl enable --now afw && afw status'
```

`mode: shadow` installs observation rules only. Read `/var/log/afw/afw.jsonl` for a few days: every verdict has a plain-English explanation next to it. Anything flagged that should not be is a threshold to change (`heuristics:` in the config).

## 2. Enforce, on probation

```sh
sudo afw mode enforce        # disarms itself in 15 minutes...
sudo afw confirm             # ...unless you confirm you can still reach the Pi
```

Check from a second device that your normal use still works before confirming. Your SSH session's address is protected automatically.

## Decoys

Add a few ports that nothing on the box serves (`canary.ports` in the config). Anything that completes a connection to one is blocked within about a tenth of a second. From another machine, `nc <pi> 2323` should hang, and `afw status` should show the touch. Unblock yourself with `afw unblock <your-ip>`.

## 3. Gateway, then crosstalk

Set `role: gateway` only once host mode has been quiet. To run both layers, give each node `crosstalk.peers` entries for the other and the same key file (`openssl rand -hex 32`).

## If anything goes wrong

```sh
sudo afw unblock 203.0.113.7     # lift one subject, and leave it alone for an hour
sudo afw panic                    # remove every afw rule immediately
```

Every block also expires on its own (10 minutes on a first offence). Stopping the service leaves only those timed entries, which lapse.

## Tuning on your own traffic

Set `log.observations: all` for an hour to capture traffic, then try a config change offline:

```sh
afw replay /var/log/afw/afw.jsonl -c my-new.yaml > verdicts.jsonl
```
