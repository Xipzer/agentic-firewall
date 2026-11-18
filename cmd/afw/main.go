// Command afw is the agentic-firewall single-node daemon and CLI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/daemon"
	"github.com/Xipzer/agentic-firewall/internal/enforce"
)

var version = "0.1.0-dev"

const usage = `afw: agentic firewall (AFP v0.1)

Usage:
  afw run      [-c config.yaml]           run the daemon (needs root or CAP_NET_ADMIN)
  afw status   [-c config.yaml]           show mode, protected subjects, counters and feeds
  afw confirm  [-c config.yaml]           keep enforcing after the probation window
  afw mode     shadow|enforce [-c ...]    switch mode live
  afw unblock  <ip|cidr> [-grace 1h]      lift an action and hold the subject in grace
  afw breakglass on|off [-c ...]          emergency lane: trusted first, newcomers capped
  afw panic    [-c config.yaml]           remove every afw rule from the kernel now
  afw replay   <observations.jsonl> [-c]  run recorded traffic through the fast tier offline
  afw validate <file.json|jsonl>...       check AFP messages against the v0.1 rules
  afw ruleset  [-c config.yaml]           print the nftables ruleset afw would install
  afw version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", defaultConfig(), "config file")
	grace := fs.Duration("grace", time.Hour, "unblock: how long to leave the subject alone")
	positional := parseInterleaved(fs, args)
	var err error
	switch cmd {
	case "run":
		err = run(*cfgPath)
	case "status":
		err = control(*cfgPath, http.MethodGet, "/status", nil)
	case "confirm":
		err = control(*cfgPath, http.MethodPost, "/confirm", nil)
	case "mode":
		err = need(positional, 1, func() error {
			return control(*cfgPath, http.MethodPost, "/mode", url.Values{"m": {positional[0]}})
		})
	case "unblock":
		err = need(positional, 1, func() error {
			return control(*cfgPath, http.MethodPost, "/unblock", url.Values{"subject": {positional[0]}, "grace": {grace.String()}})
		})
	case "breakglass":
		err = need(positional, 1, func() error {
			return control(*cfgPath, http.MethodPost, "/breakglass", url.Values{"state": {positional[0]}})
		})
	case "panic":
		err = panicCmd(*cfgPath)
	case "replay":
		err = need(positional, 1, func() error { return replay(*cfgPath, positional[0]) })
	case "validate":
		err = need(positional, 1, func() error { return validate(positional) })
	case "ruleset":
		err = ruleset(*cfgPath)
	case "version":
		fmt.Println("afw", version, "afp", afp.Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "afw:", err)
		os.Exit(1)
	}
}

// parseInterleaved lets flags appear before or after positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			return pos
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func need(pos []string, n int, f func() error) error {
	if len(pos) < n {
		return errors.New("missing argument; see afw help")
	}
	return f()
}

func defaultConfig() string {
	if _, err := os.Stat("/etc/afw/afw.yaml"); err == nil {
		return "/etc/afw/afw.yaml"
	}
	return ""
}

func load(path string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

func run(cfgPath string) error {
	cfg, err := load(cfgPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	d := daemon.New(cfg, log)
	if err := d.Init(); err != nil {
		return err
	}
	stopSensors := startSensors(ctx, d, log)
	defer stopSensors()
	go func() {
		if err := d.ServeControl(ctx, cfg.ControlSocket, stop); err != nil {
			log.Error("control socket", "err", err)
		}
	}()
	log.Info("afw starting", "version", version, "node", cfg.Node, "role", cfg.Role, "mode", cfg.Mode)
	return d.Run(ctx)
}

func client(cfgPath string) (*http.Client, error) {
	cfg, err := load(cfgPath)
	if err != nil {
		return nil, err
	}
	sock := cfg.ControlSocket
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}, nil
}

func control(cfgPath, method, path string, q url.Values) error {
	c, err := client(cfgPath)
	if err != nil {
		return err
	}
	u := "http://afw" + path
	if q != nil {
		u += "?" + q.Encode()
	}
	req, _ := http.NewRequest(method, u, nil)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("is afw running? %w", err)
	}
	defer resp.Body.Close()
	var v any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

// panicCmd asks the daemon to tear down, then deletes the table directly in
// case the daemon is hung or gone. Either path alone is enough.
func panicCmd(cfgPath string) error {
	cfg, err := load(cfgPath)
	if err != nil {
		return err
	}
	viaDaemon := control(cfgPath, http.MethodPost, "/panic", nil)
	out, direct := exec.Command(cfg.NFT.Binary, "delete", "table", "inet", cfg.NFT.Table).CombinedOutput()
	if viaDaemon != nil && direct != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("daemon: %v; nft: %v %s", viaDaemon, direct, out)
	}
	fmt.Println("afw table removed: nothing from afw is filtering traffic now")
	return nil
}

func replay(cfgPath, file string) error {
	cfg, err := load(cfgPath)
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	res, err := daemon.Replay(cfg, f, os.Stdout, log, config.Discovered{})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "replayed %d events: %v\n", res.Events, res.Verdicts)
	return nil
}

func validate(files []string) error {
	bad := 0
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		lines := [][]byte{b}
		if strings.HasSuffix(name, ".jsonl") {
			lines = nil
			for _, l := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(l) != "" {
					lines = append(lines, []byte(l))
				}
			}
		}
		for i, l := range lines {
			var env afp.Envelope
			if json.Unmarshal(l, &env) == nil && env.Type == "event" {
				continue // journal housekeeping lines are not AFP messages
			}
			if _, err := afp.Decode(l); err != nil {
				bad++
				fmt.Printf("%s:%d: %v\n", filepath.Base(name), i+1, err)
			}
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d invalid message(s)", bad)
	}
	fmt.Println("ok")
	return nil
}

func ruleset(cfgPath string) error {
	cfg, err := load(cfgPath)
	if err != nil {
		return err
	}
	n := enforce.NewNFT(cfg.NFT.Binary, cfg.NFT.Table, cfg.NFT.LogGroup, cfg.NFT.LogRate, cfg.Policy.ThrottleRate)
	n.SensitivePorts = cfg.SensitivePorts
	prot := cfg.ProtectedPrefixes()
	if cfg.AutoProtectEnabled() {
		prot = append(prot, config.Discover().All()...)
	}
	fmt.Print(n.Ruleset(prot, cfg.Mode != "enforce"))
	return nil
}
