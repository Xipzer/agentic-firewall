package afp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

func (e Envelope) validate(want Type) error {
	var errs []error
	if e.AFP != Version {
		errs = append(errs, fmt.Errorf("afp version %q, want %q", e.AFP, Version))
	}
	if e.Type != want {
		errs = append(errs, fmt.Errorf("type %q, want %q", e.Type, want))
	}
	if e.ID == "" {
		errs = append(errs, errors.New("missing id"))
	}
	if e.TS.IsZero() {
		errs = append(errs, errors.New("missing ts"))
	}
	switch e.Source.Tier {
	case TierDataplane, TierFast, TierMedium, TierSlow, TierHuman, TierPeer:
	default:
		errs = append(errs, fmt.Errorf("bad source tier %q", e.Source.Tier))
	}
	if e.Source.Agent == "" {
		errs = append(errs, errors.New("missing source agent"))
	}
	return errors.Join(errs...)
}

func (s Subject) validate() error {
	switch s.Kind {
	case SubjectHost, SubjectPrefix:
		_, err := s.Prefix()
		return err
	case SubjectFlow:
		if s.Value == "" {
			return errors.New("empty flow subject")
		}
		return nil
	}
	return fmt.Errorf("bad subject kind %q", s.Kind)
}

func validEndpoint(s string) bool {
	if _, err := netip.ParseAddrPort(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func (o *Observation) Validate() error {
	errs := []error{o.Envelope.validate(TypeObservation)}
	if o.Flow == nil && len(o.Context) == 0 {
		errs = append(errs, errors.New("observation needs flow or context"))
	}
	if f := o.Flow; f != nil {
		if !validEndpoint(f.Src) || !validEndpoint(f.Dst) {
			errs = append(errs, fmt.Errorf("bad flow endpoints %q -> %q", f.Src, f.Dst))
		}
		if f.Proto == "" {
			errs = append(errs, errors.New("missing flow proto"))
		}
	}
	return errors.Join(errs...)
}

func (v *Verdict) Validate() error {
	errs := []error{v.Envelope.validate(TypeVerdict), v.Subject.validate()}
	if !v.Action.Valid() {
		errs = append(errs, fmt.Errorf("bad action %q", v.Action))
	}
	if v.Action != ActionAllow {
		if _, err := ParseTTL(v.TTL); err != nil {
			errs = append(errs, fmt.Errorf("non-allow verdict needs ttl: %w", err))
		}
	}
	if v.Confidence < 0 || v.Confidence > 1 {
		errs = append(errs, fmt.Errorf("confidence %v out of [0,1]", v.Confidence))
	}
	if strings.TrimSpace(v.Reason) == "" {
		errs = append(errs, errors.New("missing reason"))
	}
	if v.Mode != "" && v.Mode != "enforce" && v.Mode != "shadow" {
		errs = append(errs, fmt.Errorf("bad mode %q", v.Mode))
	}
	if v.Hops < 0 {
		errs = append(errs, errors.New("negative hops"))
	}
	return errors.Join(errs...)
}

func (e *Escalation) Validate() error {
	errs := []error{e.Envelope.validate(TypeEscalation), e.Subject.validate()}
	if len(e.Refs) == 0 {
		errs = append(errs, errors.New("escalation needs refs"))
	}
	if strings.TrimSpace(e.Question) == "" {
		errs = append(errs, errors.New("missing question"))
	}
	switch e.Priority {
	case "low", "normal", "high", "critical":
	default:
		errs = append(errs, fmt.Errorf("bad priority %q", e.Priority))
	}
	if e.Deadline != "" {
		if _, err := ParseTTL(e.Deadline); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *Rule) Validate() error {
	errs := []error{r.Envelope.validate(TypeRule)}
	if len(r.Match) == 0 {
		errs = append(errs, errors.New("rule needs a match"))
	}
	if !r.Action.Valid() {
		errs = append(errs, fmt.Errorf("bad action %q", r.Action))
	}
	if _, err := ParseTTL(r.TTL); err != nil {
		errs = append(errs, fmt.Errorf("rule needs ttl: %w", err))
	}
	if r.Provenance.Incident == "" && r.Provenance.Explanation == "" && len(r.Provenance.Verdicts) == 0 {
		errs = append(errs, errors.New("rule needs provenance"))
	}
	return errors.Join(errs...)
}

func (x *Explanation) Validate() error {
	errs := []error{x.Envelope.validate(TypeExplanation)}
	if x.About == "" {
		errs = append(errs, errors.New("missing about"))
	}
	if strings.TrimSpace(x.Summary) == "" {
		errs = append(errs, errors.New("missing summary"))
	}
	if x.Confidence < 0 || x.Confidence > 1 {
		errs = append(errs, fmt.Errorf("confidence %v out of [0,1]", x.Confidence))
	}
	return errors.Join(errs...)
}
