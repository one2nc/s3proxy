package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/pquerna/otp/totp"
)

const DEFAULT = "*"

type Rule struct {
	Emails         []string `json:"emails"`
	WhitelistedIPs []string `json:"whitelisted_ips"`
	Secrets        []string `json:"secrets"`
}

type Rules map[string]map[string]Rule

type RulesConf struct {
	Rules Rules `json:"rules"`
}

type TsAuth struct {
	rules Rules
}

type Payload struct {
	Path     string
	Key      string
	SourceIP string
	Email    string
	Otp      string
}

func NewPayload(p, k, s, e, o string) *Payload {
	return &Payload{p, k, s, e, o}
}

func (t *TsAuth) Verify(p *Payload) (bool, error) {
	if p == nil {
		return true, nil
	}

	check := func(rules map[string]Rule, p *Payload) (bool, error) {
		rule, ok := rules[p.Key]
		if !ok {
			rule, ok = rules[DEFAULT]
		}
		if !ok {
			return false, fmt.Errorf("rule is not configured for action %v", p.Key)
		}

		if len(rule.WhitelistedIPs) == 0 && len(rule.Emails) == 0 && len(rule.Secrets) == 0 {
			return true, nil
		}

		// If Email and otp is passed, check from pritunl config
		if p.Email != "" && p.Otp != "" && len(rule.Emails) > 0 {
			for _, e := range rule.Emails {
				if e == p.Email {
					if !IsValid(p.Email, p.Otp) {
						return false, errors.New("invalid OTP")
					}

					return true, nil
				}
			}
		}

		// If otp is passed without email, check in secrets
		if p.Email == "" && p.Otp != "" && len(rule.Secrets) > 0 {
			for _, s := range rule.Secrets {
				if totp.Validate(p.Otp, s) {
					return true, nil
				}
			}
		}

		if p.SourceIP != "" {
			for _, w := range rule.WhitelistedIPs {
				if w == p.SourceIP {
					return true, nil
				}
			}
		}

		return false, errors.New(http.StatusText(http.StatusUnauthorized))
	}

	rules, ok := t.rules[p.Path]
	defaultRules, dOk := t.rules[DEFAULT]
	var valid bool

	if ok {
		valid, _ = check(rules, p)
	}

	if valid {
		return valid, nil
	}

	if !valid && dOk {
		return check(defaultRules, p)
	}

	return false, errors.New(http.StatusText(http.StatusUnauthorized))
}

func New(c *RulesConf) *TsAuth {
	if c == nil {
		c = &RulesConf{}
	}

	if c.Rules == nil {
		c.Rules = Rules{}
	}

	return &TsAuth{rules: c.Rules}
}
