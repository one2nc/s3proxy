package auth

import (
	"errors"
	"fmt"
	"net/http"
)

const DEFAULT = "*"

type Rule struct {
	Emails         []string `json:"emails"`
	WhitelistedIPs []string `json:"whitelisted_ips"`
}

type Rules map[string]map[string]Rule

type RulesConf struct {
	Rules Rules `json:"rules"`
}

type TsAuth struct {
	rules Rules
}

type payload struct {
	path             string
	key              string
	sourceIP         string
	email            string
	otp              string
	otpRequired      bool
	allowDefaultPath bool
}

func NewPayload(p, k, s, e, o string, or, a bool) *payload {
	return &payload{p, k, s, e, o, or, a}
}

func (t *TsAuth) Verify(p *payload) (bool, error) {
	if p == nil {
		return false, errors.New("payload is nil")
	}

	check := func(rules map[string]Rule, p *payload) (bool, error) {
		rule, ok := rules[p.key]
		if !ok {
			rule, ok = rules[DEFAULT]
		}
		if !ok {
			return false, fmt.Errorf("rule is not configured for action %v", p.key)
		}

		if len(rule.WhitelistedIPs) == 0 && len(rule.Emails) == 0 {
			return false, errors.New("no rules specified in configuration, contact service administrator")
		}

		validateOtp := func(email, otp string) (bool, error) {
			if !IsValid(p.email, p.otp) {
				return false, errors.New("invalid OTP")
			}

			return true, nil
		}

		if p.sourceIP != "" {
			for _, w := range rule.WhitelistedIPs {
				if w == p.sourceIP {
					if p.otpRequired {
						return validateOtp(p.email, p.otp)
					}
					return true, nil
				}
			}
		}

		// If email and otp is passed, check from pritunl config
		if p.email != "" && p.otp != "" && len(rule.Emails) > 0 {
			if len(rule.Emails) == 1 && rule.Emails[0] == DEFAULT {
				return validateOtp(p.email, p.otp)
			}

			for _, e := range rule.Emails {
				if e == p.email {
					return validateOtp(p.email, p.otp)
				}
			}
		}

		return false, errors.New(http.StatusText(http.StatusUnauthorized))
	}

	rules, ok := t.rules[p.path]
	defaultRules, dOk := t.rules[DEFAULT]
	var valid bool

	if !ok && dOk && p.allowDefaultPath {
		return check(defaultRules, p)
	}

	if ok {
		valid, _ = check(rules, p)
	}

	if valid {
		return valid, nil
	}

	if ok && dOk {
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
