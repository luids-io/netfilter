// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. See LICENSE.

package nfqueue

import (
	"fmt"
	"strings"
)

// Verdict represents the actions that a firewall can do
type Verdict int

// Action types
const (
	Default Verdict = iota
	Accept
	Drop
)

func (v Verdict) String() string {
	switch v {
	case Default:
		return "default"
	case Accept:
		return "accept"
	case Drop:
		return "drop"
	default:
		return fmt.Sprintf("unknown(%v)", int(v))
	}
}

// ToVerdict returns action from a string
func ToVerdict(s string) (Verdict, error) {
	switch strings.ToLower(s) {
	case "":
		return Default, nil
	case "default":
		return Default, nil
	case "accept":
		return Accept, nil
	case "drop":
		return Drop, nil
	default:
		return Verdict(-1), fmt.Errorf("invalid verdict %s", s)
	}
}
