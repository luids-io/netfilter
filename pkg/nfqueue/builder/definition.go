// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package builder

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

//PluginDef is used for construct plugins
type PluginDef struct {
	// Name must exist and be unique in databases for its correct operation
	Name string `json:"name"`
	// Class defines the class
	Class string `json:"class"`
	// Disabled
	Disabled bool `json:"disabled"`
	// Services is a map of services used by plugin
	Services map[string]string `json:"services,omitempty"`
	// Actions is a list of actions
	Actions []ActionDef `json:"actions,omitempty"`
	// Opts allow optional fields
	Opts map[string]interface{} `json:"opts,omitempty"`
}

// ActionDef is used for construct actions
type ActionDef struct {
	// Name must exist and be unique in databases for its correct operation
	Name string `json:"name"`
	// Class defines the class
	Class string `json:"class"`
	// Disabled
	Disabled bool `json:"disabled"`
	// Services is a map of services used by plugin
	Services map[string]string `json:"services,omitempty"`
	// Rules is a list of ruleset definitions
	Rules []RuleItemDef `json:"rules,omitempty"`
	// OnError stores on error verdict
	OnError string `json:"onerror,omitempty"`
	// Opts allow optional fields
	Opts map[string]interface{} `json:"opts,omitempty"`
}

// RuleItemDef defines a set of rules
type RuleItemDef struct {
	// When defines condition
	When string `json:"when"`
	// Rule stores definition
	Rule RuleDef `json:"rule"`
}

// RuleDef stores information about rules
type RuleDef struct {
	// Merge option
	Merge bool `json:"merge,omitempty"`
	// Event stores event level
	Event string `json:"event,omitempty"`
	// Log enable logging in action
	Log bool `json:"log"`
	// Verdict stores verdict to firewall processors
	Verdict string `json:"verdict,omitempty"`
}

// PluginDefsFromFile creates a slice of PluginDef from a file in json format.
func PluginDefsFromFile(path string) ([]PluginDef, error) {
	var plugins []PluginDef
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	byteValue, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(byteValue, &plugins)
	if err != nil {
		return nil, err
	}
	return plugins, nil
}
