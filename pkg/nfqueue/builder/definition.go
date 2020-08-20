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
	// Args is a list of args for plugin
	Args []string `json:"args,omitempty"`
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
	// Policy defines ruleset
	Policy *RuleSetDef `json:"policy,omitempty"`
	// Args is a list of args for action
	Args []string `json:"args,omitempty"`
	// Opts allow optional fields
	Opts map[string]interface{} `json:"opts,omitempty"`
}

// RuleSetDef defines a set of rules
type RuleSetDef struct {
	// Positive stores actions to do when positive matching
	Positive *RuleDef `json:"positive,omitempty"`
	// Negative stores actions to do when negative matching
	Negative *RuleDef `json:"negative,omitempty"`
	// Merge stores merge option
	Merge bool `json:"merge,omitempty"`
	// OnError stores on error verdict
	OnError string `json:"onerror,omitempty"`
}

// RuleDef stores information about rules
type RuleDef struct {
	// Event stores event level
	Event string `json:"event,omitempty"`
	// Tags used when the rule is applied
	Tags []string `json:"tags,omitempty"`
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
