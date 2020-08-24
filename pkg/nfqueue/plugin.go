// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package nfqueue

import "github.com/google/gopacket"

// Plugin defines interface for packet processing plugins
type Plugin interface {
	// Name returns the name of the plugin instance
	Name() string
	// Class returns the class name of the plugin
	Class() string
	// Register add hooks to a the packet processing pipeline
	Register(hooks *Hooks)
	// Layers returns layers required by the plugin
	Layers() []gopacket.LayerType
	// CleanUp of the plugin
	CleanUp()
}

// Action defines interface for actions (used by plugins)
type Action interface {
	// Name returns the name of the action instance
	Name() string
	// Class returns the class name of the action
	Class() string
	// PluginClass returns the plugin class implemented by the action
	PluginClass() string
}
