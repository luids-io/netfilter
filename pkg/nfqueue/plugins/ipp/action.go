// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package ipp

import "github.com/luids-io/netfilter/pkg/nfqueue"

// Action defines interface action
type Action interface {
	nfqueue.Action
	RegisterIP(*Hooks)
}
