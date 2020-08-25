// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package main

import (
	// apiservices
	_ "github.com/luids-io/api/dnsutil/grpc/resolvcheck"
	_ "github.com/luids-io/api/event/grpc/archive"
	_ "github.com/luids-io/api/event/grpc/notify"
	_ "github.com/luids-io/api/xlist/grpc/check"

	// plugins
	_ "github.com/luids-io/netfilter/pkg/nfqueue/plugins/ipp"

	// actions
	_ "github.com/luids-io/netfilter/pkg/nfqueue/plugins/ipp/actions/checkip"
	_ "github.com/luids-io/netfilter/pkg/nfqueue/plugins/ipp/actions/checkresolv"
)
