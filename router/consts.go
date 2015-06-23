package router

import (
	"math"
	"time"
)

const (
	Port             = 6783
	HTTPPort         = Port + 1
	MaxUDPPacketSize = 65536
	ChannelSize      = 16
	TCPHeartbeat     = 30 * time.Second
	GossipInterval   = 30 * time.Second
	MaxDuration      = time.Duration(math.MaxInt64)
	HeaderTimeout    = 10 * time.Second
)
