package router

// Interface to intra-host (i.e. container) packet handling
type IntraHost interface {
	// Inject a packet to be delivered locally
	InjectPacket([]byte) error

	// Start consuming packets from the bridge
	ConsumePackets(IntraHostConsumer) error
}

// A function that accepts locally captured packets.  The ethernet
// decoder is specific to this thread, and will already have been used
// to to decode the packet data.
type IntraHostConsumer func([]byte, *EthernetDecoder)

type NullIntraHost struct{}

func (NullIntraHost) InjectPacket([]byte) error {
	return nil
}

func (NullIntraHost) ConsumePackets(IntraHostConsumer) error {
	return nil
}

func (NullIntraHost) String() string {
	return "<no intra-host networking>"
}
