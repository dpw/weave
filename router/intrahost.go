package router

// Interface to intra-host (i.e. container) packet handling
type IntraHost interface {
	// Inject a packet to be delivered locally
	InjectPacket(PacketKey) FlowOp

	// Start consuming packets from the bridge
	ConsumeIntraHostPackets(IntraHostConsumer) error
}

// A function that determines how to handle locally captured packets.
type IntraHostConsumer func(PacketKey) FlowOp

type NullIntraHost struct{}

func (NullIntraHost) InjectPacket(PacketKey) FlowOp {
	return nil
}

func (NullIntraHost) ConsumeIntraHostPackets(IntraHostConsumer) error {
	return nil
}

func (NullIntraHost) String() string {
	return "<no intra-host networking>"
}
