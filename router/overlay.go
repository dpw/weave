package router

import (
	"net"
)

// Interface to overlay network packet handling
type Overlay interface {
	// Start consuming forwarded packets.
	ConsumeOverlayPackets(*Peer, *Peers, OverlayConsumer) error

	// Form a packet-forwarding connection.
	MakeForwarder(ForwarderParams) (OverlayForwarder, error)

	// The routes have changed, so any cached information should
	// be discarded.
	InvalidateRoutes()

	// A mapping of a short id to a peer has changed
	InvalidateShortIDs()

	// Enhance a features map with overlay-related features
	AddFeaturesTo(map[string]string)
}

type ForwarderParams struct {
	RemotePeer *Peer

	// The local IP address to use for sending.  Derived from the
	// local address of the corresponding TCP socket, so may
	// differ for different forwarders.
	LocalIP net.IP

	// The remote address to send to.  nil if unknown, i.e. an
	// incoming connection, in which case the Overlay needs to
	// discover it (e.g. from incoming datagrams).
	RemoteAddr *net.UDPAddr

	// Unique identifier for this connection
	ConnUID uint64

	// Crypto bits.  Nil if not encrypting
	Crypto *OverlayCrypto

	// Function to send a control message to the counterpart
	// forwarder.
	SendControlMessage func([]byte) error

	// Features passed at connection initiation
	Features map[string]string
}

// When a consumer is called, the decoder will already have been used
// to decode the frame.
type OverlayConsumer func(ForwardPacketKey) FlowOp

// Crypto settings for a forwarder.
type OverlayCrypto struct {
	Dec   Decryptor
	Enc   Encryptor
	EncDF Encryptor
}

// All of the machinery to forward packets to a particular peer
type OverlayForwarder interface {
	// Register a callback for forwarder state changes.
	// side-effect, calling this confirms that the connection is
	// really wanted, and so the provider should activate it.
	// However, Forward might be called before this is called
	// (e.g. on another thread).
	SetListener(OverlayForwarderListener)

	// Forward a packet across the connection.
	Forward(ForwardPacketKey) FlowOp

	Close()

	// Handle a message from the peer
	ControlMessage([]byte)
}

type OverlayForwarderListener interface {
	Established()
	Error(error)
}

type NullOverlay struct{}

func (NullOverlay) ConsumeOverlayPackets(*Peer, *Peers, OverlayConsumer) error {
	return nil
}

func (NullOverlay) MakeForwarder(ForwarderParams) (OverlayForwarder, error) {
	return NullOverlay{}, nil
}

func (NullOverlay) InvalidateRoutes() {
}

func (NullOverlay) InvalidateShortIDs() {
}

func (NullOverlay) AddFeaturesTo(map[string]string) {
}

func (NullOverlay) SetListener(OverlayForwarderListener) {
}

func (NullOverlay) Forward(ForwardPacketKey) FlowOp {
	return nil
}

func (NullOverlay) Close() {
}

func (NullOverlay) ControlMessage([]byte) {
}
