package router

import (
	"net"
)

// Interface to inter-host (i.e. overlay network) packet handling
type InterHost interface {
	// Start consuming forwarded packets.
	ConsumePackets(*Peer, *Peers, InterHostConsumer) error

	// Form a packet-forwarding connection.
	MakeForwarder(ForwarderParams) (InterHostForwarder, error)

	// Feature identifiers to send during the handshake.
	// Indentifiers must not contain whitespace.
	Features() []string
}

type ForwarderParams struct {
	RemotePeer *Peer

	// The local IP address to use for sending.  Derived from the
	// local address of the corresponding TCP socket, so may
	// differ for different forwarders.
	LocalIP net.IP

	// The remote address to send to.  nil if unknown, i.e. an
	// incoming connection, in which case the InterHost needs to
	// discover it (e.g. from incoming datagrams).
	RemoteAddr *net.UDPAddr

	// Unique identifier for this connection
	ConnUID uint64

	// Crypto bits.  Nil if not encrypting
	Crypto *InterHostCrypto

	// Peer's feature identifiers
	Features []string

	// Function to send a control message to the counterpart
	// forwarder.
	SendControlMessage func([]byte) error
}

// When a consumer is called, the decoder will already have been used
// to decode the frame.
type InterHostConsumer func(ForwardPacketKey) FlowOp

// Crypto settings for a forwarder.
type InterHostCrypto struct {
	Dec   Decryptor
	Enc   Encryptor
	EncDF Encryptor
}

// All of the machinery to forward packets to a particular peer
type InterHostForwarder interface {
	// Register a callback for forwarder state changes.
	// side-effect, calling this confirms that the connection is
	// really wanted, and so the provider should activate it.
	// However, Forward might be called before this is called
	// (e.g. on another thread).
	SetListener(InterHostForwarderListener)

	// Forward a packet across the connection.
	Forward(ForwardPacketKey) FlowOp

	Close()

	// Handle a message from the peer
	ControlMessage([]byte)
}

type InterHostForwarderListener interface {
	Established()
	Error(error)
}

type NullInterHost struct{}

func (NullInterHost) ConsumePackets(*Peer, *Peers, InterHostConsumer) error {
	return nil
}

func (NullInterHost) MakeForwarder(ForwarderParams) (InterHostForwarder, error) {
	return NullInterHost{}, nil
}

func (NullInterHost) Features() []string {
	return []string{}
}

func (NullInterHost) SetListener(InterHostForwarderListener) {
}

func (NullInterHost) Forward(ForwardPacketKey) FlowOp {
	return nil
}

func (NullInterHost) Close() {
}

func (NullInterHost) ControlMessage([]byte) {
}
