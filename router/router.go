package router

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	. "github.com/weaveworks/weave/common"
)

const (
	macMaxAge        = 10 * time.Minute       // [1]
	acceptMaxTokens  = 100                    // [2]
	acceptTokenDelay = 100 * time.Millisecond // [3]
)

// [1] should be greater than typical ARP cache expiries, i.e. > 3/2 *
// /proc/sys/net/ipv4_neigh/*/base_reachable_time_ms on Linux

// [2] capacity of token bucket for rate limiting accepts

// [3] control rate at which new tokens are added to the bucket

type LogFrameFunc func(string, []byte, *EthernetDecoder)

type Config struct {
	Port               int
	ProtocolMinVersion byte
	Password           []byte
	ConnLimit          int
	PeerDiscovery      bool
	BufSz              int
	LogFrame           LogFrameFunc
	Bridge             Bridge
	Overlay            Overlay
}

type Router struct {
	Config
	Ourself         *LocalPeer
	Macs            *MacCache
	Peers           *Peers
	Routes          *Routes
	ConnectionMaker *ConnectionMaker
	gossipLock      sync.RWMutex
	gossipChannels  GossipChannels
	TopologyGossip  Gossip
	UDPListener     *net.UDPConn
	acceptLimiter   *TokenBucket
}

func NewRouter(config Config, name PeerName, nickName string) *Router {
	router := &Router{Config: config, gossipChannels: make(GossipChannels)}

	if router.Bridge == nil {
		router.Bridge = NullBridge{}
	}

	if router.Overlay == nil {
		router.Overlay = NullOverlay{}
	}

	onMacExpiry := func(mac net.HardwareAddr, peer *Peer) {
		Log.Println("Expired MAC", mac, "at", peer)
	}
	onPeerGC := func(peer *Peer) {
		router.Macs.Delete(peer)
		Log.Println("Removed unreachable peer", peer)
	}
	router.Ourself = NewLocalPeer(name, nickName, router)
	router.Macs = NewMacCache(macMaxAge, onMacExpiry)
	router.Peers = NewPeers(router.Ourself)
	router.Peers.OnGC(onPeerGC)
	router.Peers.FetchWithDefault(router.Ourself.Peer)
	router.Routes = NewRoutes(router.Ourself, router.Peers)
	router.ConnectionMaker = NewConnectionMaker(router.Ourself, router.Peers, router.Port, router.PeerDiscovery)
	router.TopologyGossip = router.NewGossip("topology", router)
	router.acceptLimiter = NewTokenBucket(acceptMaxTokens, acceptTokenDelay)
	return router
}

// Start listening for TCP connections, locally captured packets, and
// forwarded packets.  This is separate from NewRouter so
// that gossipers can register before we start forming connections.
func (router *Router) Start() {
	Log.Println("Sniffing traffic on", router.Bridge)
	checkFatal(router.Bridge.ConsumePackets(router.handleCapturedPacket))
	checkFatal(router.Overlay.ConsumePackets(router.Ourself.Peer, router.Peers, router.handleForwardedPacket))
	router.listenTCP(router.Port)
}

func (router *Router) Stop() error {
	// TODO: perform graceful shutdown...
	return nil
}

func (router *Router) UsingPassword() bool {
	return router.Password != nil
}

func (router *Router) Status() string {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "Our name is", router.Ourself)
	fmt.Fprintln(&buf, "Encryption", OnOff(router.UsingPassword()))
	fmt.Fprintln(&buf, "Peer discovery", OnOff(router.PeerDiscovery))
	fmt.Fprintln(&buf, "Sniffing traffic on", router.Bridge)
	fmt.Fprintf(&buf, "MACs:\n%s", router.Macs)
	fmt.Fprintf(&buf, "Peers:\n%s", router.Peers)
	fmt.Fprintf(&buf, "Routes:\n%s", router.Routes)
	fmt.Fprint(&buf, router.ConnectionMaker.Status())
	return buf.String()
}

func (router *Router) handleCapturedPacket(frameData []byte, dec *EthernetDecoder) {
	router.LogFrame("Sniffed", frameData, dec)
	decodedLen := len(dec.decoded)
	if decodedLen == 0 {
		return
	}
	srcMac := dec.Eth.SrcMAC
	srcPeer, found := router.Macs.Lookup(srcMac)
	// We need to filter out frames we injected ourselves. For such
	// frames, the srcMAC will have been recorded as associated with a
	// different peer.
	if found && srcPeer != router.Ourself.Peer {
		return
	}
	if router.Macs.Enter(srcMac, router.Ourself.Peer) {
		Log.Println("Discovered local MAC", srcMac)
	}
	if dec.DropFrame() {
		return
	}
	dstMac := dec.Eth.DstMAC
	dstPeer, found := router.Macs.Lookup(dstMac)
	if found && dstPeer == router.Ourself.Peer {
		return
	}
	router.LogFrame("Forwarding", frameData, dec)

	// at this point we are handing over the frame to forwarders, so
	// we need to make a copy of it in order to prevent the next
	// capture from overwriting the data
	frameLen := len(frameData)
	frameCopy := make([]byte, frameLen, frameLen)
	copy(frameCopy, frameData)

	// If we don't know which peer corresponds to the dest MAC,
	// broadcast it.
	if !found {
		router.Ourself.Broadcast(frameCopy, dec)
		return
	}

	router.Ourself.Forward(dstPeer, frameCopy, dec)
}

func (router *Router) listenTCP(localPort int) {
	localAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprint(":", localPort))
	checkFatal(err)
	ln, err := net.ListenTCP("tcp4", localAddr)
	checkFatal(err)
	go func() {
		defer ln.Close()
		for {
			tcpConn, err := ln.AcceptTCP()
			if err != nil {
				Log.Errorln(err)
				continue
			}
			router.acceptTCP(tcpConn)
			router.acceptLimiter.Wait()
		}
	}()
}

func (router *Router) acceptTCP(tcpConn *net.TCPConn) {
	// someone else is dialing us, so our udp sender is the conn
	// on router.Port and we wait for them to send us something on UDP to
	// start.
	remoteAddrStr := tcpConn.RemoteAddr().String()
	Log.Printf("->[%s] connection accepted", remoteAddrStr)
	connRemote := NewRemoteConnection(router.Ourself.Peer, nil, remoteAddrStr, false, false)
	StartLocalConnection(connRemote, tcpConn, nil, router, true)
}

func (router *Router) handleForwardedPacket(srcPeer *Peer, dstPeer *Peer,
	frame []byte, dec *EthernetDecoder) {
	if dstPeer != router.Ourself.Peer {
		// it's not for us, we're just relaying it
		router.LogFrame("Relaying", frame, dec)
		router.Ourself.Relay(srcPeer, dstPeer, frame, dec)
		return
	}

	srcMac := dec.Eth.SrcMAC
	dstMac := dec.Eth.DstMAC

	if router.Macs.Enter(srcMac, srcPeer) {
		log.Println("Discovered remote MAC", srcMac, "at", srcPeer)
	}

	router.LogFrame("Injecting", frame, dec)
	checkWarn(router.Bridge.InjectPacket(frame))

	dstPeer, found := router.Macs.Lookup(dstMac)
	if !found || dstPeer != router.Ourself.Peer {
		router.LogFrame("Relaying broadcast", frame, dec)
		router.Ourself.RelayBroadcast(srcPeer, frame, dec)
	}
}

// Gossiper methods - the Router is the topology Gossiper

type TopologyGossipData struct {
	peers  *Peers
	update PeerNameSet
}

func NewTopologyGossipData(peers *Peers, update ...*Peer) *TopologyGossipData {
	names := make(PeerNameSet)
	for _, p := range update {
		names[p.Name] = void
	}
	return &TopologyGossipData{peers: peers, update: names}
}

func (d *TopologyGossipData) Merge(other GossipData) {
	for name := range other.(*TopologyGossipData).update {
		d.update[name] = void
	}
}

func (d *TopologyGossipData) Encode() [][]byte {
	return [][]byte{d.peers.EncodePeers(d.update)}
}

func (router *Router) OnGossipUnicast(sender PeerName, msg []byte) error {
	return fmt.Errorf("unexpected topology gossip unicast: %v", msg)
}

func (router *Router) OnGossipBroadcast(_ PeerName, update []byte) (GossipData, error) {
	origUpdate, _, err := router.applyTopologyUpdate(update)
	if err != nil || len(origUpdate) == 0 {
		return nil, err
	}
	return &TopologyGossipData{peers: router.Peers, update: origUpdate}, nil
}

func (router *Router) Gossip() GossipData {
	return &TopologyGossipData{peers: router.Peers, update: router.Peers.Names()}
}

func (router *Router) OnGossip(update []byte) (GossipData, error) {
	_, newUpdate, err := router.applyTopologyUpdate(update)
	if err != nil || len(newUpdate) == 0 {
		return nil, err
	}
	return &TopologyGossipData{peers: router.Peers, update: newUpdate}, nil
}

func (router *Router) applyTopologyUpdate(update []byte) (PeerNameSet, PeerNameSet, error) {
	origUpdate, newUpdate, err := router.Peers.ApplyUpdate(update)
	if _, ok := err.(UnknownPeerError); err != nil && ok {
		// That update contained a reference to a peer which wasn't
		// itself included in the update, and we didn't know about
		// already. We ignore this; eventually we should receive an
		// update containing a complete topology.
		Log.Println("Topology gossip:", err)
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(newUpdate) > 0 {
		router.ConnectionMaker.Refresh()
		router.Routes.Recalculate()
	}
	return origUpdate, newUpdate, nil
}
