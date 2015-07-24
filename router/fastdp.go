package router

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/weaveworks/go-odp/odp"
)

// FDP has to implement a bridge
//
// Bridge ports are
// - netdev vports (i.e. veth netdevs leading to containers)
// - internal vports (i.e. the 'weave' netdev used for 'weave expose')
// - the weave router, leading to the overlay network.
//
// When we get an ODP miss due to a packet from a container:
// - makeMissHandler examines the ingress vport and decides if it
//   is of an appropriate type (e.g. netdev or internal)
//
// A thunk does work with the FDP lock dropped.
//
// If the

// A bridgePortID is either an ODP vport or the router.  We express it
// like this to use it as a map key.
type bridgePortID struct {
	vport  odp.VportID
	router bool
}

var routerPortID = bridgePortID{router: true}

type bridgeSender func(key PacketKey) FlowOp

type FastDatapath struct {
	dpname string

	// The lock guards rthe FastDatapath state, and also
	// synchronises use of the dpif
	lock            sync.Mutex
	dpif            *odp.Dpif
	dp              odp.DatapathHandle
	missHandlers    map[odp.VportID]func(odp.FlowKeys) FlowOp
	vxlanVportID    odp.VportID
	localPeer       *Peer
	peers           *Peers
	overlayConsumer OverlayConsumer

	// Bridge state: How to send to the given bridge port
	sendToPort map[bridgePortID]bridgeSender
	// How to send to a given destination MAC
	sendToMAC map[MAC]bridgeSender

	// Only accessed from Miss, so not locked
	dec *EthernetDecoder
}

func NewFastDatapath(dpname string, vxlanUDPPort int) (*FastDatapath, error) {
	dpif, err := odp.NewDpif()
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			dpif.Close()
		}
	}()

	dp, err := dpif.LookupDatapath(dpname)
	if err != nil {
		return nil, err
	}

	fastdp := &FastDatapath{
		dpname:       dpname,
		dpif:         dpif,
		dp:           dp,
		missHandlers: make(map[odp.VportID]func(odp.FlowKeys) FlowOp),
		sendToPort:   nil,
		sendToMAC:    make(map[MAC]bridgeSender),
		dec:          NewEthernetDecoder(),
	}

	if err := fastdp.deleteVxlanVports(); err != nil {
		return nil, err
	}

	if err := fastdp.clearFlows(); err != nil {
		return nil, err
	}

	fastdp.vxlanVportID, err = fastdp.dp.CreateVport(
		odp.NewVxlanVportSpec("vxlan", uint16(vxlanUDPPort)))
	if err != nil {
		return nil, err
	}

	if err := fastdp.dp.ConsumeMisses(fastdp); err != nil {
		return nil, err
	}

	success = true
	return fastdp, nil
}

func (fastdp *FastDatapath) String() string {
	return fmt.Sprint(fastdp.dpname, " (via ODP)")
}

func (fastdp *FastDatapath) Close() error {
	err := fastdp.dpif.Close()
	fastdp.dpif = nil
	return err
}

func (fastdp *FastDatapath) clearFlows() error {
	flows, err := fastdp.dp.EnumerateFlows()
	if err != nil {
		return err
	}

	for _, flow := range flows {
		err = fastdp.dp.DeleteFlow(flow.FlowSpec)
		if err != nil && !odp.IsNoSuchFlowError(err) {
			return err
		}
	}

	return nil
}

func (fastdp *FastDatapath) deleteVxlanVports() error {
	vports, err := fastdp.dp.EnumerateVports()
	if err != nil {
		return err
	}

	for _, vport := range vports {
		if vport.Spec.TypeName() != "vxlan" {
			continue
		}

		err = fastdp.dp.DeleteVport(vport.ID)
		if err != nil && !odp.IsNoSuchVportError(err) {
			return err
		}
	}

	return nil
}

func (fastdp *FastDatapath) Error(err error, stopped bool) {
	// XXX fatal if stopped
	log.Println("Error while listening on datapath:", err)
}

func (fastdp *FastDatapath) Miss(packet []byte, fks odp.FlowKeys) error {
	ingress := fks[odp.OVS_KEY_ATTR_IN_PORT].(odp.InPortFlowKey).VportID()
	log.Println("Got miss", fks, "on port", ingress)

	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()

	// missHandlers is a cache indexed by the ingress vport
	handler := fastdp.missHandlers[ingress]
	if handler == nil {
		handler = fastdp.makeBridgeMissHandler(ingress)
		if handler == nil {
			return nil
		}

		fastdp.missHandlers[ingress] = handler
	}

	fastdp.send(handler(fks), packet)
	return nil
}

// Send a packet, creating a corresponding ODP flow rule if possible
func (fastdp *FastDatapath) send(fops FlowOp, frame []byte) {
	// Gather the actions from actionFlowOps, execute any others
	var dec *EthernetDecoder
	flow := odp.NewFlowSpec()
	createFlow := true

	for _, xfop := range FlattenFlowOp(fops) {
		switch fop := xfop.(type) {
		case interface {
			updateFlowSpec(*odp.FlowSpec)
		}:
			fop.updateFlowSpec(&flow)
		case vetoFlowCreationFlowOp:
			createFlow = false
		default:
			// A foreign flow op, so send the packet the
			// normal way, decoding the packet lazily.
			if dec == nil {
				dec = fastdp.dec
				dec.DecodeLayers(frame)
				createFlow = false
			}

			if len(dec.decoded) != 0 {
				fop.Send(frame, dec, false)
			}
		}
	}

	if len(flow.Actions) != 0 {
		checkWarn(fastdp.dp.Execute(frame, nil, flow.Actions))
	}

	if createFlow {
		log.Println("Creating flow", flow)
		checkWarn(fastdp.dp.CreateFlow(flow))
	}
}

type odpActionsFlowOp struct {
	fastdp  *FastDatapath
	actions []odp.Action
}

func (fastdp *FastDatapath) odpActions(actions ...odp.Action) FlowOp {
	return odpActionsFlowOp{
		fastdp:  fastdp,
		actions: actions,
	}
}

func (fop odpActionsFlowOp) updateFlowSpec(flow *odp.FlowSpec) {
	flow.AddActions(fop.actions)
}

func (fop odpActionsFlowOp) Send(frame []byte, dec *EthernetDecoder, bc bool) {
	fastdp := fop.fastdp
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	checkWarn(fastdp.dp.Execute(frame, nil, fop.actions))
}

type nopFlowOp struct{}

func (nopFlowOp) Send([]byte, *EthernetDecoder, bool) {
	// A nopFlowOp just provides a hint about flow creation, it
	// doesn't send anything
}

// A vetoFlowCreationFlowOp flags that no flow should be created
type vetoFlowCreationFlowOp struct {
	nopFlowOp
}

// A odpFlowKeyFlowOp adds a FlowKey to the resulting flow
type odpFlowKeyFlowOp struct {
	key odp.FlowKey
	nopFlowOp
}

func odpFlowKey(key odp.FlowKey) FlowOp {
	return odpFlowKeyFlowOp{key: key}
}

func (fop odpFlowKeyFlowOp) updateFlowSpec(flow *odp.FlowSpec) {
	flow.AddKey(fop.key)
}

func odpEthernetFlowKey(key PacketKey) FlowOp {
	fk := odp.NewEthernetFlowKey()
	fk.SetEthSrc(key.SrcMAC)
	fk.SetEthDst(key.DstMAC)
	return odpFlowKeyFlowOp{key: fk}
}

// Bridge

func (fastdp *FastDatapath) ConsumeBridgePackets(
	consumer BridgeConsumer) error {
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()

	if fastdp.sendToPort[routerPortID] != nil {
		return fmt.Errorf("FastDatapath already has a BridgeConsumer")
	}

	fastdp.addSendToPort(routerPortID, func(key PacketKey) FlowOp {
		// We are dropping the FastDatapath lock while we call
		// the consumer.  Callers have to be prepared for
		// this.
		fastdp.lock.Unlock()
		defer fastdp.lock.Lock()
		return consumer(key)
	})

	return nil
}

func (fastdp *FastDatapath) InjectPacket(key PacketKey) FlowOp {
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	return fastdp.bridge(routerPortID, key)
}

func (fastdp *FastDatapath) makeBridgeMissHandler(
	ingress odp.VportID) func(odp.FlowKeys) FlowOp {
	// Set up a bridge port for netdev and internal vports.  vxlan
	// vports are handled differently (we set up the handler for
	// the main vxlan vport in ConsumeOverlayPackets).

	vport, err := fastdp.dp.LookupVport(ingress)
	if err != nil {
		log.Println(err)
		return nil
	}

	typ := vport.Spec.TypeName()
	if typ != "netdev" && typ != "internal" {
		return nil
	}

	// Sending to the bridge port outputs on the vport:
	fastdp.addSendToPort(bridgePortID{vport: ingress},
		func(key PacketKey) FlowOp {
			return fastdp.odpActions(odp.NewOutputAction(ingress))
		})

	// Clear flows, in order to recalculate flows for broadcasts
	// on the bridge.
	checkWarn(fastdp.clearFlows())

	// Packets coming from the netdev are processed by the bridge
	return func(flowKeys odp.FlowKeys) FlowOp {
		return fastdp.bridge(bridgePortID{vport: ingress},
			flowKeysToPacketKey(flowKeys))
	}
}

// The sendToPort map is read-only, so this method does the copy in
// order to add an entry.
func (fastdp *FastDatapath) addSendToPort(portId bridgePortID,
	sender bridgeSender) {
	sendToPort := map[bridgePortID]bridgeSender{portId: sender}
	for id, sender := range fastdp.sendToPort {
		sendToPort[id] = sender
	}
	fastdp.sendToPort = sendToPort
}

func flowKeysToPacketKey(fks odp.FlowKeys) PacketKey {
	eth := fks[odp.OVS_KEY_ATTR_ETHERNET].(odp.EthernetFlowKey).Key()
	return PacketKey{SrcMAC: eth.EthSrc, DstMAC: eth.EthDst}
}

// A simple bridge implementation
func (fastdp *FastDatapath) bridge(ingress bridgePortID,
	key PacketKey) FlowOp {
	if fastdp.sendToMAC[key.SrcMAC] == nil {
		// Learn the source MAC
		fastdp.sendToMAC[key.SrcMAC] = fastdp.sendToPort[ingress]
	}

	// If we know about the destination MAC, deliver it to the
	// associated port.
	if sender := fastdp.sendToMAC[key.DstMAC]; sender != nil {
		return NewMultiFlowOp(false, odpEthernetFlowKey(key),
			sender(key))
	}

	// Otherwise, it might be a real broadcast, or it might
	// be for a MAC we don't know about yet.  Either way, we'll
	// broadcast it.
	mfop := NewMultiFlowOp(false)

	if (key.DstMAC[0] & 1) == 0 {
		// Not a real broadcast, so doon't create a flow rule.
		// If we did, we'd need to clear the flows every time
		// we learned a new MAC address, or have a more
		// complicated selective invalidation scheme.
		mfop.Add(vetoFlowCreationFlowOp{})
	} else {
		// A real broadcast
		mfop.Add(odpEthernetFlowKey(key))

		if !ingress.router {
			// The flowops below depend on the ingress vport.
			mfop.Add(odpFlowKey(odp.NewInPortFlowKey(
				ingress.vport)))
		}
	}

	// Send to all ports except the one it came in on. The
	// sendToPort map is immutable, so it is safe to iterate over
	// it even though the sender functions can drop the
	// FastDataPath lock.
	for id, sender := range fastdp.sendToPort {
		if id != ingress {
			mfop.Add(sender(key))
		}
	}

	return mfop
}

// Overlay

func (fastdp *FastDatapath) ConsumeOverlayPackets(
	localPeer *Peer, peers *Peers, consumer OverlayConsumer) error {
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()

	if fastdp.missHandlers[fastdp.vxlanVportID] != nil {
		return fmt.Errorf("FastDatapath already has an OverlayConsumer")
	}

	fastdp.localPeer = localPeer
	fastdp.peers = peers

	fastdp.missHandlers[fastdp.vxlanVportID] = func(fks odp.FlowKeys) FlowOp {
		tunnel := fks[odp.OVS_KEY_ATTR_TUNNEL].(odp.TunnelFlowKey).Key()
		srcPeer, dstPeer := fastdp.extractPeers(tunnel.TunnelId)
		if srcPeer == nil || dstPeer == nil {
			return vetoFlowCreationFlowOp{}
		}

		key := ForwardPacketKey{
			SrcPeer:   srcPeer,
			DstPeer:   dstPeer,
			PacketKey: flowKeysToPacketKey(fks),
		}

		// The resulting flow rule should be restricted to
		// packets with the same tunnelID
		var tunnelFlowKey odp.TunnelFlowKey
		tunnelFlowKey.SetTunnelId(tunnel.TunnelId)
		tunnelFlowKey.SetIpv4Src(tunnel.Ipv4Src)
		tunnelFlowKey.SetIpv4Dst(tunnel.Ipv4Dst)

		// We drop the FastDatapath lock while we call the
		// consumer.  Callers have to be prepared for this.
		fastdp.lock.Unlock()
		defer fastdp.lock.Lock()
		return NewMultiFlowOp(false, odpFlowKey(tunnelFlowKey),
			consumer(key))
	}

	return nil
}

func (fastdp *FastDatapath) InvalidateRoutes() {
	fmt.Println("InvalidateRoutes")
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	checkWarn(fastdp.clearFlows())
}

func (fastdp *FastDatapath) InvalidateShortIDs() {
	fmt.Println("InvalidateShortIDs")
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	checkWarn(fastdp.clearFlows())
}

func (fastdp *FastDatapath) extractPeers(tunnelID [8]byte) (*Peer, *Peer) {
	if fastdp.peers == nil {
		return nil, nil
	}

	vni := binary.BigEndian.Uint64(tunnelID[:])
	srcPeer := fastdp.peers.FetchByShortID(PeerShortID(vni & 0xfff))
	dstPeer := fastdp.peers.FetchByShortID(PeerShortID((vni >> 12) & 0xfff))
	return srcPeer, dstPeer
}

type FastDatapathForwarder struct {
	fastdp         *FastDatapath
	remotePeer     *Peer
	localIP        [4]byte
	sendControlMsg func([]byte) error

	lock        sync.Mutex
	listener    OverlayForwarderListener
	remoteIP    [4]byte
	established bool
}

func (fastdp *FastDatapath) MakeForwarder(
	params ForwarderParams) (OverlayForwarder, error) {
	if len(params.LocalIP) != 4 {
		return nil, fmt.Errorf("local IP address %s is not IPv4",
			params.LocalIP)
	}

	fwd := &FastDatapathForwarder{
		fastdp:         fastdp,
		remotePeer:     params.RemotePeer,
		sendControlMsg: params.SendControlMessage,
	}
	copy(fwd.localIP[:], params.LocalIP)
	return fwd, nil
}

func (fwd *FastDatapathForwarder) SetListener(
	listener OverlayForwarderListener) {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()

	if listener == nil {
		panic("nil listener")
	}

	fwd.listener = listener
	if fwd.established {
		listener.Established()
	}

	fwd.sendControlMsg(fwd.localIP[:])
}

func (fwd *FastDatapathForwarder) ControlMessage(msg []byte) {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()

	if len(msg) != 4 {
		if fwd.listener != nil {
			fwd.listener.Error(fmt.Errorf("FastDatapath control message wrong length %d", len(msg)))
			fwd.listener = nil
		}

		return
	}

	if !fwd.established {
		copy(fwd.remoteIP[:], msg)
		fwd.established = true
		if fwd.listener != nil {
			fwd.listener.Established()
		}
	}
}

func (fwd *FastDatapathForwarder) Forward(key ForwardPacketKey) FlowOp {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()
	if !fwd.established {
		// Ideally we could just return nil.  But then we
		// would have to invalidate the resulting flows when
		// we learn the remote IP.  So for now, just prevent
		// flows.
		return vetoFlowCreationFlowOp{}
	}

	var sta odp.SetTunnelAction
	sta.SetTunnelId(tunnelIDFor(key))
	sta.SetIpv4Src(fwd.localIP)
	sta.SetIpv4Dst(fwd.remoteIP)
	sta.SetTos(0)
	sta.SetTtl(64)
	sta.SetDf(true)
	sta.SetCsum(false)

	return fwd.fastdp.odpActions(sta,
		odp.NewOutputAction(fwd.fastdp.vxlanVportID))
}

func tunnelIDFor(key ForwardPacketKey) (tunnelID [8]byte) {
	src := uint64(key.SrcPeer.ShortID)
	dst := uint64(key.DstPeer.ShortID)
	binary.BigEndian.PutUint64(tunnelID[:], src|dst<<12)
	return
}

func (fwd *FastDatapathForwarder) Close() {
	// Ideally we would delete all the relevant flows here.  But
	// until we do that, it's probably not worth clearing all
	// flows.
}
