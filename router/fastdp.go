package router

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

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

type bridgeSender func(key PacketKey, lock *fastDatapathLock) FlowOp
type missHandler func(fks odp.FlowKeys, lock *fastDatapathLock) FlowOp

type FastDatapath struct {
	dpname string

	// The lock guards the FastDatapath state, and also
	// synchronizes use of the dpif
	lock            sync.Mutex
	dpif            *odp.Dpif
	dp              odp.DatapathHandle
	clearFlowsCount uint64
	missHandlers    map[odp.VportID]missHandler
	vxlanVportID    odp.VportID
	localPeer       *Peer
	peers           *Peers
	overlayConsumer OverlayConsumer

	// Bridge state: How to send to the given bridge port
	sendToPort map[bridgePortID]bridgeSender
	// How to send to a given destination MAC
	sendToMAC map[MAC]bridgeSender

	// A singleton pool for the occasions when we need to decode
	// the packet.
	dec *EthernetDecoder

	// forwarders by remote peer
	forwarders map[PeerName]*FastDatapathForwarder
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
		missHandlers: make(map[odp.VportID]missHandler),
		sendToPort:   nil,
		sendToMAC:    make(map[MAC]bridgeSender),
		forwarders:   make(map[PeerName]*FastDatapathForwarder),
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
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	err := fastdp.dpif.Close()
	fastdp.dpif = nil
	return err
}

type fastDatapathLock struct {
	fastdp          *FastDatapath
	locked          bool
	clearFlowsCount uint64
}

func (fastdp *FastDatapath) startLock() fastDatapathLock {
	fastdp.lock.Lock()
	return fastDatapathLock{
		fastdp:          fastdp,
		locked:          true,
		clearFlowsCount: fastdp.clearFlowsCount,
	}
}

func (lock *fastDatapathLock) unlock() {
	if lock.locked {
		lock.fastdp.lock.Unlock()
		lock.locked = false
	}
}

func (lock *fastDatapathLock) relock() {
	if !lock.locked {
		lock.fastdp.lock.Lock()
		lock.locked = true
	}
}

func (fastdp *FastDatapath) addForwarder(peer PeerName,
	fwd *FastDatapathForwarder) {
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()

	// We shouldn't have two confirmed forwarders to the same
	// remotePeer, due to the checks in LocalPeer AddConnection.
	fastdp.forwarders[peer] = fwd
}

func (fastdp *FastDatapath) removeForwarder(peer PeerName,
	fwd *FastDatapathForwarder) {
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	if fastdp.forwarders[peer] == fwd {
		delete(fastdp.forwarders, peer)
	}
}

func (fastdp *FastDatapath) clearFlows() error {
	fastdp.clearFlowsCount++

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
	log.Error("Error while listening on datapath: ", err)
}

func (fastdp *FastDatapath) Miss(packet []byte, fks odp.FlowKeys) error {
	ingress := fks[odp.OVS_KEY_ATTR_IN_PORT].(odp.InPortFlowKey).VportID()
	log.Debug("Got ODP miss ", fks, " on port ", ingress)

	lock := fastdp.startLock()
	defer lock.unlock()

	// missHandlers is a cache indexed by the ingress vport
	handler := fastdp.missHandlers[ingress]
	if handler == nil {
		handler = fastdp.makeBridgeMissHandler(ingress)
		if handler == nil {
			return nil
		}

		fastdp.missHandlers[ingress] = handler
	}

	fastdp.send(handler(fks, &lock), packet, &lock)
	return nil
}

// Send a packet, creating a corresponding ODP flow rule if possible
func (fastdp *FastDatapath) send(fops FlowOp, frame []byte,
	lock *fastDatapathLock) {
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
				dec = fastdp.takeDecoder(lock)
				dec.DecodeLayers(frame)
				createFlow = false
			}

			if len(dec.decoded) != 0 {
				// drop the lock while calling the
				// foreign Send function
				lock.unlock()
				fop.Send(frame, dec, false)
			}
		}
	}

	if dec != nil {
		// put the decoder back
		lock.relock()
		fastdp.dec = dec
	}

	if len(flow.Actions) != 0 {
		lock.relock()
		checkWarn(fastdp.dp.Execute(frame, nil, flow.Actions))
	}

	if createFlow {
		lock.relock()
		// if the fastdp's clearFlowsCount changed since we
		// initially locked it, then we might have created a
		// flow on the basis of stale information.  Ift's fine
		// to handle one packet like that, but it would be bad
		// to introduce a stale flow.
		if lock.clearFlowsCount != fastdp.clearFlowsCount {
			log.Debug("Creating ODP flow ", flow)
			checkWarn(fastdp.dp.CreateFlow(flow))
		}
	}
}

func (fastdp *FastDatapath) takeDecoder(lock *fastDatapathLock) *EthernetDecoder {
	lock.relock()
	dec := fastdp.dec
	if dec == nil {
		dec = NewEthernetDecoder()
	} else {
		fastdp.dec = nil
	}
	return dec
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

	fastdp.addSendToPort(routerPortID,
		func(key PacketKey, lock *fastDatapathLock) FlowOp {
			// drop the FastDatapath lock in order to call
			// the consumer
			lock.unlock()
			return consumer(key)
		})
	return nil
}

func (fastdp *FastDatapath) InjectPacket(key PacketKey) FlowOp {
	lock := fastdp.startLock()
	defer lock.unlock()
	return fastdp.bridge(routerPortID, key, &lock)
}

func (fastdp *FastDatapath) makeBridgeMissHandler(
	ingress odp.VportID) missHandler {
	// Set up a bridge port for netdev and internal vports.  vxlan
	// vports are handled differently (we set up the handler for
	// the main vxlan vport in ConsumeOverlayPackets).

	vport, err := fastdp.dp.LookupVport(ingress)
	if err != nil {
		log.Error(err)
		return nil
	}

	typ := vport.Spec.TypeName()
	if typ != "netdev" && typ != "internal" {
		return nil
	}

	// Sending to the bridge port outputs on the vport:
	fastdp.addSendToPort(bridgePortID{vport: ingress},
		func(_ PacketKey, _ *fastDatapathLock) FlowOp {
			return fastdp.odpActions(odp.NewOutputAction(ingress))
		})

	// Clear flows, in order to recalculate flows for broadcasts
	// on the bridge.
	checkWarn(fastdp.clearFlows())

	// Packets coming from the netdev are processed by the bridge
	return func(flowKeys odp.FlowKeys, lock *fastDatapathLock) FlowOp {
		return fastdp.bridge(bridgePortID{vport: ingress},
			flowKeysToPacketKey(flowKeys), lock)
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
	key PacketKey, lock *fastDatapathLock) FlowOp {
	lock.relock()
	if fastdp.sendToMAC[key.SrcMAC] == nil {
		// Learn the source MAC
		fastdp.sendToMAC[key.SrcMAC] = fastdp.sendToPort[ingress]
	}

	// If we know about the destination MAC, deliver it to the
	// associated port.
	if sender := fastdp.sendToMAC[key.DstMAC]; sender != nil {
		return NewMultiFlowOp(false, odpEthernetFlowKey(key),
			sender(key, lock))
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
	// fastDatapathLock
	for id, sender := range fastdp.sendToPort {
		if id != ingress {
			mfop.Add(sender(key, lock))
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

	handler := func(fks odp.FlowKeys, lock *fastDatapathLock) FlowOp {
		lock.unlock()
		tunnel := fks[odp.OVS_KEY_ATTR_TUNNEL].(odp.TunnelFlowKey).Key()
		srcPeer, dstPeer := fastdp.extractPeers(tunnel.TunnelId)
		if srcPeer == nil || dstPeer == nil {
			return vetoFlowCreationFlowOp{}
		}

		pk := flowKeysToPacketKey(fks)
		var zeroMAC MAC
		if pk.SrcMAC == zeroMAC && pk.DstMAC == zeroMAC {
			return vxlanSpecialPacketFlowOp{fastdp, srcPeer,
				tunnel.Ipv4Src}
		}

		key := ForwardPacketKey{
			SrcPeer:   srcPeer,
			DstPeer:   dstPeer,
			PacketKey: pk,
		}

		// The resulting flow rule should be restricted to
		// packets with the same tunnelID
		var tunnelFlowKey odp.TunnelFlowKey
		tunnelFlowKey.SetTunnelId(tunnel.TunnelId)
		tunnelFlowKey.SetIpv4Src(tunnel.Ipv4Src)
		tunnelFlowKey.SetIpv4Dst(tunnel.Ipv4Dst)

		return NewMultiFlowOp(false, odpFlowKey(tunnelFlowKey),
			consumer(key))
	}

	fastdp.missHandlers[fastdp.vxlanVportID] = handler
	return nil
}

type vxlanSpecialPacketFlowOp struct {
	fastdp  *FastDatapath
	srcPeer *Peer
	ipv4Src [4]byte
}

func (op vxlanSpecialPacketFlowOp) Send(frame []byte, dec *EthernetDecoder,
	broadcast bool) {
	op.fastdp.lock.Lock()
	fwd := op.fastdp.forwarders[op.srcPeer.Name]
	op.fastdp.lock.Unlock()

	if !dec.IsSpecial() {
		// A surprising case, as we already know the packet is
		// to/from the all-zeroes MAC address from the flow
		// key.
		return
	}

	fwd.handleVxlanSpecialPacket(frame, op.ipv4Src)
}

func (fastdp *FastDatapath) InvalidateRoutes() {
	log.Debug("InvalidateRoutes")
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	checkWarn(fastdp.clearFlows())
}

func (fastdp *FastDatapath) InvalidateShortIDs() {
	log.Debug("InvalidateShortIDs")
	fastdp.lock.Lock()
	defer fastdp.lock.Unlock()
	checkWarn(fastdp.clearFlows())
}

func (*FastDatapath) AddFeaturesTo(features map[string]string) {
	features["FastDatapath"] = ""
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
	connUID        uint64

	lock              sync.RWMutex
	confirmed         bool
	remoteIP          [4]byte
	haveRemoteIP      bool
	heartbeatInterval time.Duration
	heartbeatTimer    *time.Timer
	heartbeatTimeout  *time.Timer
	ackedHeartbeat    bool
	stopChan          chan struct{}
	stopped           bool

	establishedChan chan struct{}
	errorChan       chan error
}

func (fastdp *FastDatapath) MakeForwarder(
	params ForwarderParams) (OverlayForwarder, error) {
	if _, present := params.Features["FastDatapath"]; !present {
		return nil, UnsupportedOverlayError{"fast datapath"}
	}

	localIP, err := ipv4Bytes(params.LocalIP)
	if err != nil {
		return nil, err
	}

	fwd := &FastDatapathForwarder{
		fastdp:         fastdp,
		remotePeer:     params.RemotePeer,
		localIP:        localIP,
		sendControlMsg: params.SendControlMessage,
		connUID:        params.ConnUID,

		heartbeatInterval: FastHeartbeat,
		stopChan:          make(chan struct{}),

		establishedChan: make(chan struct{}),
		errorChan:       make(chan error, 1),
	}

	if params.RemoteAddr != nil {
		fwd.haveRemoteIP = true
		fwd.remoteIP, err = ipv4Bytes(params.RemoteAddr.IP)
		if err != nil {
			return nil, err
		}
	}

	return fwd, err
}

func ipv4Bytes(ip net.IP) (res [4]byte, err error) {
	ipv4 := ip.To4()
	if ipv4 != nil {
		copy(res[:], ipv4)
	} else {
		err = fmt.Errorf("IP address %s is not IPv4", ip)
	}
	return
}

func (fwd *FastDatapathForwarder) logPrefix() string {
	var ip net.IP
	if fwd.haveRemoteIP {
		ip = net.IP(fwd.remoteIP[:])
	}

	return fmt.Sprintf("->[%s|%s]: ", ip, fwd.remotePeer)
}

func (fwd *FastDatapathForwarder) SetListener(
	listener OverlayForwarderListener) {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()

	if listener == nil {
		panic("nil listener")
	}

	if fwd.confirmed {
		panic("already confirmed")
	}

	go func() {
		select {
		case <-fwd.establishedChan:
			listener.Established()

		case <-fwd.stopChan:
		}
	}()
	go func() {
		select {
		case err := <-fwd.errorChan:
			if err != nil {
				listener.Error(err)
			}

		case <-fwd.stopChan:
		}
	}()

	log.Debug(fwd.logPrefix(), "confirmed")
	fwd.fastdp.addForwarder(fwd.remotePeer.Name, fwd)
	fwd.confirmed = true

	if fwd.haveRemoteIP {
		// have the goroutnie send a heartbeat straight away
		fwd.heartbeatTimer = time.NewTimer(0)
	} else {
		// we'll reset the timer when we learn the remote ip
		fwd.heartbeatTimer = time.NewTimer(time.Hour * 24 * 365)
	}

	fwd.heartbeatTimeout = time.NewTimer(HeartbeatTimeout)
	go fwd.doHeartbeats()

	// start sending heartbeats when confirmed, and when have
	// remote addr (i.e. received heartbeat).

	// need to set up the heeartbeat timer when confirmed and have
	// remoute address

	// need to start the heartbeat timeout when confirmed

	// need to call the listeners established func

	// thread: waits for timer, waits for timeout, waits for
	// "close" indication.
}

func (fwd *FastDatapathForwarder) doHeartbeats() {
	var err error

	for err == nil {
		select {
		case <-fwd.heartbeatTimer.C:
			if fwd.confirmed {
				fwd.sendHeartbeat()
			}
			fwd.heartbeatTimer.Reset(fwd.heartbeatInterval)

		case <-fwd.heartbeatTimeout.C:
			err = fmt.Errorf("timed out waiting for vxlan heartbeat")

		case <-fwd.stopChan:
			return
		}
	}

	fwd.lock.Lock()
	defer fwd.lock.Unlock()
	fwd.handleError(err)
}

func (fwd *FastDatapathForwarder) sendHeartbeat() {
	fwd.lock.RLock()
	log.Debug(fwd.logPrefix(), "sendHeartbeat")
	var buf [EthernetOverhead + 8]byte
	binary.BigEndian.PutUint64(buf[EthernetOverhead:], fwd.connUID)
	dec := NewEthernetDecoder()
	dec.DecodeLayers(buf[:])
	pk := ForwardPacketKey{
		PacketKey: dec.PacketKey(),
		SrcPeer:   fwd.fastdp.localPeer,
		DstPeer:   fwd.remotePeer,
	}
	fwd.lock.RUnlock()
	fwd.Forward(pk).Send(buf[:], dec, false)
}

// Handle an error which leads to notifying the listener and
// termination of the forwarder
func (fwd *FastDatapathForwarder) handleError(err error) {
	if err == nil {
		return
	}

	select {
	case fwd.errorChan <- err:
	default:
	}

	// stop the heartbeat goroutine
	if !fwd.stopped {
		fwd.stopped = true
		close(fwd.stopChan)
	}
}

func (fwd *FastDatapathForwarder) handleVxlanSpecialPacket(frame []byte,
	ipv4Src [4]byte) {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()

	uid := binary.BigEndian.Uint64(frame[EthernetOverhead:])
	if uid != fwd.connUID {
		return
	}

	log.Debug(fwd.logPrefix(), "handleHeartbeat")

	if !fwd.haveRemoteIP {
		fwd.remoteIP = ipv4Src
		fwd.haveRemoteIP = true

		if fwd.confirmed {
			fwd.heartbeatTimer.Reset(0)
		}
	} else if fwd.remoteIP != ipv4Src {
		log.Info(fwd.logPrefix(),
			"Peer IP address changed to", net.IP(ipv4Src[:]))
		fwd.remoteIP = ipv4Src
	}

	if !fwd.ackedHeartbeat {
		fwd.ackedHeartbeat = true
		fwd.handleError(fwd.sendControlMsg([]byte{HeartbeatAck}))
	}
}

func (fwd *FastDatapathForwarder) ControlMessage(msg []byte) {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()

	if len(msg) == 0 {
		log.Info(fwd.logPrefix(),
			"Received zero-length control message")
	}

	switch msg[0] {
	case HeartbeatAck:
		fwd.handleHeartbeatAck()

	default:
		log.Info(fwd.logPrefix(),
			"Ignoring unknown control message:", msg[0])
	}
}

func (fwd *FastDatapathForwarder) handleHeartbeatAck() {
	log.Debug(fwd.logPrefix(), "handleHeartbeat")

	if fwd.heartbeatInterval != SlowHeartbeat {
		close(fwd.establishedChan)
		fwd.heartbeatInterval = SlowHeartbeat
		if fwd.heartbeatTimer != nil {
			fwd.heartbeatTimer.Reset(fwd.heartbeatInterval)
		}
	}
}

func (fwd *FastDatapathForwarder) Forward(key ForwardPacketKey) FlowOp {
	fwd.lock.RLock()
	defer fwd.lock.RUnlock()

	if !fwd.haveRemoteIP {
		// Just returning nil would indicate that that the
		// packet is discarded.  But that would result in a
		// flow rule, which we would have to invalidate when
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
	// Might be nice to delete all the relevant flows here, but we
	// can just lett them expire.
	fwd.fastdp.removeForwarder(fwd.remotePeer.Name, fwd)

	fwd.lock.Lock()
	defer fwd.lock.Unlock()
	fwd.sendControlMsg = func([]byte) error { return nil }
}
