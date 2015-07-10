package router

import (
	"encoding/json"
	"fmt"
	"time"
)

func (router *Router) StatusJSON(version string) ([]byte, error) {
	return json.Marshal(struct {
		Version       string
		Encryption    bool
		PeerDiscovery bool
		Name          string
		NickName      string
		Interface     string
		Macs          *MacCache
		Peers         *Peers
		Routes        *Routes
		ConnectionMakerStatus
	}{version, router.UsingPassword(), router.PeerDiscovery, router.Ourself.Name.String(), router.Ourself.NickName, fmt.Sprint(router.Bridge), router.Macs, router.Peers, router.Routes, router.ConnectionMaker.Status()})
}

func (cache *MacCache) MarshalJSON() ([]byte, error) {
	type cacheEntry struct {
		Mac      string
		Name     string
		NickName string
		LastSeen time.Time
	}
	var entries []*cacheEntry
	for key, entry := range cache.table {
		entries = append(entries, &cacheEntry{intmac(key).String(), entry.peer.Name.String(), entry.peer.NickName, entry.lastSeen})
	}
	return json.Marshal(entries)
}

func (peers *Peers) MarshalJSON() ([]byte, error) {
	type p struct {
		Name        string
		NickName    string
		UID         PeerUID
		Version     uint64
		Connections []Connection
	}
	var ps []*p
	peers.ForEach(func(peer *Peer) {
		var connections []Connection
		if peer == peers.ourself.Peer {
			for conn := range peers.ourself.Connections() {
				connections = append(connections, conn)
			}
		} else {
			// Modifying peer.connections requires a write lock on
			// Peers, and since we are holding a read lock (due to the
			// ForEach), access without locking the peer is safe.
			for _, conn := range peer.connections {
				connections = append(connections, conn)
			}
		}
		ps = append(ps, &p{peer.Name.String(), peer.NickName, peer.UID, peer.version, connections})
	})
	return json.Marshal(ps)
}

func (routes *Routes) MarshalJSON() ([]byte, error) {
	routes.RLock()
	defer routes.RUnlock()
	type uni struct {
		Dest, Via PeerName
	}
	type broad struct {
		Source PeerName
		Via    []PeerName
	}
	var r struct {
		Unicast   []*uni
		Broadcast []*broad
	}
	for name, hop := range routes.unicast {
		r.Unicast = append(r.Unicast, &uni{name, hop})
	}
	for name, hops := range routes.broadcast {
		r.Broadcast = append(r.Broadcast, &broad{name, hops})
	}
	return json.Marshal(r)
}

func (conn *RemoteConnection) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name     string
		NickName string
		TCPAddr  string
	}{conn.Remote().Name.String(), conn.Remote().NickName, conn.RemoteTCPAddr()})
}

func (name PeerName) MarshalJSON() ([]byte, error) {
	return json.Marshal(name.String())
}

func (target Target) MarshalJSON() ([]byte, error) {
	t := struct {
		Attempting  bool      `json:"Attempting,omitempty"`
		TryAfter    time.Time `json:"TryAfter,omitempty"`
		TryInterval string    `json:"TryInterval,omitempty"`
		LastError   string    `json:"LastError,omitempty"`
	}{
		Attempting:  target.attempting,
		TryAfter:    target.tryAfter,
		TryInterval: target.tryInterval.String(),
	}
	if target.lastError != nil {
		t.LastError = target.lastError.Error()
	}
	return json.Marshal(t)
}
