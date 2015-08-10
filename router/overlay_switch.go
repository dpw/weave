package router

import (
	"fmt"
)

// Switch between the sleeve and fastdp overlays, based on what
// the peer reports during connection initiation (TODO also on the forwarder
// status)

type OverlaySwitch struct {
	overlays []Overlay
}

func NewOverlaySwitch(overlays ...Overlay) Overlay {
	return &OverlaySwitch{
		overlays: overlays,
	}
}

func (osw *OverlaySwitch) AddFeaturesTo(features map[string]string) {
	for _, overlay := range osw.overlays {
		overlay.AddFeaturesTo(features)
	}
}

func (osw *OverlaySwitch) InvalidateRoutes() {
	for _, overlay := range osw.overlays {
		overlay.InvalidateRoutes()
	}
}

func (osw *OverlaySwitch) InvalidateShortIDs() {
	for _, overlay := range osw.overlays {
		overlay.InvalidateShortIDs()
	}
}

func (osw *OverlaySwitch) ConsumeOverlayPackets(localPeer *Peer, peers *Peers,
	consumer OverlayConsumer) error {
	for _, overlay := range osw.overlays {
		if err := overlay.ConsumeOverlayPackets(localPeer, peers,
			consumer); err != nil {
			return err
		}
	}
	return nil
}

func (osw *OverlaySwitch) MakeForwarder(
	params ForwarderParams) (OverlayForwarder, error) {
	for _, overlay := range osw.overlays {
		fwd, err := overlay.MakeForwarder(params)
		if err == nil {
			return fwd, nil
		}

		if _, isUOE := err.(UnsupportedOverlayError); !isUOE {
			return nil, err
		}
	}

	return nil, fmt.Errorf("no suitable overlay for connection")
}
