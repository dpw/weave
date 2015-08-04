package router

import (
	"fmt"
)

// Switch between the sleeve and fastdp overlays, based on what
// the peer reports during connection initiation (TODO also on the forwarder
// status)

type OverlaySwitch struct {
	NullOverlay
	overlays []Overlay
}

func NewOverlaySwitch(overlays ...Overlay) Overlay {
	return &OverlaySwitch{
		overlays: overlays,
	}
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
