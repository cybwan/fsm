package v2

import (
	"time"

	"github.com/flomesh-io/fsm/pkg/xnetwork/xnet/maps"
)

var (
	bridgeInfo *maps.IFaceVal
)

func (s *Server) getBridgeInfo() *maps.IFaceVal {
	if bridgeInfo != nil {
		return bridgeInfo
	}

	brKey := new(maps.IFaceKey)
	brKey.Len = uint8(len(bridgeDev))
	copy(brKey.Name[0:brKey.Len], bridgeDev)
	for {
		var err error
		bridgeInfo, err = maps.GetIFaceEntry(brKey)
		if err != nil {
			log.Error().Err(err).Msg(`failed to get node bridge info`)
			time.Sleep(time.Second * 5)
			continue
		}
		if bridgeInfo == nil {
			log.Error().Msg(`failed to get node bridge info`)
			time.Sleep(time.Second * 5)
			continue
		}
		break
	}
	return bridgeInfo
}
