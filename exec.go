package tuya_local_sdk

import (
	"encoding/json"
	"time"
)

type DataPoint struct {
	SwitchOn  bool `json:"1"`
	Countdown int  `json:"9"`
	Current   int  `json:"18"`
	Power     int  `json:"19"`
	Voltage   int  `json:"20"`
}

type ExecFunc func() (Command, []byte)

func onOff(on bool) (Command, []byte) {
	p, _ := json.Marshal(map[string]any{
		"protocol": 4,
		"t":        time.Now().Unix(),
		"data": map[string]map[string]any{
			"dps": {
				"1": on,
			},
		},
	})
	return ControlNew, p
}

func TurnOn() (Command, []byte) {
	return onOff(true)
}

func TurnOff() (Command, []byte) {
	return onOff(false)
}

func RefreshDp() (Command, []byte) {
	p, _ := json.Marshal(map[string]any{
		"t":    time.Now().Unix(),
		"dpId": []int{4, 5, 6, 18, 19, 20},
	})
	return UpdateDps, p
}

func Ping() (Command, []byte) {
	return HeartBeat, []byte("{}")
}
