package tuya_local_sdk

type Command uint32

/*
Tuya Command Types
Reference: https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/blob/master/sdk/include/lan_protocol.h
*/
const (
	Udp                   = 0x00
	ApConfig              = 0x01 //   # FRM_TP_CFG_WF      # only used for ap 3.0 network config
	Active                = 0x02 //   # FRM_TP_ACTV (discard) # WORK_MODE_CMD
	SessionKeyNegStart    = 0x03 //   # FRM_SECURITY_TYPE3 # negotiate session key
	SessionKeyNegResponse = 0x04 //   # FRM_SECURITY_TYPE4 # negotiate session key response
	SessionKeyNegFinish   = 0x05 //   # FRM_SECURITY_TYPE5 # finalize session key negotiation
	Unbind                = 0x06 //   # FRM_TP_UNBIND_DEV  # DATA_QUERT_CMD - issue command
	Control               = 0x07 //   # FRM_TP_CMD         # STATE_UPLOAD_CMD
	Status                = 0x08 //   # FRM_TP_STAT_REPORT # STATE_QUERY_CMD
	HeartBeat             = 0x09 //   # FRM_TP_HB
	DpQuery               = 0x0a //  # FRM_QUERY_STAT      # UPDATE_START_CMD - get data points
	QueryWifi             = 0x0b //  # FRM_SSID_QUERY (discard) # UPDATE_TRANS_CMD
	TokenBind             = 0x0c //  # FRM_USER_BIND_REQ   # GET_ONLINE_TIME_CMD - system time (GMT)
	ControlNew            = 0x0d //  # FRM_TP_NEW_CMD      # FACTORY_MODE_CMD
	EnableWifi            = 0x0e //  # FRM_ADD_SUB_DEV_CMD # WIFI_TEST_CMD
	WifiInfo              = 0x0f //  # FRM_CFG_WIFI_INFO
	DpQueryNew            = 0x10 //  # FRM_QUERY_STAT_NEW
	SceneExecute          = 0x11 //  # FRM_SCENE_EXEC
	UpdateDps             = 0x12 //  # FRM_LAN_QUERY_DP    # Request refresh of DPS
	UdpNew                = 0x13 //  # FR_TYPE_ENCRYPTION
	ApConfigNew           = 0x14 //  # FRM_AP_CFG_WF_V40
	BoardcastLpv          = 0x23 //  # FR_TYPE_BOARDCAST_LPV34
	ReqDevinfo            = 0x25 //  # broadcast to port 7000 to get v3.5 devices to send their info
	LanExtStream          = 0x40 //  # FRM_LAN_EXT_STREAM
)

var NoProtocolHeaderCmds = []Command{
	DpQuery, DpQueryNew, UpdateDps, HeartBeat, SessionKeyNegStart, SessionKeyNegResponse, SessionKeyNegFinish, LanExtStream,
}
