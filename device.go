package tuya_local_sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"time"
)

type Version string

const (
	Version31 = "3.1"
	Version32 = "3.2"
	Version33 = "3.3"
	Version34 = "3.4"
)

type Device struct {
	IpAddr   string
	Port     int
	DeviceId string
	Version  Version
	Handler  Handler
	LocalKey []byte

	// used for session key negotiation process
	// if received msg from this channel, session key negotiation is done
	localNonce  []byte
	remoteNonce []byte
	sessionKey  []byte
	seq         int64
	conn        net.Conn
	isConnected bool
}

func (d *Device) key() []byte {
	if len(d.sessionKey) == 0 {
		return d.LocalKey
	}
	return d.sessionKey
}

func (d *Device) negotiateSessionKeyStart() error {
	slog.Debug("Sending session neg start")
	_, err := d.write(SessionKeyNegStart, d.localNonce)
	if err != nil {
		return err
	}
	return nil
}

func (d *Device) negotiateSessionKeyFinish() error {
	hmacValue := hmac.New(sha256.New, d.key())
	hmacValue.Write(d.remoteNonce)
	ss := hmacValue.Sum(nil)
	slog.Debug("hmacValue SessionKeyNegFinish", slog.String("value", hex.EncodeToString(ss)))
	_, err := d.write(SessionKeyNegFinish, ss)
	if err != nil {
		return err
	}
	return nil
}

func (d *Device) doNegotiation(f *Frame, finishFunc func() error) error {
	remoteNonce, err := extractRemoteNonce(d.key(), d.localNonce, f)
	if err != nil {
		return err
	}

	d.remoteNonce = remoteNonce
	err = finishFunc()
	if err != nil {
		return err
	}
	d.sessionKey = generateSessionKey(d.key(), d.localNonce, remoteNonce)
	slog.Debug("Protocol 3.4 sessionKey", slog.String("value", hex.EncodeToString(d.sessionKey)))

	return nil
}

func (d *Device) handleSessionKeyNeg(f *Frame) error {
	err := d.doNegotiation(f, d.negotiateSessionKeyFinish)
	if err != nil {
		return err
	}
	return nil
}

func (d *Device) handleUpdateDps(f *Frame) error {
	if len(f.Payload) > 0 {
		slog.Info(fmt.Sprintf("received DP_REFRESH response packet with data"))
		return nil
	}
	slog.Info(fmt.Sprintf("received DP_REFRESH response packet without data"))
	return nil
}

func (d *Device) initSessionKey() error {
	key := d.key()
	var fm *Frame
	for {
		f, err := DecodeVersion34(key, d.conn)
		if err != nil {
			slog.Warn(fmt.Sprintf("failed decode frame session key: %v", err))
			continue
		}
		slog.Debug("frame session key",
			slog.Int("seq", int(f.Seq)),
			slog.Int("cmd", int(f.Cmd)),
			slog.String("payload", hex.EncodeToString(f.Payload)),
		)
		f.Payload, err = DecryptPayload(key, f.Payload)
		if err != nil {
			slog.Warn(fmt.Sprintf("failed decrypt payload session key: %v", err))
			continue
		}
		if f.Cmd != SessionKeyNegResponse {
			slog.Debug("frame is not session key neg response")
			continue
		}
		fm = f
		break
	}
	err := d.handleSessionKeyNeg(fm)
	if err != nil {
		return fmt.Errorf("handle frame session key: %v", err)
	}
	slog.Info("session key negotiation is done")
	return nil
}

func (d *Device) Connect() error {
	slog.Info(fmt.Sprintf("connecting to %s:%d", d.IpAddr, d.Port))
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", d.IpAddr, d.Port))
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("connected to %s:%d", d.IpAddr, d.Port))
	d.localNonce = random()
	d.seq = 1
	d.conn = conn
	d.isConnected = true

	chDone := make(chan struct{})
	go func() {
		err := d.initSessionKey()
		if err != nil {
			slog.Error(fmt.Sprintf("init session key: %v", err))
			return
		}
		chDone <- struct{}{}
	}()

	err = d.negotiateSessionKeyStart()
	if err != nil {
		return err
	}

	// wait for session key negotiation
	<-chDone

	return nil
}

func (d *Device) Status() error {
	payload := map[string]any{
		"gwId":  d.DeviceId,
		"devId": d.DeviceId,
		"t":     time.Now().Unix(),
		"dps":   map[string]any{},
		"uid":   d.DeviceId,
	}
	payloadBytes, err := json.Marshal(payload)
	slog.Debug(fmt.Sprintf("payload status dp %s", payloadBytes))
	_, err = d.write(DpQueryNew, payloadBytes)
	if err != nil {
		return err
	}
	return nil
}

type Handler interface {
	Handle(f *Frame) error
}

func (d *Device) Read() (*Response, error) {
	return read(d.key(), d.conn)
}

// Close closes the Client connection.
func (d *Device) Close() error {
	return d.conn.Close()
}

// write sends a message to the connected device. The message is constructed
// from the `cmd` number and `payload`, which may be a JSON-serializable
// object or a []byte containing a raw message. If `encrypt` is true, the
// message will be encrypted. write may be called from multiple goroutines.
func (d *Device) write(cmd Command, payload []byte) (seq uint32, err error) {
	seq = uint32(d.seq)
	payloadEncrypted, err := EncodeVersion34(d.key(), Frame{
		Seq:     seq,
		Cmd:     uint32(cmd),
		Payload: payload,
	})
	if err != nil {
		return 0, fmt.Errorf("encode frame: %v", err)
	}
	d.seq += 1
	_, err = d.conn.Write(payloadEncrypted)
	if err != nil {
		return 0, fmt.Errorf("send payload: %v", err)
	}
	slog.Debug("send payload", slog.String("value", hex.EncodeToString(payloadEncrypted)),
		slog.Int("cmd", int(cmd)), slog.Int("seq", int(seq)))
	return seq, nil
}

func SendCommand(d *Device, do ExecFunc) error {
	cmd, payload := do()
	_, err := d.write(cmd, payload)
	if err != nil {
		return err
	}
	return nil
}

func generateSessionKey(key, localNonce, remoteNonce []byte) []byte {
	var sessionKey []byte
	for i := 0; i < len(localNonce); i++ {
		sessionKey = append(sessionKey, localNonce[i]^remoteNonce[i])
	}
	sessionKeyEncrypted, err := encryptAESWithECB(key, sessionKey, false)
	if err != nil {
		log.Fatal(err)
	}
	return sessionKeyEncrypted
}

func extractRemoteNonce(key, localNonce []byte, f *Frame) ([]byte, error) {
	remoteNonce := f.Payload[:16]
	slog.Debug("Protocol 3.4 localNonce", slog.String("value", hex.EncodeToString(localNonce)))
	slog.Debug("Protocol 3.4 remoteNonce", slog.String("value", hex.EncodeToString(remoteNonce)))
	slog.Debug("calcLocalHmac using key", slog.String("value", hex.EncodeToString(key)))
	calcLocalHmac := hmac.New(sha256.New, key)
	calcLocalHmac.Write(localNonce)
	expLocalHmac := f.Payload[16 : 16+32]
	if !bytes.Equal(expLocalHmac, calcLocalHmac.Sum(nil)) {
		return nil, fmt.Errorf("local hmac mismatch")
	}
	return remoteNonce, nil
}

// Read reads a Response from the connected device; it will block until it reads
// a full message or encounters invalid message data. It is *not* safe to call
// from multiple goroutines.
func read(key []byte, r io.Reader) (*Response, error) {
	f, err := DecodeVersion34(key, r)
	if err != nil {
		return nil, fmt.Errorf("DecodeFrame: %v", err)
	}
	slog.Debug("DecodeFrame",
		slog.Int("seq", int(f.Seq)),
		slog.Int("cmd", int(f.Cmd)),
		slog.String("payload", hex.EncodeToString(f.Payload)),
	)
	f.Payload, err = DecryptPayload(key, f.Payload)
	if err != nil {
		return nil, fmt.Errorf("DecryptPayload: %v", err)
	}
	return &Response{f}, nil
}
