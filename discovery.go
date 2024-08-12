package tuya_local_sdk

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
)

func decodeBroadcast34(key []byte, r io.Reader) (*Frame, error) {
	// Read header
	var h header
	var hb bytes.Buffer
	err := binary.Read(r, binary.BigEndian, &h)
	_ = binary.Write(&hb, binary.BigEndian, h)
	slog.Debug(fmt.Sprintf("response header part %s", hex.EncodeToString(hb.Bytes())))
	if err != nil {
		return nil, fmt.Errorf("header Read: %w", err)
	}
	slog.Debug(fmt.Sprintf("response header detail %+v", h))

	if h.Prefix != prefixValue {
		return nil, ErrorBadPrefix
	}
	f := &Frame{
		Seq: h.Seq,
		Cmd: h.Cmd,
	}

	//Try to reuse the existing Payload []byte if it is big enough.
	//payloadSize := int(h.Length)
	//f.Payload = make([]byte, payloadSize)
	payloadSize := int(h.Length) - 0x8
	if cap(f.Payload) < payloadSize {
		if payloadSize > MaxPayloadSize {
			return nil, fmt.Errorf("payload too large; %d > %d", payloadSize, MaxPayloadSize)
		}
		f.Payload = make([]byte, payloadSize)
	} else {
		f.Payload = f.Payload[:payloadSize]
	}

	// Read payload
	cmdFromDiscovery := Command(h.Cmd) == Udp ||
		Command(h.Cmd) == UdpNew ||
		Command(h.Cmd) == BoardcastLpv
	err = binary.Read(r, binary.BigEndian, &f.Payload)
	slog.Debug(fmt.Sprintf("responsepayload part %s", hex.EncodeToString(f.Payload)))
	if err != nil {
		return nil, fmt.Errorf("payload Read: %w", err)
	}
	returnCode := binary.BigEndian.Uint32(f.Payload[0:4])
	slog.Debug("response returnCode", slog.String("value", hex.EncodeToString(f.Payload[0:4])))

	var dataPayload []byte
	if returnCode&0xFFFFFF00 != 0 {
		if !cmdFromDiscovery {
			dataPayload = f.Payload[:]
		}
	} else if !cmdFromDiscovery {
		dataPayload = f.Payload[4:]
	} else {
		dataPayload = f.Payload[4:]
	}
	slog.Debug("response dataPayload", slog.String("value", hex.EncodeToString(dataPayload)))

	// Read trailerV34
	trailerBytes := make([]byte, int(h.Length)-payloadSize)
	err = binary.Read(r, binary.BigEndian, &trailerBytes)
	slog.Debug(fmt.Sprintf("response trailer part %s", hex.EncodeToString(trailerBytes)))
	if err != nil {
		return nil, fmt.Errorf("trailerV34 Read: %w", err)
	}

	slog.Debug("response trailerBytes", slog.String("value", hex.EncodeToString(trailerBytes)))
	hmacBytes := trailerBytes[:len(trailerBytes)-binary.Size(prefixValue)]
	slog.Debug("response hmacBytes", slog.String("value", hex.EncodeToString(hmacBytes)))
	suffixBytes := trailerBytes[len(trailerBytes)-binary.Size(prefixValue):]
	slog.Debug("response suffixBytes", slog.String("value", hex.EncodeToString(suffixBytes)))

	var t = trailerV34{
		HmacValue: hmacBytes,
		Suffix:    binary.BigEndian.Uint32(suffixBytes),
	}
	if t.Suffix != suffixValue {
		return nil, ErrorBadSuffix
	}

	calc := hmac.New(sha256.New, key)
	calc.Write(f.Payload)
	hmacValue := calc.Sum(nil)

	// Validate HmacValue
	if bytes.Equal(hmacValue, t.HmacValue) {
		return nil, ErrorInvalidHmac
	}
	f.Payload = dataPayload
	return f, nil
}

type BcPacket struct {
	Ip         string `json:"ip"`
	GwId       string `json:"gwId"`
	Active     int    `json:"active"`
	Ablilty    int    `json:"ablilty"`
	Encrypt    bool   `json:"encrypt"`
	ProductKey string `json:"productKey"`
	Version    string `json:"version"`
}

type DiscoveryReport struct {
	Ip         string `json:"ip"`
	GwId       string `json:"gwId"`
	ProductKey string `json:"productKey"`
	Version    string `json:"version"`
}

const udpKey = "yGAdlopoPVldABfn"

func Discovery(ctx context.Context) (map[string]DiscoveryReport, error) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", 6667))
	if err != nil {
		return nil, err
	}
	key := md5.New()
	key.Write([]byte(udpKey))
	result := make(map[string]DiscoveryReport)
	for {
		select {
		case <-ctx.Done():
			return result, nil
		default:
		}

		func() {
			var buf [1024]byte
			_, _, err := conn.ReadFrom(buf[0:])
			if err != nil {
				slog.Error(err.Error())
				return
			}
			bb := bytes.NewBuffer(buf[0:])
			data, err := parseBcPacket(key.Sum(nil), bb)
			if err != nil {
				slog.Error(err.Error())
				return
			}
			r := DiscoveryReport{}
			err = json.Unmarshal(data, &r)
			if err != nil {
				slog.Error(err.Error())
				return
			}
			result[r.GwId] = r
		}()
	}
}

func parseBcPacket(key []byte, r io.Reader) ([]byte, error) {
	f, err := decodeBroadcast34(key, r)
	if err != nil {
		return nil, err
	}
	data, err := DecryptPayload(key, f.Payload)
	if err != nil {
		return nil, err
	}
	return data, nil
}
