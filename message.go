package tuya_local_sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

var (
	headerProtocol34 = []byte("3.4")
	MaxPayloadSize   = maxPacketSize
	// Precompute some useful sizes for decoding.
	headerSize = binary.Size(header{})
)

var (
	ErrorBadPrefix   = errors.New("bad prefix")
	ErrorBadSuffix   = errors.New("bad suffix")
	ErrorInvalidHmac = errors.New("invalid hmac")
)

const (
	// Magic values that bookend frames.
	prefixValue uint32 = 0x55aa
	suffixValue uint32 = 0xaa55
	// Packets seem to be limited to a single TCP frame in practice.
	maxPacketSize = 0xffff
)

// Frame header: "55aa" <prefix> <seq> <cmd> <length>
type header struct {
	Prefix uint32
	Seq    uint32
	Cmd    uint32
	Length uint32
}

// Frame trailerV34: <hmac256> <suffix> "aa55"
type trailerV34 struct {
	HmacValue []byte
	Suffix    uint32
}

// A Frame represents a message frame, with the sequence and command numbers parsed out.
type Frame struct {
	Seq     uint32
	Cmd     uint32
	Payload []byte
}

func DecodeVersion34(key []byte, r io.Reader) (*Frame, error) {
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
	payloadSize := int(h.Length) - 0x24
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

func DecryptPayload(key []byte, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	decrypted, err := decryptAESWithECB(key, payload)
	if err != nil {
		return nil, err
	}
	// Remove padding
	removedPadding := decrypted[:len(decrypted)-int(decrypted[len(decrypted)-1])]
	slog.Debug("decrypted", "value", hex.EncodeToString(removedPadding))
	return removedPadding, nil
}

func EncodeVersion34(key []byte, f Frame) ([]byte, error) {
	cmd := f.Cmd
	data := f.Payload
	seq := f.Seq

	if len(data) > MaxPayloadSize {
		return nil, fmt.Errorf("data too large; %d > %d", len(data), MaxPayloadSize)
	}
	if cmd != DpQuery && cmd != HeartBeat &&
		cmd != DpQueryNew && cmd != SessionKeyNegStart &&
		cmd != SessionKeyNegFinish && cmd != UpdateDps {
		// Add 3.4 header
		data = make([]byte, len(f.Payload)+15)
		copy(data[0:len(headerProtocol34)], headerProtocol34)
		copy(data[15:], f.Payload)
		slog.Debug("added 3.4 header")
	}

	paddingLen := 0x10 - (len(data) & 0xF)
	slog.Debug("paddingLen", slog.Int("value", paddingLen))
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	slog.Debug("padding", slog.String("value", hex.EncodeToString(padding)))
	data = append(data, padding...)
	slog.Debug("data", slog.String("value", hex.EncodeToString(data)))

	encrypted, err := encryptAESWithECB(key, data, false)
	if err != nil {
		return nil, err
	}
	slog.Debug("encrypted payload", slog.String("value", hex.EncodeToString(encrypted)))

	buf := bytes.NewBuffer(make([]byte, 0, len(encrypted)+52))
	buf2 := bytes.NewBuffer(make([]byte, 0, len(encrypted)+headerSize))

	w := io.MultiWriter(buf, buf2)

	length := buf.Cap() - headerSize

	// write header
	_ = binary.Write(w, binary.BigEndian, header{
		Prefix: prefixValue,
		Seq:    seq,
		Cmd:    cmd,
		Length: uint32(length),
	})

	// write data
	_, _ = w.Write(encrypted)

	// Calculate HMAC
	hmacTarget, _ := io.ReadAll(buf2)
	slog.Debug("target hmac", slog.String("value", hex.EncodeToString(hmacTarget)))
	calc := hmac.New(sha256.New, key)
	calc.Write(hmacTarget)
	hmacValue := calc.Sum(nil)
	slog.Debug("hmac", slog.String("value", hex.EncodeToString(hmacValue)))

	// write trailerV34
	_ = binary.Write(buf, binary.BigEndian, hmacValue[:])
	err = binary.Write(buf, binary.BigEndian, suffixValue)
	if err != nil {
		return nil, err
	}
	result, _ := io.ReadAll(buf)
	slog.Debug("final payload", slog.String("value", hex.EncodeToString(result)))
	return result, nil
}

type Response struct {
	*Frame
}

// DecodeJSON unmarshal the payload into an object with `json.Unmarshal`.
func (r *Response) DecodeJSON(v interface{}) error {
	payload := r.Payload[:]
	slog.Debug(fmt.Sprintf("try to decode respose to json %s", string(payload)))
	err := json.Unmarshal(payload, v)
	if err == nil {
		return nil
	}

	payload = r.Payload[15:]
	slog.Debug(fmt.Sprintf("try to decode response to json %s", string(payload)))
	err = json.Unmarshal(payload, v)
	if err == nil {
		return nil
	}
	return fmt.Errorf("unmarshal: %w", err)
}

// ResponseError is returned by `Response.Err()` for non-zero error codes.
type ResponseError struct {
	Code    uint32
	Message string
}

// Error implements the error interface.
func (re ResponseError) Error() string {
	return fmt.Sprintf("%s [error code %d]", re.Message, re.Code)
}
