package tuya_local_sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

type Option func(m *Manager)

func WithCallback(cmd Command, cb CallbackFunc) Option {
	return func(m *Manager) {
		m.callbackTable[cmd] = cb
	}
}

type Manager struct {
	Device        *Device
	mutex         sync.Mutex
	responseTable map[Command]chan *Response
	callbackTable map[Command]CallbackFunc
}

func NewManager(device *Device, opts ...Option) *Manager {
	m := &Manager{
		Device:        device,
		responseTable: make(map[Command]chan *Response),
		callbackTable: make(map[Command]CallbackFunc),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Start a new goroutine for the client read loop.
func (m *Manager) Start(ctx context.Context) {
	defer m.Device.Close()
	type readMsg struct {
		res *Response
		err error
	}
	msg := make(chan readMsg)
	for {
		go func() {
			res, err := m.Device.Read()
			if err != nil {
				if errors.Unwrap(err) == io.EOF {
					msg <- readMsg{nil, nil}
					return
				}
				msg <- readMsg{nil, err}
				return
			}
			slog.Debug(fmt.Sprintf("manager success read response with cmd %v", res.Cmd))
			msg <- readMsg{res, nil}
			return
		}()

		slog.Debug(fmt.Sprintf("manager waiting response"))
		select {
		case res := <-msg:
			if res.err == nil && res.res == nil {
				slog.Debug(fmt.Sprintf("manager exited, EOF"))
				return
			}
			if res.err != nil {
				slog.Error(fmt.Sprintf("error reading from device: %v", res.err))
				return
			}
			cmd := Command(res.res.Cmd)
			m.mutex.Lock()
			if ch, ok := m.responseTable[cmd]; ok {
				ch <- res.res
				delete(m.responseTable, cmd)
			} else {
				slog.Info(fmt.Sprintf("no request matching for cmd %d", cmd))
			}
			if callback, ok := m.callbackTable[cmd]; ok {
				callback(res.res)
			}
			m.mutex.Unlock()
		case <-ctx.Done():
			slog.Debug(fmt.Sprintf("manager exited, context done"))
			return
		}
	}
}

func (m *Manager) regRt(cmd Command, ch chan *Response) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, ok := m.responseTable[cmd]; !ok {
		slog.Debug(fmt.Sprintf("register response channel for command %v", cmd))
		m.responseTable[cmd] = ch
		return true
	}
	return false
}

func (m *Manager) delRt(cmd Command) {
	m.mutex.Lock()
	delete(m.responseTable, cmd)
	m.mutex.Unlock()
}

func (m *Manager) SendExec(ctx context.Context, do ExecFunc) (map[string]any, error) {
	cmd, _ := do()
	ch := make(chan *Response, 1)
	ok := m.regRt(cmd, ch)
	if !ok {
		return nil, errors.New("there is dangling command")
	}

	err := SendCommand(m.Device, do)
	if err != nil {
		m.delRt(cmd)
		return nil, err
	}
	slog.Debug(fmt.Sprintf("waiting response for command %v", cmd))
	select {
	case res := <-ch:
		if len(res.Payload) == 0 {
			return nil, nil
		}
		a := map[string]any{}
		err = res.DecodeJSON(&a)
		if err != nil {
			return nil, fmt.Errorf("decode response: %v", err)
		}
		return a, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type CallbackFunc func(r *Response)
