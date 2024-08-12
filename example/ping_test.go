package example

import (
	"context"
	"fmt"
	sdk "github.com/mnaufala13/tugoya"
	"log/slog"
	"sync"
	"testing"
)

func TestPing(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	lk := []byte("PUT_LOCAL_KEY")
	d := sdk.Device{
		IpAddr:   "127.0.0.1",
		Port:     6668,
		DeviceId: " PUT_DEV_ID",
		Version:  sdk.Version34,
		LocalKey: lk,
	}
	err := d.Connect()
	if err != nil {
		panic(err)
	}
	defer d.Close()

	m := sdk.NewManager(&d, sdk.WithCallback(sdk.HeartBeat, func(r *sdk.Response) {
		slog.Debug(fmt.Sprintf("pong"))
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		m.Start(ctx)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		slog.Debug("ping")
		_, err := m.SendExec(ctx, sdk.Ping)
		if err != nil {
			slog.Error(fmt.Sprintf("error sending command: %v", err))
		}
		wg.Done()
		// stop response reader after receiving the pong response
		cancel()
	}()

	wg.Wait()
}
