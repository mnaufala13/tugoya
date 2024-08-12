package example

import (
	"context"
	sdk "github.com/mnaufala13/tugoya"
	"testing"
	"time"
)

func TestDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	rr, err := sdk.Discovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rr {
		t.Logf("%+v", r)
	}
}
