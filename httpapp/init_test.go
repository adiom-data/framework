package httpapp

import (
	"context"
	"testing"

	"github.com/adiom-data/framework/telemetry"
)

func TestInitRuntimeUsesTelemetryConfig(t *testing.T) {
	runtime, err := Init(context.Background(), WithTelemetry(telemetry.DisabledConfig()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()

	if runtime.TelemetryConfig().Enabled == nil || *runtime.TelemetryConfig().Enabled {
		t.Fatal("runtime telemetry config was not disabled")
	}

	service := runtime.NewService()
	app := service.app()
	if app.Telemetry.Enabled == nil || *app.Telemetry.Enabled {
		t.Fatal("runtime.NewService did not apply runtime telemetry config")
	}

	clientOptions, err := runtime.ConnectClientOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(clientOptions) != 0 {
		t.Fatalf("ConnectClientOptions len=%d want 0 for disabled telemetry", len(clientOptions))
	}
}
