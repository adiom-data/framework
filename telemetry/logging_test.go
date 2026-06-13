package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestTraceLogHandlerAddsTraceFields(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(slog.NewJSONHandler(&output, nil))
	traceID := trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	spanID := trace.SpanID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	}))

	logger.InfoContext(ctx, "hello")

	log := output.String()
	if !strings.Contains(log, `"trace_id":"0102030405060708090a0b0c0d0e0f10"`) {
		t.Fatalf("log missing trace_id: %s", log)
	}
	if !strings.Contains(log, `"span_id":"1112131415161718"`) {
		t.Fatalf("log missing span_id: %s", log)
	}
	if !strings.Contains(log, `"trace_sampled":true`) {
		t.Fatalf("log missing trace_sampled: %s", log)
	}
}

func TestTraceLogHandlerSkipsTraceFieldsWithoutSpan(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(slog.NewJSONHandler(&output, nil))

	logger.InfoContext(context.Background(), "hello")

	log := output.String()
	if strings.Contains(log, "trace_id") || strings.Contains(log, "span_id") {
		t.Fatalf("log unexpectedly has trace fields: %s", log)
	}
}

func TestContextLogAttrsUseStandardInfoContext(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(slog.NewJSONHandler(&output, nil))
	traceID := trace.TraceID{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30}
	spanID := trace.SpanID{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	ctx := ContextWithLogAttrs(context.Background(), "tenant_id", "tenant-1")
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	}))

	logger.InfoContext(ctx, "hello", "workspace_id", "workspace-1")

	log := output.String()
	for _, want := range []string{
		`"tenant_id":"tenant-1"`,
		`"workspace_id":"workspace-1"`,
		`"trace_id":"2122232425262728292a2b2c2d2e2f30"`,
		`"span_id":"3132333435363738"`,
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("log missing %s: %s", want, log)
		}
	}
}

func TestContextLogAttrsAccumulate(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(slog.NewJSONHandler(&output, nil))
	ctx := ContextWithLogAttrs(context.Background(), "tenant_id", "tenant-1")
	ctx = ContextWithLogAttrs(ctx, slog.String("workspace_id", "workspace-1"))

	logger.InfoContext(ctx, "hello")

	log := output.String()
	for _, want := range []string{
		`"tenant_id":"tenant-1"`,
		`"workspace_id":"workspace-1"`,
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("log missing %s: %s", want, log)
		}
	}
}

func TestLoggerWithContextSnapshotsAttrsAndTraceFields(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(slog.NewJSONHandler(&output, nil))
	traceID := trace.TraceID{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50}
	spanID := trace.SpanID{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58}
	ctx := ContextWithLogAttrs(context.Background(), "tenant_id", "tenant-1")
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	}))

	scoped := LoggerWithContext(ctx, logger)
	scoped.Info("hello", "workspace_id", "workspace-1")

	log := output.String()
	for _, want := range []string{
		`"tenant_id":"tenant-1"`,
		`"workspace_id":"workspace-1"`,
		`"trace_id":"4142434445464748494a4b4c4d4e4f50"`,
		`"span_id":"5152535455565758"`,
		`"trace_sampled":true`,
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("log missing %s: %s", want, log)
		}
	}
}

func TestLoggerWithContextHandlesNilLogger(t *testing.T) {
	if LoggerWithContext(context.Background(), nil) == nil {
		t.Fatal("LoggerWithContext should return a logger")
	}
}

func TestLoggerWithContextHandlesNilContext(t *testing.T) {
	if LoggerWithContext(nil, nil) == nil {
		t.Fatal("LoggerWithContext should return a logger")
	}
}

func TestContextWithLogAttrsNoArgsReturnsContext(t *testing.T) {
	ctx := context.Background()
	if got := ContextWithLogAttrs(ctx); got != ctx {
		t.Fatal("ContextWithLogAttrs with no args should return the original context")
	}
}

func TestSampledLogHandlerDropsInfoForUnsampledTrace(t *testing.T) {
	var output bytes.Buffer
	logger := NewSampledLogger(slog.NewJSONHandler(&output, nil))
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		SpanID:  trace.SpanID{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
	}))

	logger.InfoContext(ctx, "dropped")

	if got := output.String(); got != "" {
		t.Fatalf("unsampled info log was emitted: %s", got)
	}
}

func TestSampledLogHandlerKeepsInfoForSampledTrace(t *testing.T) {
	var output bytes.Buffer
	logger := NewSampledLogger(slog.NewJSONHandler(&output, nil))
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
		SpanID:     trace.SpanID{0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
		TraceFlags: trace.FlagsSampled,
	}))

	logger.InfoContext(ctx, "kept")

	log := output.String()
	if !strings.Contains(log, `"msg":"kept"`) {
		t.Fatalf("sampled info log was not emitted: %s", log)
	}
	if !strings.Contains(log, `"trace_sampled":true`) {
		t.Fatalf("sampled info log missing trace fields: %s", log)
	}
}

func TestSampledLogHandlerKeepsWarnForUnsampledTrace(t *testing.T) {
	var output bytes.Buffer
	logger := NewSampledLogger(slog.NewJSONHandler(&output, nil))
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05},
		SpanID:  trace.SpanID{0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06},
	}))

	logger.WarnContext(ctx, "kept")

	log := output.String()
	if !strings.Contains(log, `"msg":"kept"`) {
		t.Fatalf("unsampled warn log was not emitted: %s", log)
	}
	if !strings.Contains(log, `"trace_sampled":false`) {
		t.Fatalf("unsampled warn log missing trace fields: %s", log)
	}
}

func TestSampledLogHandlerKeepsInfoWithoutTrace(t *testing.T) {
	var output bytes.Buffer
	logger := NewSampledLogger(slog.NewJSONHandler(&output, nil))

	logger.InfoContext(context.Background(), "kept")

	if log := output.String(); !strings.Contains(log, `"msg":"kept"`) {
		t.Fatalf("log without trace was not emitted: %s", log)
	}
}

func TestSampledLogHandlerMinimumLevelCanBeConfigured(t *testing.T) {
	var output bytes.Buffer
	logger := NewSampledLogger(
		slog.NewJSONHandler(&output, nil),
		WithSampledLogMinimumLevel(slog.LevelInfo),
	)
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07},
		SpanID:  trace.SpanID{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08},
	}))

	logger.InfoContext(ctx, "kept")

	if log := output.String(); !strings.Contains(log, `"msg":"kept"`) {
		t.Fatalf("configured minimum level did not keep info log: %s", log)
	}
}

func TestSampledLogHandlerUsesLoggerWithContextSamplingDecision(t *testing.T) {
	var output bytes.Buffer
	logger := NewSampledLogger(slog.NewJSONHandler(&output, nil))
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09},
		SpanID:  trace.SpanID{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a},
	}))
	scoped := LoggerWithContext(ctx, logger)

	scoped.Info("dropped")
	if got := output.String(); got != "" {
		t.Fatalf("context-less unsampled info log was emitted: %s", got)
	}

	scoped.Warn("kept")
	log := output.String()
	if !strings.Contains(log, `"msg":"kept"`) {
		t.Fatalf("context-less unsampled warn log was not emitted: %s", log)
	}
	if !strings.Contains(log, `"trace_sampled":false`) {
		t.Fatalf("context-less warn log missing sampled decision: %s", log)
	}
}
