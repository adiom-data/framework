package telemetry

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

// TraceLogHandler wraps a slog handler and adds context log attributes and
// trace correlation fields to context-aware log records.
func TraceLogHandler(next slog.Handler) slog.Handler {
	if next == nil {
		next = slog.Default().Handler()
	}
	return traceLogHandler{next: next}
}

// NewLogger returns a slog logger that adds context log attributes and trace
// correlation fields to context-aware log records.
func NewLogger(next slog.Handler) *slog.Logger {
	return slog.New(TraceLogHandler(next))
}

// NewSampledLogger returns a logger that adds trace fields and suppresses
// low-severity records when ctx contains a valid unsampled trace.
func NewSampledLogger(next slog.Handler, opts ...SampledLogOption) *slog.Logger {
	return NewLogger(SampledLogHandler(next, opts...))
}

// DefaultLogger returns the framework structured logger for stdout log
// collection.
func DefaultLogger() *slog.Logger {
	return defaultLogger(os.Stdout)
}

type logAttrsContextKey struct{}

// ContextWithLogAttrs stores logging attributes in ctx. Handlers wrapped with
// TraceLogHandler add those attributes to context-aware log records.
func ContextWithLogAttrs(ctx context.Context, args ...any) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(args) == 0 {
		return ctx
	}
	attrs := append([]slog.Attr{}, logAttrsFromContext(ctx)...)
	attrs = append(attrs, attrsFromArgs(args)...)
	return context.WithValue(ctx, logAttrsContextKey{}, attrs)
}

// LoggerWithContext returns a child logger with the current context log
// attributes and trace correlation fields copied onto the logger. Use this
// when passing a logger to an API that does not accept context at log time.
func LoggerWithContext(ctx context.Context, logger *slog.Logger) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	attrs := attrsFromContext(ctx)
	if len(attrs) == 0 {
		return logger
	}
	return logger.With(attrsToArgs(attrs)...)
}

type traceLogHandler struct {
	next slog.Handler
}

func (h traceLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h traceLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if attrs := attrsFromContext(ctx); len(attrs) > 0 {
		record.AddAttrs(attrs...)
	}
	return h.next.Handle(ctx, record)
}

func (h traceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceLogHandler{next: h.next.WithAttrs(attrs)}
}

func (h traceLogHandler) WithGroup(name string) slog.Handler {
	return traceLogHandler{next: h.next.WithGroup(name)}
}

// SampledLogOption customizes SampledLogHandler.
type SampledLogOption func(*sampledLogConfig)

type sampledLogConfig struct {
	minLevel      slog.Level
	dropUnsampled bool
}

// WithSampledLogMinimumLevel sets the lowest log level that always passes
// through even when ctx contains a valid unsampled trace. The default is Warn.
func WithSampledLogMinimumLevel(level slog.Level) SampledLogOption {
	return func(cfg *sampledLogConfig) {
		cfg.minLevel = level
	}
}

// WithoutUnsampledLogs suppresses every record whose ctx contains a valid
// unsampled trace.
func WithoutUnsampledLogs() SampledLogOption {
	return func(cfg *sampledLogConfig) {
		cfg.dropUnsampled = true
	}
}

// SampledLogHandler wraps a slog handler and suppresses records below Warn when
// ctx contains a valid unsampled trace. Records without trace context, records
// with sampled trace context, and Warn/Error records always pass through.
func SampledLogHandler(next slog.Handler, opts ...SampledLogOption) slog.Handler {
	if next == nil {
		next = slog.Default().Handler()
	}
	cfg := sampledLogConfig{minLevel: slog.LevelWarn}
	for _, opt := range opts {
		opt(&cfg)
	}
	return sampledLogHandler{next: next, cfg: cfg}
}

type sampledLogHandler struct {
	next         slog.Handler
	cfg          sampledLogConfig
	traceSampled *bool
}

func (h sampledLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if !h.shouldLog(ctx, level) {
		return false
	}
	return h.next.Enabled(ctx, level)
}

func (h sampledLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if !h.shouldLog(ctx, record.Level) {
		return nil
	}
	return h.next.Handle(ctx, record)
}

func (h sampledLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if sampled, ok := traceSampledAttr(attrs); ok {
		h.traceSampled = &sampled
	}
	h.next = h.next.WithAttrs(attrs)
	return h
}

func (h sampledLogHandler) WithGroup(name string) slog.Handler {
	h.next = h.next.WithGroup(name)
	return h
}

func (h sampledLogHandler) shouldLog(ctx context.Context, level slog.Level) bool {
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		return h.shouldLogSampledDecision(spanContext.IsSampled(), level)
	}
	if h.traceSampled != nil {
		return h.shouldLogSampledDecision(*h.traceSampled, level)
	}
	return true
}

func (h sampledLogHandler) shouldLogSampledDecision(sampled bool, level slog.Level) bool {
	if sampled {
		return true
	}
	if h.cfg.dropUnsampled {
		return false
	}
	return level >= h.cfg.minLevel
}

func traceSampledAttr(attrs []slog.Attr) (bool, bool) {
	for _, attr := range attrs {
		if attr.Key == "trace_sampled" && attr.Value.Kind() == slog.KindBool {
			return attr.Value.Bool(), true
		}
	}
	return false, false
}

func attrsFromContext(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	attrs := append([]slog.Attr{}, logAttrsFromContext(ctx)...)
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		attrs = append(attrs,
			slog.String("trace_id", spanContext.TraceID().String()),
			slog.String("span_id", spanContext.SpanID().String()),
			slog.Bool("trace_sampled", spanContext.IsSampled()),
		)
	}
	return attrs
}

func logAttrsFromContext(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	attrs, _ := ctx.Value(logAttrsContextKey{}).([]slog.Attr)
	return attrs
}

func attrsFromArgs(args []any) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(args)/2)
	for len(args) > 0 {
		if attr, ok := args[0].(slog.Attr); ok {
			attrs = append(attrs, attr)
			args = args[1:]
			continue
		}
		key, ok := args[0].(string)
		if !ok {
			attrs = append(attrs, slog.Any("!BADKEY", args[0]))
			args = args[1:]
			continue
		}
		if len(args) == 1 {
			attrs = append(attrs, slog.String("!BADKEY", key))
			break
		}
		attrs = append(attrs, slog.Any(key, args[1]))
		args = args[2:]
	}
	return attrs
}

func attrsToArgs(attrs []slog.Attr) []any {
	args := make([]any, 0, len(attrs))
	for _, attr := range attrs {
		args = append(args, attr)
	}
	return args
}

func defaultLogger(output io.Writer) *slog.Logger {
	handlerOptions := &slog.HandlerOptions{}
	if level, ok := logLevelFromEnv("LOG_LEVEL"); ok {
		handlerOptions.Level = level
	}
	handler := slog.NewJSONHandler(output, handlerOptions)
	if opts, ok := unsampledLogOptionsFromEnv(); ok {
		return NewLogger(SampledLogHandler(handler, opts...))
	}
	return NewLogger(handler)
}

func unsampledLogOptionsFromEnv() ([]SampledLogOption, bool) {
	value := strings.TrimSpace(os.Getenv("LOG_UNSAMPLED_MIN_LEVEL"))
	if value == "" {
		return nil, false
	}
	if strings.EqualFold(value, "off") || strings.EqualFold(value, "none") || strings.EqualFold(value, "disabled") {
		return []SampledLogOption{WithoutUnsampledLogs()}, true
	}
	level, ok := parseLogLevel(value)
	if !ok {
		return nil, false
	}
	return []SampledLogOption{WithSampledLogMinimumLevel(level)}, true
}

func logLevelFromEnv(name string) (slog.Level, bool) {
	return parseLogLevel(os.Getenv(name))
}

func parseLogLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return 0, false
	}
}
