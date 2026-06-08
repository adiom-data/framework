# middleware

`middleware` contains the default HTTP middleware used by `httpapp`.

Use `Default` when you want to compose framework defaults with service-specific
middleware:

```go
stack := append(middleware.Default(logger), cors, addRequestID)

app := httpapp.NewService(
	httpapp.WithServiceMiddleware(stack...),
)
```

The first middleware in a stack is outermost.

Defaults:

- `LogRequests`
- `RecoverPanics`
