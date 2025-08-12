// Private context key types to prevent collisions
type contextKey string

const (
    userIDKey    contextKey = "userID"
    deviceIDKey  contextKey = "deviceID" 
    requestIDKey contextKey = "requestID"
)

// Safe context value setters
func SetUserID(ctx context.Context, userID uuid.UUID) context.Context {
    return context.WithValue(ctx, userIDKey, userID)
}

func SetDeviceID(ctx context.Context, deviceID uuid.UUID) context.Context {
    return context.WithValue(ctx, deviceIDKey, deviceID)
}

func SetRequestID(ctx context.Context, requestID string) context.Context {
    return context.WithValue(ctx, requestIDKey, requestID)
}

// Safe context value getters
func GetUserIDFromContext(ctx context.Context) uuid.UUID {
    if userID, ok := ctx.Value(userIDKey).(uuid.UUID); ok {
        return userID
    }
    return uuid.Nil // Return zero value instead of panicking
}

func GetDeviceIDFromContext(ctx context.Context) uuid.UUID {
    if deviceID, ok := ctx.Value(deviceIDKey).(uuid.UUID); ok {
        return deviceID
    }
    return uuid.Nil
}

func GetRequestIDFromContext(ctx context.Context) string {
    if requestID, ok := ctx.Value(requestIDKey).(string); ok {
        return requestID
    }
    return ""
}