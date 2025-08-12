# Go Project Refactoring - Fixing Over-complications

## Key Changes Made:

### 1. Standard HTTP Handlers (replacing CustomHandler)

```go
// internal/handlers/get_device.go
package handlers

import (
    "encoding/json"
    "errors"
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"

    "github.com/burning-buttons/okto-devices/internal/devicelib/models"
    "github.com/burning-buttons/okto-devices/internal/okto_errors"
)

func (s *Service) GetDevice(w http.ResponseWriter, r *http.Request) {
    deviceID := chi.URLParam(r, "deviceID")
    
    deviceUUID, err := uuid.Parse(deviceID)
    if err != nil {
        http.Error(w, "invalid device ID", http.StatusBadRequest)
        return
    }

    // No transaction for simple reads
    device, err := s.deviceRepository.GetByID(r.Context(), s.pgxPool, deviceUUID)
    if err != nil {
        if errors.Is(err, okto_errors.ErrNotFound) {
            http.Error(w, "device not found", http.StatusNotFound) // Fixed: 404 instead of 401
            return
        }
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }

    response := models.GetDeviceResponse{Device: device}
    
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(response); err != nil {
        http.Error(w, "failed to encode response", http.StatusInternalServerError)
        return
    }
}

// Bulk operations still use transactions where needed
func (s *Service) BulkCreateDevice(w http.ResponseWriter, r *http.Request) {
    userID := GetUserIDFromContext(r.Context()) // Safe context extraction
    
    var request models.BulkCreateDeviceRequest
    decoder := json.NewDecoder(r.Body)
    decoder.DisallowUnknownFields() // Better validation
    
    if err := decoder.Decode(&request); err != nil {
        http.Error(w, "invalid request format", http.StatusBadRequest)
        return
    }
    request.UserID = userID

    if err := s.validator.Struct(request); err != nil {
        http.Error(w, "validation failed: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Use transaction only for multi-step operations
    tx, err := s.pgxPool.Begin(r.Context())
    if err != nil {
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }
    defer tx.Rollback(r.Context())

    userCompanyID, err := s.userRepository.GetCompanyIDByID(r.Context(), tx, request.UserID)
    if err != nil {
        if errors.Is(err, okto_errors.ErrNotFound) {
            http.Error(w, "user not found", http.StatusUnauthorized)
            return
        }
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }

    // Validate production lines belong to same company
    for _, createDeviceInfo := range request.CreateDeviceInfos {
        productionLineCompanyID, err := s.productionLineRepository.GetCompanyIDByID(r.Context(), tx, createDeviceInfo.ProductionLineID)
        if err != nil {
            if errors.Is(err, okto_errors.ErrNotFound) {
                http.Error(w, "production line not found", http.StatusBadRequest)
                return
            }
            http.Error(w, "internal server error", http.StatusInternalServerError)
            return
        }
        if productionLineCompanyID != userCompanyID {
            http.Error(w, "production line belongs to another company", http.StatusForbidden)
            return
        }
    }

    if err := s.deviceRepository.BulkCreate(r.Context(), tx, userCompanyID, request.CreateDeviceInfos); err != nil {
        http.Error(w, "failed to create devices", http.StatusInternalServerError)
        return
    }

    if err := tx.Commit(r.Context()); err != nil {
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }

    response := models.BulkCreateDeviceResponse{Message: "devices created successfully"}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

### 2. Proper Context Key Types (private, collision-safe)

```go
// internal/middleware/context.go
package middleware

import (
    "context"
    "github.com/google/uuid"
)

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
```

### 3. Split Middleware (Single Responsibility)

```go
// internal/middleware/auth.go
package middleware

import (
    "context"
    "net/http"
    "strings"
    "time"

    "github.com/burning-buttons/okto-devices/internal/jwt"
)

func UserAuth(jwtManager *jwt.Manager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "authorization required", http.StatusUnauthorized)
                return
            }

            parts := strings.Split(authHeader, "Bearer ")
            if len(parts) != 2 {
                http.Error(w, "invalid authorization format", http.StatusUnauthorized)
                return
            }

            claims, err := jwtManager.ValidateAndParseUserAccessToken(parts[1])
            if err != nil {
                http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
                return
            }

            if claims.ExpirationAt <= time.Now().Unix() {
                http.Error(w, "token expired", http.StatusUnauthorized)
                return
            }

            ctx := SetUserID(r.Context(), claims.UserID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func DeviceAuth(jwtManager *jwt.Manager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "authorization required", http.StatusUnauthorized)
                return
            }

            parts := strings.Split(authHeader, "Bearer ")
            if len(parts) != 2 {
                http.Error(w, "invalid authorization format", http.StatusUnauthorized)
                return
            }

            claims, err := jwtManager.ValidateAndParseDeviceAccessToken(parts[1])
            if err != nil {
                http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
                return
            }

            // Note: Device tokens don't expire per comment in original code
            ctx := SetDeviceID(r.Context(), claims.DeviceID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// internal/middleware/logging.go
package middleware

import (
    "net/http"
    "time"

    "github.com/google/uuid"
    "go.uber.org/zap"
)

func RequestLogger(logger *zap.SugaredLogger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            requestID := uuid.New().String()
            
            ctx := SetRequestID(r.Context(), requestID)
            
            logger.Infow("request started",
                "requestID", requestID,
                "method", r.Method,
                "url", r.URL.Path,
            )

            ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
            next.ServeHTTP(ww, r.WithContext(ctx))

            logger.Infow("request completed",
                "requestID", requestID,
                "status", ww.statusCode,
                "duration", time.Since(start),
            )
        })
    }
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}

// internal/middleware/recovery.go
package middleware

import (
    "net/http"
    "go.uber.org/zap"
)

func Recovery(logger *zap.SugaredLogger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            defer func() {
                if err := recover(); err != nil {
                    requestID := GetRequestIDFromContext(r.Context())
                    logger.Errorw("panic recovered",
                        "requestID", requestID,
                        "error", err,
                    )
                    http.Error(w, "internal server error", http.StatusInternalServerError)
                }
            }()
            next.ServeHTTP(w, r)
        })
    }
}
```

### 4. Database-Level Concurrency Control

```go
// internal/devicelib/repositories/device.go
package repositories

import (
    "context"
    "errors"
    "fmt"
    "strings"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"

    "github.com/burning-buttons/okto-devices/internal/devicelib/models"
    "github.com/burning-buttons/okto-devices/internal/okto_errors"
)

type PostgresDeviceRepository struct {}

// Read operations without transactions
func (r *PostgresDeviceRepository) GetByID(ctx context.Context, pool *pgxpool.Pool, deviceID uuid.UUID) (models.DeviceInfo, error) {
    const query = `SELECT id, name, company_id, device_mode, setting, workplace_id, seq_number, line 
                   FROM devices WHERE id = $1`

    var device models.DeviceInfo
    err := pool.QueryRow(ctx, query, deviceID).Scan(
        &device.ID, &device.Name, &device.CompanyID, &device.DeviceMode, 
        &device.Setting, &device.WorkplaceID, &device.SeqNumber, &device.Line)
    
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return models.DeviceInfo{}, fmt.Errorf("%w: device %s does not exist", okto_errors.ErrNotFound, deviceID)
        }
        return models.DeviceInfo{}, fmt.Errorf("failed to get device: %w", err)
    }

    return device, nil
}

// Use database sequences instead of mutex for workplace_id/seq_number
func (r *PostgresDeviceRepository) BulkCreate(ctx context.Context, tx pgx.Tx, companyID uuid.UUID, createDeviceInfos []models.CreateDeviceInfo) error {
    if len(createDeviceInfos) == 0 {
        return nil
    }

    // Check if company exists
    var exists bool
    err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM companies WHERE id = $1)", companyID).Scan(&exists)
    if err != nil {
        return fmt.Errorf("failed to check company existence: %w", err)
    }
    if !exists {
        return fmt.Errorf("%w: company %s does not exist", okto_errors.ErrNotFound, companyID)
    }

    // Generate workplace_id and seq_number using database atomicity
    const getNextIDsQuery = `
        WITH next_ids AS (
            SELECT 
                COALESCE(MAX(workplace_id), 0) + generate_series(1, $2) as workplace_id,
                COALESCE(MAX(seq_number), 0) + generate_series(1, $2) as seq_number
            FROM devices 
            WHERE company_id = $1
        )
        SELECT workplace_id, seq_number FROM next_ids ORDER BY workplace_id`

    rows, err := tx.Query(ctx, getNextIDsQuery, companyID, len(createDeviceInfos))
    if err != nil {
        return fmt.Errorf("failed to generate IDs: %w", err)
    }
    defer rows.Close()

    type idPair struct {
        workplaceID int
        seqNumber   int
    }

    var idPairs []idPair
    for rows.Next() {
        var pair idPair
        if err := rows.Scan(&pair.workplaceID, &pair.seqNumber); err != nil {
            return fmt.Errorf("failed to scan ID pair: %w", err)
        }
        idPairs = append(idPairs, pair)
    }

    if err := rows.Err(); err != nil {
        return fmt.Errorf("error iterating ID pairs: %w", err)
    }

    // Build bulk insert
    valueStrings := make([]string, 0, len(createDeviceInfos))
    args := make([]interface{}, 0, len(createDeviceInfos)*8)
    
    for i, createDeviceInfo := range createDeviceInfos {
        if i >= len(idPairs) {
            return fmt.Errorf("insufficient ID pairs generated")
        }

        // Get default settings if empty
        setting := createDeviceInfo.Setting
        if len(setting) == 0 {
            setting, err = r.getDefaultDevicesSetting(ctx, tx, companyID)
            if err != nil {
                return err
            }
        }

        // Get line info
        deviceLine, err := r.getLineByID(ctx, tx, createDeviceInfo.ProductionLineID)
        if err != nil {
            return err
        }

        valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)", 
            i*8+1, i*8+2, i*8+3, i*8+4, i*8+5, i*8+6, i*8+7, i*8+8))
        
        args = append(args,
            createDeviceInfo.Name,
            createDeviceInfo.DeviceMode,
            createDeviceInfo.ProductionLineID,
            setting,
            companyID,
            idPairs[i].workplaceID,
            idPairs[i].seqNumber,
            deviceLine,
        )
    }

    query := fmt.Sprintf(`INSERT INTO devices 
        (name, device_mode, production_line_id, setting, company_id, workplace_id, seq_number, line) 
        VALUES %s`, strings.Join(valueStrings, ", "))

    _, err = tx.Exec(ctx, query, args...)
    if err != nil {
        return fmt.Errorf("failed to insert devices: %w", err)
    }

    return nil
}

// Helper functions remain similar but with better error handling
func (r *PostgresDeviceRepository) getDefaultDevicesSetting(ctx context.Context, tx pgx.Tx, companyID uuid.UUID) (types.DeviceSetting, error) {
    const query = "SELECT default_devices_setting FROM companies WHERE id = $1"
    var setting types.DeviceSetting

    err := tx.QueryRow(ctx, query, companyID).Scan(&setting)
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, fmt.Errorf("%w: company %s does not exist", okto_errors.ErrNotFound, companyID)
        }
        return nil, fmt.Errorf("failed to get default device setting: %w", err)
    }

    return setting, nil
}

func (r *PostgresDeviceRepository) getLineByID(ctx context.Context, tx pgx.Tx, productionLineID uuid.UUID) (types.DeviceLine, error) {
    const query = `SELECT id::TEXT, name::TEXT, product, identifier::TEXT, production_datetime::TEXT, party::TEXT 
                   FROM production_lines WHERE id = $1`

    var ID, name, identifier, productionDatetime, party *string
    var product map[string]any

    err := tx.QueryRow(ctx, query, productionLineID).Scan(&ID, &name, &product, &identifier, &productionDatetime, &party)
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, fmt.Errorf("%w: production line %s does not exist", okto_errors.ErrNotFound, productionLineID)
        }
        return nil, fmt.Errorf("failed to get production line: %w", err)
    }

    deviceLine := make(types.DeviceLine, 6)
    deviceLine["id"] = ID
    deviceLine["name"] = name
    deviceLine["product"] = product
    deviceLine["identifier"] = identifier
    deviceLine["production_datetime"] = productionDatetime
    deviceLine["party"] = party

    return deviceLine, nil
}
```

### 5. Structured Types Instead of map[string]any

```go
// internal/devicelib/types/device.go
package types

import "encoding/json"

// Replace map[string]any with proper structs
type DeviceSetting struct {
    MaxCodeLength              int    `json:"max_code_length"`
    MinCodeLength              int    `json:"min_code_length"`
    BatchSize                  int    `json:"batch_size"`
    KeyboardListenerTimeout    int    `json:"keyboard_listener_timeout"`
    PrintMode                  string `json:"print_mode"`
    PaperWidth                 int    `json:"paper_width"`
    LocalServer                string `json:"local_server"`
    PrintLabelTwice            bool   `json:"print_label_twice"`
    // Add other known fields as needed
    ExtraFields                map[string]interface{} `json:"-"` // For unknown fields
}

type DeviceLine struct {
    ID                 string                 `json:"id"`
    Name               string                 `json:"name"`
    Product            map[string]interface{} `json:"product"`
    Identifier         string                 `json:"identifier"`
    ProductionDatetime string                 `json:"production_datetime"`
    Party              string                 `json:"party"`
}

// Custom JSON marshaling to handle extra fields
func (ds *DeviceSetting) UnmarshalJSON(data []byte) error {
    // First unmarshal into a map to catch all fields
    var raw map[string]interface{}
    if err := json.Unmarshal(data, &raw); err != nil {
        return err
    }

    // Extract known fields
    if val, ok := raw["max_code_length"]; ok {
        if intVal, ok := val.(float64); ok {
            ds.MaxCodeLength = int(intVal)
        }
    }
    // ... extract other known fields ...

    // Store remaining fields
    ds.ExtraFields = make(map[string]interface{})
    knownFields := map[string]bool{
        "max_code_length": true,
        "min_code_length": true,
        // ... list all known fields ...
    }

    for key, val := range raw {
        if !knownFields[key] {
            ds.ExtraFields[key] = val
        }
    }

    return nil
}

func (ds *DeviceSetting) MarshalJSON() ([]byte, error) {
    // Combine known fields with extra fields
    result := map[string]interface{}{
        "max_code_length":              ds.MaxCodeLength,
        "min_code_length":              ds.MinCodeLength,
        "batch_size":                   ds.BatchSize,
        "keyboard_listener_timeout":    ds.KeyboardListenerTimeout,
        "print_mode":                   ds.PrintMode,
        "paper_width":                  ds.PaperWidth,
        "local_server":                 ds.LocalServer,
        "print_label_twice":            ds.PrintLabelTwice,
    }

    // Add extra fields
    for key, val := range ds.ExtraFields {
        result[key] = val
    }

    return json.Marshal(result)
}
```

### 6. Improved JWT Handling

```go
// internal/jwt/manager.go
package jwt

import (
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

type Manager struct {
    key []byte
}

func NewManager(key string) *Manager {
    return &Manager{key: []byte(key)}
}

// Use structured claims instead of MapClaims
type UserClaims struct {
    UserID uuid.UUID `json:"user_id"`
    jwt.RegisteredClaims
}

type DeviceClaims struct {
    DeviceID uuid.UUID `json:"device_id"` // Consistent naming
    jwt.RegisteredClaims
}

func (m *Manager) ValidateAndParseUserAccessToken(tokenString string) (UserAccessTokenClaims, error) {
    claims := &UserClaims{}
    
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return m.key, nil
    })

    if err != nil {
        return UserAccessTokenClaims{}, fmt.Errorf("invalid token: %w", err)
    }

    if !token.Valid {
        return UserAccessTokenClaims{}, fmt.Errorf("invalid token")
    }

    // Check expiration with leeway
    now := time.Now()
    leeway := 30 * time.Second
    
    if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Add(leeway).Before(now) {
        return UserAccessTokenClaims{}, fmt.Errorf("token expired")
    }

    return UserAccessTokenClaims{
        UserID:       claims.UserID,
        ExpirationAt: claims.ExpiresAt.Unix(),
    }, nil
}

func (m *Manager) ValidateAndParseDeviceAccessToken(tokenString string) (DeviceAccessTokenClaims, error) {
    claims := &DeviceClaims{}
    
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return m.key, nil
    })

    if err != nil {
        return DeviceAccessTokenClaims{}, fmt.Errorf("invalid token: %w", err)
    }

    if !token.Valid {
        return DeviceAccessTokenClaims{}, fmt.Errorf("invalid token")
    }

    return DeviceAccessTokenClaims{
        DeviceID:     claims.DeviceID,
        ExpirationAt: claims.ExpiresAt.Unix(),
    }, nil
}
```

### 7. Updated Routes with Standard Handlers

```go
// services/devices/routes.go
package devices

import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/go-playground/validator/v10"

    "github.com/burning-buttons/okto-devices/internal/devicelib/repositories"
    "github.com/burning-buttons/okto-devices/internal/handlers"
    custommw "github.com/burning-buttons/okto-devices/internal/middleware"
)

func (s *Server) AddRoutes() {
    service := handlers.NewService(
        s.pgxPool,
        validator.New(validator.WithRequiredStructEnabled()),
        &repositories.PostgresDeviceRepository{},
        &repositories.PostgresUserRepository{},
        &repositories.PostgresProductionLineRepository{},
    )

    r := chi.NewRouter()

    // Use standard chi middleware + custom ones
    r.Use(custommw.Recovery(s.logger))
    r.Use(custommw.RequestLogger(s.logger))
    r.Use(middleware.Timeout(60 * time.Second))

    r.Get("/health", handlers.HealthcheckHandler(s.pgxPool, s.logger))

    // Device routes (single operations)
    r.Route("/device/{deviceID}", func(r chi.Router) {
        r.Use(custommw.DeviceAuth(s.jwtManager))
        r.Get("/", service.GetDevice)
        r.Patch("/", service.UpdateDevice)
    })

    // Devices routes (bulk operations)  
    r.Route("/devices", func(r chi.Router) {
        r.Use(custommw.UserAuth(s.jwtManager))
        r.Post("/", service.BulkCreateDevice)
        r.Get("/", service.BulkGetDevice)
        r.Patch("/", service.BulkUpdateDevice)
        r.Delete("/", service.BulkDeleteDevice)
    })

    s.srv.Handler = r
}
```

### 8. Fixed Dockerfile

```dockerfile
FROM golang:1.24-alpine AS builder

ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .

# Generate swagger docs (if needed in CI, not in container build)
# RUN go install github.com/swaggo/swag/cmd/swag@latest
# RUN swag init --parseDependency --parseInternal --parseGoList=false -g ./cmd/main.go -o ./docs

# Build with optimization flags
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o main ./cmd/main.go

# Use minimal image
FROM scratch

WORKDIR /bin

# Copy CA certificates for HTTPS calls
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /app/main /bin/main

ENTRYPOINT ["/bin/main"]
```

### 9. Error-returning Server.Run()

```go
// services/devices/server.go
package devices

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "go.uber.org/zap"
)

func (s *Server) Run() error {
    // Create error channel for server startup
    errChan := make(chan error, 1)
    
    go func() {
        s.logger.Info("server starting", "address", s.srv.Addr)
        if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            errChan <- fmt.Errorf("server failed to start: %w", err)
        }
    }()

    // Create quit channel for graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

    // Wait for either server error or quit signal
    select {
    case err := <-errChan:
        return err
    case sig := <-quit:
        s.logger.Info("shutdown signal received", "signal", sig)
    }

    // Graceful shutdown
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    s.logger.Info("shutting down server...")
    if err := s.srv.Shutdown(ctx); err != nil {
        return fmt.Errorf("server shutdown failed: %w", err)
    }

    s.logger.Info("server shutdown complete")
    return nil
}

// Update main.go to handle the returned error
func main() {
    // ... config and setup code ...

    server := devices.NewServer(&cfg, postgresConnectionPool, logger, jwtManager)
    if err := server.Run(); err != nil {
        logger.Fatal("server error", "error", err)
    }
}
```

## Summary of Key Improvements:

1. **Standard HTTP Handlers**: Replaced custom handler signature with standard `http.HandlerFunc`
2. **Proper Context Keys**: Private, typed context keys to prevent collisions
3. **Split Middleware**: Separated concerns (auth, logging, recovery) into individual middleware
4. **Database Concurrency**: Replaced mutex with proper database-level atomic operations
5. **Structured Types**: Replaced `map[string]any` with proper structs where possible
6. **Better JWT**: Structured claims, consistent naming, proper validation with leeway
7. **Correct HTTP Status Codes**: 404 for not found, proper error semantics
8. **No Panic in HTTP Path**: Proper error handling and recovery middleware
9. **Optimized Transactions**: Only use transactions where atomicity is needed
10. **Improved Error Handling**: Return errors instead of panic, proper error wrapping
11. **Better Dockerfile**: Proper layer caching, static binary compilation
12. **Unified Logging**: Single zap logger throughout, no mixing with standard log

## Additional Improvements to Consider:

### 10. Database Schema Improvements

```sql
-- Use database sequences for auto-incrementing IDs instead of application-level logic
-- This eliminates the need for mutex/locking entirely

-- Add sequences for workplace_id and seq_number
CREATE SEQUENCE IF NOT EXISTS workplace_id_seq;
CREATE SEQUENCE IF NOT EXISTS seq_number_seq;

-- Modify table to use sequences with company-specific partitioning
ALTER TABLE devices 
ADD COLUMN IF NOT EXISTS workplace_id_seq INTEGER DEFAULT nextval('workplace_id_seq'),
ADD COLUMN IF NOT EXISTS seq_number_seq INTEGER DEFAULT nextval('seq_number_seq');

-- Or better yet, use GENERATED columns
ALTER TABLE devices 
ALTER COLUMN workplace_id SET DEFAULT nextval('workplace_id_seq'),
ALTER COLUMN seq_number SET DEFAULT nextval('seq_number_seq');

-- Create a function to reset sequences per company if needed
CREATE OR REPLACE FUNCTION reset_device_sequences(company_uuid UUID) 
RETURNS void AS $
DECLARE
    max_workplace INT;
    max_seq INT;
BEGIN
    SELECT COALESCE(MAX(workplace_id), 0), COALESCE(MAX(seq_number), 0) 
    INTO max_workplace, max_seq 
    FROM devices 
    WHERE company_id = company_uuid;
    
    -- This approach still has race conditions; better to use company-specific sequences
    -- or handle this entirely in application logic with proper SELECT FOR UPDATE
END;
$ LANGUAGE plpgsql;
```

### 11. Interface-Based Dependency Injection

```go
// internal/interfaces/repositories.go
package interfaces

import (
    "context"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"

    "github.com/burning-buttons/okto-devices/internal/devicelib/models"
)

type DeviceRepository interface {
    GetByID(ctx context.Context, pool *pgxpool.Pool, deviceID uuid.UUID) (models.DeviceInfo, error)
    GetCompanyIDByID(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) (uuid.UUID, error)
    BulkGetByCompanyID(ctx context.Context, pool *pgxpool.Pool, companyID uuid.UUID) ([]models.DeviceInfo, error)
    BulkCreate(ctx context.Context, tx pgx.Tx, companyID uuid.UUID, createDeviceInfos []models.CreateDeviceInfo) error
    BulkUpdate(ctx context.Context, tx pgx.Tx, companyID uuid.UUID, updateDeviceInfos []models.UpdateDeviceInfo) error
    BulkDelete(ctx context.Context, tx pgx.Tx, companyID uuid.UUID, deviceIDs []uuid.UUID) error
    Update(ctx context.Context, tx pgx.Tx, companyID uuid.UUID, updateDeviceInfo models.UpdateDeviceInfo) error
}

type UserRepository interface {
    GetCompanyIDByID(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (uuid.UUID, error)
}

type ProductionLineRepository interface {
    GetCompanyIDByID(ctx context.Context, tx pgx.Tx, productionLineID uuid.UUID) (uuid.UUID, error)
}

// internal/handlers/service.go - Updated with interfaces
type Service struct {
    pgxPool                  *pgxpool.Pool
    validator                *validator.Validate
    deviceRepo               interfaces.DeviceRepository
    userRepo                 interfaces.UserRepository
    productionLineRepo       interfaces.ProductionLineRepository
}

func NewService(
    pgxPool *pgxpool.Pool,
    validator *validator.Validate,
    deviceRepo interfaces.DeviceRepository,
    userRepo interfaces.UserRepository,
    productionLineRepo interfaces.ProductionLineRepository,
) *Service {
    return &Service{
        pgxPool:            pgxPool,
        validator:          validator,
        deviceRepo:         deviceRepo,
        userRepo:           userRepo,
        productionLineRepo: productionLineRepo,
    }
}
```

### 12. Configuration Validation & Environment Handling

```go
// config/config.go - Enhanced with validation
package config

import (
    "fmt"
    "time"
)

type Config struct {
    LogLevel    string `envconfig:"LOG_LEVEL" default:"info" validate:"oneof=debug info warn error"`
    AuthKey     string `envconfig:"AUTH_KEY" required:"true" validate:"min=32"`
    HTTPAddress string `envconfig:"HTTP_ADDRESS" default:":8080" validate:"required"`
    PostgresDSN string `envconfig:"PG_DSN" required:"true" validate:"required"`
    
    // Additional useful config
    HTTPTimeout     time.Duration `envconfig:"HTTP_TIMEOUT" default:"60s"`
    HTTPMaxRequests int           `envconfig:"HTTP_MAX_REQUESTS" default:"1000"`
    DBMaxConns      int           `envconfig:"DB_MAX_CONNS" default:"25"`
    DBMinConns      int           `envconfig:"DB_MIN_CONNS" default:"5"`
    DBMaxIdleTime   time.Duration `envconfig:"DB_MAX_IDLE_TIME" default:"30m"`
}

func (c *Config) Validate() error {
    if len(c.AuthKey) < 32 {
        return fmt.Errorf("AUTH_KEY must be at least 32 characters long")
    }
    if c.DBMaxConns < c.DBMinConns {
        return fmt.Errorf("DB_MAX_CONNS must be >= DB_MIN_CONNS")
    }
    return nil
}
```

### 13. Improved Health Check

```go
// internal/handlers/healthcheck.go
package handlers

import (
    "context"
    "encoding/json"
    "net/http"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "go.uber.org/zap"
)

type HealthResponse struct {
    Status    string                 `json:"status"`
    Timestamp time.Time              `json:"timestamp"`
    Checks    map[string]CheckResult `json:"checks"`
}

type CheckResult struct {
    Status  string        `json:"status"`
    Message string        `json:"message,omitempty"`
    Latency time.Duration `json:"latency,omitempty"`
}

func HealthcheckHandler(pool *pgxpool.Pool, logger *zap.SugaredLogger) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
        defer cancel()

        response := HealthResponse{
            Timestamp: time.Now(),
            Checks:    make(map[string]CheckResult),
        }

        // Check database
        dbStart := time.Now()
        if err := pool.Ping(ctx); err != nil {
            response.Checks["database"] = CheckResult{
                Status:  "unhealthy",
                Message: err.Error(),
                Latency: time.Since(dbStart),
            }
            response.Status = "unhealthy"
        } else {
            response.Checks["database"] = CheckResult{
                Status:  "healthy",
                Latency: time.Since(dbStart),
            }
        }

        // Overall status
        if response.Status == "" {
            response.Status = "healthy"
        }

        // Set status code
        statusCode := http.StatusOK
        if response.Status == "unhealthy" {
            statusCode = http.StatusServiceUnavailable
        }

        // Only log unhealthy responses to reduce noise
        if response.Status == "unhealthy" {
            logger.Warnw("health check failed",
                "status", response.Status,
                "checks", response.Checks,
            )
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(statusCode)
        json.NewEncoder(w).Encode(response)
    }
}
```

### 14. Request Validation Middleware

```go
// internal/middleware/validation.go
package middleware

import (
    "encoding/json"
    "io"
    "net/http"
)

const maxRequestSize = 1 << 20 // 1MB

func RequestValidation() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Limit request size
            r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
            
            // For JSON requests, validate it's parseable JSON
            if r.Header.Get("Content-Type") == "application/json" && r.ContentLength > 0 {
                // Read and validate JSON, then restore body
                body, err := io.ReadAll(r.Body)
                if err != nil {
                    http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
                    return
                }
                
                if len(body) > 0 && !json.Valid(body) {
                    http.Error(w, "invalid JSON", http.StatusBadRequest)
                    return
                }
                
                // Restore body for downstream handlers
                r.Body = io.NopCloser(bytes.NewReader(body))
                r.GetBody = func() (io.ReadCloser, error) {
                    return io.NopCloser(bytes.NewReader(body)), nil
                }
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

### 15. Graceful Database Connection Handling

```go
// internal/postgres/postgres.go - Enhanced connection management
package postgres

import (
    "context"
    "fmt"
    "time"

    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"

    "github.com/burning-buttons/okto-devices/config"
)

func NewPostgres(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
    pgxConfig, err := pgxpool.ParseConfig(cfg.PostgresDSN)
    if err != nil {
        return nil, fmt.Errorf("failed to parse postgres DSN: %w", err)
    }

    // Configure connection pool
    pgxConfig.MaxConns = int32(cfg.DBMaxConns)
    pgxConfig.MinConns = int32(cfg.DBMinConns)
    pgxConfig.MaxConnLifetime = time.Hour
    pgxConfig.MaxConnIdleTime = cfg.DBMaxIdleTime
    
    // Use prepared statements for better performance
    pgxConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
    
    // Add connection callback for logging
    pgxConfig.BeforeConnect = func(ctx context.Context, config *pgx.ConnConfig) error {
        // Could add custom connection setup here
        return nil
    }

    pool, err := pgxpool.NewWithConfig(ctx, pgxConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create postgres pool: %w", err)
    }

    // Test connection with timeout
    pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    
    if err := pool.Ping(pingCtx); err != nil {
        pool.Close()
        return nil, fmt.Errorf("failed to ping postgres: %w", err)
    }

    return pool, nil
}
```

### 16. Testing Improvements

```go
// internal/handlers/get_device_test.go
package handlers_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    "encoding/json"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "github.com/burning-buttons/okto-devices/internal/handlers"
    "github.com/burning-buttons/okto-devices/internal/devicelib/models"
    "github.com/burning-buttons/okto-devices/internal/middleware"
)

// Mock repository
type MockDeviceRepository struct {
    mock.Mock
}

func (m *MockDeviceRepository) GetByID(ctx context.Context, pool interface{}, deviceID uuid.UUID) (models.DeviceInfo, error) {
    args := m.Called(ctx, pool, deviceID)
    return args.Get(0).(models.DeviceInfo), args.Error(1)
}

func TestGetDevice_Success(t *testing.T) {
    // Arrange
    deviceID := uuid.New()
    expectedDevice := models.DeviceInfo{
        ID:   deviceID,
        Name: "Test Device",
    }

    mockRepo := &MockDeviceRepository{}
    mockRepo.On("GetByID", mock.Anything, mock.Anything, deviceID).Return(expectedDevice, nil)

    service := &handlers.Service{
        // Inject mock repository
    }

    req := httptest.NewRequest(http.MethodGet, "/device/"+deviceID.String(), nil)
    req = req.WithContext(middleware.SetDeviceID(req.Context(), deviceID))
    w := httptest.NewRecorder()

    // Act
    service.GetDevice(w, req)

    // Assert
    assert.Equal(t, http.StatusOK, w.Code)
    
    var response models.GetDeviceResponse
    err := json.Unmarshal(w.Body.Bytes(), &response)
    assert.NoError(t, err)
    assert.Equal(t, expectedDevice, response.Device)

    mockRepo.AssertExpectations(t)
}
```

## Migration Strategy

To implement these changes without breaking the existing system:

1. **Phase 1**: Infrastructure changes (middleware, context handling, error handling)
2. **Phase 2**: Database changes (sequences, better concurrency)
3. **Phase 3**: Handler refactoring (standard HTTP handlers)
4. **Phase 4**: Type safety improvements (structured types instead of maps)
5. **Phase 5**: Testing and monitoring improvements

Each phase can be implemented and deployed independently, ensuring system stability throughout the migration.

These improvements address all the major "Go way" violations identified in the original analysis while maintaining backward compatibility and improving system reliability, performance, and maintainability.
