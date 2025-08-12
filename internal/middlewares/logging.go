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