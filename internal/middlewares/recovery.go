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