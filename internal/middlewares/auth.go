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