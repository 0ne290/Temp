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