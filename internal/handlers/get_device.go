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