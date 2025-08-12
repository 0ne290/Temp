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