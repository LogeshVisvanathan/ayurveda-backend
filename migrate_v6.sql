-- ============================================================
-- MIGRATION: Add approval columns to existing users table
-- Run this if you already have an ayurveda_db running and
-- are getting errors like "column u.rejection_note does not exist"
--
-- Run as: psql -U postgres -d ayurveda_db -f migrate_v6.sql
-- ============================================================

-- Add missing columns (safe to run multiple times)
ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT 'pending';
ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_by     UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_at     TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS rejection_note  TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active       BOOLEAN DEFAULT FALSE;

-- Fix existing admins → always approved + active
UPDATE users
SET approval_status = 'approved',
    is_active       = TRUE
WHERE role = 'admin';

-- Grandfather existing users (registered before approval system)
-- Any farmer/lab/consumer with NULL approval_status gets approved automatically
UPDATE users
SET approval_status = 'approved',
    is_active       = TRUE
WHERE role != 'admin'
  AND (approval_status IS NULL OR approval_status = 'pending');

-- Create new tables if they don't exist yet
CREATE TABLE IF NOT EXISTS registration_documents(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    doc_type    VARCHAR(100) NOT NULL,
    doc_label   VARCHAR(255),
    file_url    TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT NOW(),
    verified    BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS user_profiles(
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    land_area_acres   DECIMAL(10,2),
    land_survey_no    VARCHAR(255),
    land_district     VARCHAR(255),
    land_state        VARCHAR(255),
    farming_type      VARCHAR(100),
    lab_name          VARCHAR(255),
    lab_licence_no    VARCHAR(255),
    lab_accreditation VARCHAR(255),
    lab_address       TEXT,
    govt_id_type      VARCHAR(100),
    govt_id_number    VARCHAR(100),
    notes             TEXT,
    updated_at        TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sequence    BIGSERIAL,
    event_type  VARCHAR(100) NOT NULL,
    actor_id    VARCHAR(255),
    entity_type VARCHAR(100),
    entity_id   VARCHAR(255),
    payload     JSONB,
    prev_hash   VARCHAR(64) NOT NULL,
    block_hash  VARCHAR(64) NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL
);

-- Verify
SELECT
    COUNT(*) FILTER (WHERE role = 'admin')    AS admins,
    COUNT(*) FILTER (WHERE role = 'farmer')   AS farmers,
    COUNT(*) FILTER (WHERE role = 'lab')      AS labs,
    COUNT(*) FILTER (WHERE role = 'consumer') AS consumers,
    COUNT(*) FILTER (WHERE approval_status = 'approved') AS approved,
    COUNT(*) FILTER (WHERE approval_status = 'pending')  AS pending
FROM users;

SELECT 'Migration complete! All columns added.' AS result;



 cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        full_name VARCHAR(255), phone VARCHAR(20), address TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS registration_documents(
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    doc_type VARCHAR(100) NOT NULL,
    doc_label VARCHAR(255),
    file_url TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE
);
    CREATE TABLE IF NOT EXISTS user_profiles(
        id UUID PRIMARY KEY,
        user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        land_area_acres DECIMAL(10,2), land_survey_no VARCHAR(255),
        land_district VARCHAR(255), land_state VARCHAR(255), farming_type VARCHAR(100),
        lab_name VARCHAR(255), lab_licence_no VARCHAR(255),
        lab_accreditation VARCHAR(255), lab_address TEXT,
        govt_id_type VARCHAR(100), govt_id_number VARCHAR(100),
        notes TEXT, updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_log(
        id UUID PRIMARY KEY,
        sequence BIGSERIAL, event_type VARCHAR(100) NOT NULL,
        actor_id VARCHAR(255), entity_type VARCHAR(100), entity_id VARCHAR(255),
        payload JSONB, prev_hash VARCHAR(64) NOT NULL,
        block_hash VARCHAR(64) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL
    );
    CREATE TABLE IF NOT EXISTS herb_batches(
        id UUID PRIMARY KEY,
        batch_id VARCHAR(100) UNIQUE NOT NULL, farmer_id UUID REFERENCES users(id),
        herb_species VARCHAR(255) NOT NULL, quantity_kg DECIMAL(10,2),
        moisture_level DECIMAL(5,2), harvest_date DATE, farming_practices TEXT,
        gps_lat DECIMAL(10,8), gps_lng DECIMAL(11,8), location_name VARCHAR(255),
        image_url TEXT, notes TEXT, status VARCHAR(50) DEFAULT 'collected',
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS processing_records(
        id UUID PRIMARY KEY,
        batch_id VARCHAR(100) REFERENCES herb_batches(batch_id),
        processor_id UUID REFERENCES users(id),
        drying_method VARCHAR(100), drying_duration_hours INTEGER,
        drying_temperature DECIMAL(5,2), grinding_status BOOLEAN DEFAULT FALSE,
        grinding_particle_sz VARCHAR(100), storage_temperature DECIMAL(5,2),
        storage_humidity DECIMAL(5,2), storage_location VARCHAR(255),
        chain_of_custody TEXT, notes TEXT, processed_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS lab_tests(
        id UUID PRIMARY KEY,
        batch_id VARCHAR(100) REFERENCES herb_batches(batch_id),
        lab_id UUID REFERENCES users(id),
        moisture_content DECIMAL(5,2), moisture_report_url TEXT,
        pesticide_residue_result VARCHAR(80), pesticide_report_url TEXT,
        dna_auth_result VARCHAR(80), dna_certificate_url TEXT,
        heavy_metal_result VARCHAR(80), microbial_count VARCHAR(100),
        overall_status VARCHAR(50) DEFAULT 'pending',
        tested_by VARCHAR(255), tested_at TIMESTAMP DEFAULT NOW(), notes TEXT
    );
    CREATE TABLE IF NOT EXISTS products(
        id UUID PRIMARY KEY,
        product_id VARCHAR(100) UNIQUE NOT NULL, batch_id VARCHAR(100) REFERENCES herb_batches(batch_id),
        qr_code_data TEXT, product_name VARCHAR(255), description TEXT,
        manufacturing_date DATE, expiry_date DATE, is_public BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS consumer_scans(
        id UUID PRIMARY KEY,
        product_id VARCHAR(100) REFERENCES products(product_id),
        scanned_at TIMESTAMP DEFAULT NOW(), user_agent TEXT, ip_address VARCHAR(50)
    );
    """)
    conn.commit()