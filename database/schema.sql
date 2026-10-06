-- 1. Table des paquets individuels capturés
CREATE TABLE IF NOT EXISTS packets (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(20) NOT NULL,
    length INT NOT NULL,
    country VARCHAR(10),
    org TEXT,
    human_explanation TEXT
);

-- 2. Table des communications / sessions regroupées
CREATE TABLE IF NOT EXISTS communications (
    id BIGSERIAL PRIMARY KEY,
    session_key VARCHAR(100) UNIQUE NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(20) NOT NULL,
    packet_count INT DEFAULT 1,
    total_bytes BIGINT DEFAULT 0,
    start_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'ACTIVE'
);

-- 3. Table des alertes et comportements inhabituels
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45),
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    message TEXT NOT NULL
);
