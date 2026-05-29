-- Initialize Canara Bank SuRaksha PostgreSQL Schemas

CREATE TYPE user_role AS ENUM ('ADMIN', 'ANALYST', 'AUDITOR');
CREATE TYPE underwriting_verdict AS ENUM ('APPROVE', 'MANUAL_REVIEW', 'HIGH_RISK_INVESTIGATION', 'REJECT');
CREATE TYPE task_status AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED');

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'ANALYST',
    mfa_secret VARCHAR(100),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts INT DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS underwriting_cases (
    case_id VARCHAR(100) PRIMARY KEY,
    account_number VARCHAR(50) NOT NULL,
    applicant_name VARCHAR(150) NOT NULL,
    document_hash VARCHAR(64) UNIQUE NOT NULL,
    forgery_score INT NOT NULL,
    verdict underwriting_verdict NOT NULL DEFAULT 'MANUAL_REVIEW',
    explainable_reasoning TEXT NOT NULL,
    audited_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rbi_compliance_scorecard (
    control_id VARCHAR(50) PRIMARY KEY,
    directive_ref VARCHAR(100) NOT NULL,
    requirement TEXT NOT NULL,
    department VARCHAR(100) NOT NULL,
    status task_status NOT NULL DEFAULT 'PENDING',
    risk_score INT NOT NULL,
    remediation TEXT,
    validated_at TIMESTAMP WITH TIME ZONE
);

-- Pre-populate RBI direct guidelines
INSERT INTO rbi_compliance_scorecard (control_id, directive_ref, requirement, department, status, risk_score, remediation) VALUES
('RBI-DPS-3.1', 'RBI-2021-01 (Sec. 3.2)', 'Implement multi-factor authentication (MFA) with dynamic OTP bindings for all banking transfers exceeding INR 10,000.', 'CORE_BANKING', 'PENDING', 10, 'Enforce out-of-band transaction signature token confirmation.'),
('RBI-DPS-4.2', 'RBI-2021-02 (Sec. 4.5)', 'Enforce device fingerprinting and binding to prevent parallel login sessions across geographic coordinates.', 'IT_INFRASTRUCTURE', 'PENDING', 45, 'Verify mobile application emulator block profiles.'),
('RBI-DPS-6.1', 'RBI-2021-03 (Sec. 6.1)', 'Deploy continuous behavioral biometrics (keystroke timing, typing speeds) to identify non-human robotic session execution.', 'INFORMATION_SECURITY', 'PENDING', 15, 'Calculate keyboard latency baseline deviations.'),
('RBI-DPS-7.3', 'RBI-2021-04 (Sec. 7.2)', 'Verify identity transitions and enforce the four-eyes dual-clerk approval rule for teller actions exceeding 25 Lakhs.', 'OPERATIONS', 'PENDING', 95, 'Lock teller session and prompt manager approval verification.'),
('RBI-DPS-8.4', 'RBI-2021-05 (Sec. 8.4)', 'Check metadata integrity and conduct automated signature integrity tests on uploaded land and collateral documents.', 'AUDIT', 'PENDING', 88, 'Run local metadata forensic and font alignment checkers.')
ON CONFLICT (control_id) DO NOTHING;
