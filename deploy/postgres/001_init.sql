create table if not exists policy_snapshots (
    version text primary key,
    generated_at timestamptz not null,
    payload jsonb not null
);

create table if not exists node_sessions (
    node_id text primary key,
    last_seen_at timestamptz not null,
    payload jsonb not null
);

create table if not exists captured_requests (
    request_id uuid primary key,
    observed_at timestamptz not null,
    lane text not null,
    payload jsonb not null
);

create table if not exists artifacts (
    artifact_key text primary key,
    status text not null,
    payload jsonb not null
);

create table if not exists artifact_blobs (
    artifact_key text not null,
    domain text not null,
    payload jsonb not null,
    primary key (artifact_key, domain)
);

create table if not exists quarantine_jobs (
    job_id uuid not null,
    artifact_key text primary key,
    status text not null,
    payload jsonb not null
);

create table if not exists lab_runs (
    run_id uuid primary key,
    artifact_key text not null,
    status text not null,
    payload jsonb not null
);

create table if not exists evidence_records (
    evidence_id uuid primary key,
    artifact_key text not null,
    payload jsonb not null
);

create table if not exists feed_records (
    feed_id uuid primary key,
    first_seen_at timestamptz not null,
    payload jsonb not null
);

create index if not exists idx_captured_requests_observed_at
    on captured_requests (observed_at desc);

create index if not exists idx_feed_records_first_seen_at
    on feed_records (first_seen_at desc);
