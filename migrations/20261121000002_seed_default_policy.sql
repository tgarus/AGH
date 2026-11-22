-- Seed baseline scan policy so fresh deployments have a safe default profile.

INSERT INTO scan_policies (
    name,
    port_spec,
    discovery_tool,
    rate_pps,
    per_ip_cooldown_ms,
    subnet_concurrency,
    kill_grace_seconds,
    inactivity_threshold,
    tarpit_port_threshold,
    enable_nuclei,
    time_windows
)
VALUES (
    'default-balanced',
    'top-1000',
    'naabu',
    500,
    250,
    4,
    3,
    3,
    200,
    FALSE,
    '{
        "allowed_windows": [
            { "start": "00:00", "end": "23:59", "timezone": "Europe/Warsaw" }
        ],
        "sampling_slots": ["00_06", "06_12", "12_18", "18_24"]
    }'::jsonb
)
ON CONFLICT (name) DO NOTHING;
