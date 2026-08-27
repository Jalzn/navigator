CREATE TABLE authority_policies (
    participant_id TEXT PRIMARY KEY NOT NULL REFERENCES participants(participant_id),
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    snapshot BLOB NOT NULL
);

CREATE TABLE authority_grants (
    grant_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    subject_participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    snapshot BLOB NOT NULL
);

CREATE TABLE authority_template_policies (
    template_id TEXT PRIMARY KEY NOT NULL REFERENCES templates(template_id),
    snapshot BLOB NOT NULL
);
