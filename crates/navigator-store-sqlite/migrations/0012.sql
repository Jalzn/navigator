ALTER TABLE sessions
ADD COLUMN compatibility_manifest_complete INTEGER NOT NULL DEFAULT 0
CHECK (compatibility_manifest_complete IN (0, 1));

ALTER TABLE sessions
ADD COLUMN compatibility_configuration_identity BLOB
CHECK (compatibility_configuration_identity IS NULL OR length(compatibility_configuration_identity) = 32);

CREATE TABLE session_template_manifest (
    session_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_compatibility BLOB NOT NULL CHECK (length(template_compatibility) = 32),
    PRIMARY KEY (session_id, template_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (template_id) REFERENCES templates(template_id)
);

INSERT INTO session_template_manifest(session_id, template_id, template_compatibility)
SELECT DISTINCT session_id, template_id, template_compatibility
FROM participants;
