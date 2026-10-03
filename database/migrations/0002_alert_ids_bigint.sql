-- Alert ids were 32-bit, which runs out at about 2.1 billion. Ids are never
-- reused, and deleting old alerts (0.5.0) keeps them climbing, so widen them
-- while tables are small. Rewrites the alerts table once.
ALTER TABLE alerts ALTER COLUMN id TYPE BIGINT;
ALTER SEQUENCE alerts_id_seq AS BIGINT;
