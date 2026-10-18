CREATE TABLE auth_delivery (
  id INTEGER PRIMARY KEY CHECK (typeof(id) = 'integer' AND id = 1),
  state TEXT NOT NULL CHECK (state IN ('CLEAR','UNRESOLVED','STALE')),
  generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 0),
  CHECK ((state = 'CLEAR' AND generation = 0)
      OR (state IN ('UNRESOLVED','STALE') AND generation > 0))
);
INSERT INTO auth_delivery(id, state, generation) VALUES (1, 'CLEAR', 0);
