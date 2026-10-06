---
"effect": patch
---

Fail `withTransaction` with the typed `SqlError` when `COMMIT` fails, instead of a defect. PostgreSQL reports deferred constraint violations and serialization failures (`40001`) at `COMMIT`, so callers can now catch and retry them. `ROLLBACK` and savepoint release failures stay defects, because the transaction's own outcome is the error that matters there.
