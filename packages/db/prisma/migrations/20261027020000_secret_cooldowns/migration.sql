CREATE TABLE "secret_cooldowns" (
    "secret_id" TEXT PRIMARY KEY REFERENCES "secrets"("id") ON DELETE CASCADE,
    "reason" TEXT NOT NULL CHECK ("reason" IN ('seven_day', 'five_hour')),
    "reset_at" BIGINT NOT NULL
);
