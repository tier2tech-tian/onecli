CREATE TABLE "secret_quota_usage" (
    "secret_id" TEXT PRIMARY KEY REFERENCES "secrets"("id") ON DELETE CASCADE ON UPDATE CASCADE,
    "five_hour_utilization" DOUBLE PRECISION,
    "five_hour_reset" BIGINT,
    "seven_day_utilization" DOUBLE PRECISION,
    "seven_day_reset" BIGINT,
    "unified_status" TEXT,
    "http_status" INTEGER NOT NULL,
    "observed_at" BIGINT NOT NULL
);
