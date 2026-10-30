-- 网关记录的账号额度用量明细：每个带用量头的模型响应一行（追加写，网关每 5 秒批量写入）
CREATE TABLE "secret_quota_usage" (
    "id" BIGSERIAL NOT NULL,
    "secret_id" TEXT NOT NULL,
    "observed_at" BIGINT NOT NULL,
    "five_hour_utilization" DOUBLE PRECISION,
    "five_hour_reset" BIGINT,
    "seven_day_utilization" DOUBLE PRECISION,
    "seven_day_reset" BIGINT,
    "unified_status" TEXT,
    "http_status" INTEGER NOT NULL,
    CONSTRAINT "secret_quota_usage_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "secret_quota_usage_secret_id_fkey" FOREIGN KEY ("secret_id") REFERENCES "secrets"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "secret_quota_usage_secret_id_observed_at_idx" ON "secret_quota_usage"("secret_id", "observed_at");
CREATE INDEX "secret_quota_usage_observed_at_idx" ON "secret_quota_usage"("observed_at");
