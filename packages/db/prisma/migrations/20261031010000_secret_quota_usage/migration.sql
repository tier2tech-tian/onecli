-- 网关记录的账号额度用量曲线：每个账号每分钟最多一行（这一分钟内最后一次观测），没有请求的分钟不写
CREATE TABLE "secret_quota_usage" (
    "secret_id" TEXT NOT NULL REFERENCES "secrets"("id") ON DELETE CASCADE ON UPDATE CASCADE,
    "minute" BIGINT NOT NULL,
    "five_hour_utilization" DOUBLE PRECISION,
    "five_hour_reset" BIGINT,
    "seven_day_utilization" DOUBLE PRECISION,
    "seven_day_reset" BIGINT,
    "unified_status" TEXT,
    "http_status" INTEGER NOT NULL,
    "observed_at" BIGINT NOT NULL,
    CONSTRAINT "secret_quota_usage_pkey" PRIMARY KEY ("secret_id", "minute")
);
CREATE INDEX "secret_quota_usage_minute_idx" ON "secret_quota_usage"("minute");
