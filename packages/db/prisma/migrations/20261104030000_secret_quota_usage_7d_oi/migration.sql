-- 7d_oi 档额度：只在 Fable 5 请求的回复头里出现（11-04 实测与 Fable 请求一一对应），按 Fable 周额度用。可空：其他模型、老数据为空。
-- 同 client_user 列：加可空列不重写旧数据，拿锁最多等 5 秒，等不到就失败（可直接重跑）。
SET lock_timeout = '5s';
ALTER TABLE "secret_quota_usage" ADD COLUMN "seven_day_oi_utilization" DOUBLE PRECISION, ADD COLUMN "seven_day_oi_reset" BIGINT;
