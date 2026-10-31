-- 每条请求的 token 用量（网关旁路读回复正文），与额度同一行。都可空：老数据、非成功回复、读不到时为空。
-- 加可空列只改表定义，不重写表、不长时间锁表。
ALTER TABLE "secret_quota_usage" ADD COLUMN "model" TEXT;
ALTER TABLE "secret_quota_usage" ADD COLUMN "input_tokens" BIGINT;
ALTER TABLE "secret_quota_usage" ADD COLUMN "output_tokens" BIGINT;
ALTER TABLE "secret_quota_usage" ADD COLUMN "cache_creation_input_tokens" BIGINT;
ALTER TABLE "secret_quota_usage" ADD COLUMN "cache_read_input_tokens" BIGINT;
