-- 流式回复的首字延迟（毫秒）：网关收到请求 → 第一个内容增量经过网关。可空：老数据、非流式回复为空。
-- 同 agent_id 列：加可空列不重写旧数据，拿锁最多等 5 秒，等不到就失败（可直接重跑）。
SET lock_timeout = '5s';
ALTER TABLE "secret_quota_usage" ADD COLUMN "ttft_ms" BIGINT;
