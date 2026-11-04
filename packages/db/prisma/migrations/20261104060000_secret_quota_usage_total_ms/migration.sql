-- 总用时（毫秒）：网关收到请求 → 回复最后一段数据经过网关（客户端中途断开 / 流被截断时是截至最后一段）。算并发数和吞吐用（11-04 大杰）。
-- 可空：老数据、没读出 token 用量的回复为空。非空不代表请求完整成功。
-- 同 ttft_ms 列：加可空列不重写旧数据，拿锁最多等 5 秒，等不到就失败（可直接重跑）。
SET lock_timeout = '5s';
-- started_at：网关收到请求的时刻（毫秒时间戳）；started_at + total_ms = 结束时刻（大杰 11-04：要完整时间）。
ALTER TABLE "secret_quota_usage" ADD COLUMN "total_ms" BIGINT, ADD COLUMN "started_at" BIGINT;
