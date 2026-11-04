-- 总用时（毫秒）：网关收到请求 → 回复最后一段数据经过网关。有了它才能从库里算并发数和吞吐（11-04 大杰）。可空：老数据、没读完正文的为空。
-- 同 ttft_ms 列：加可空列不重写旧数据，拿锁最多等 5 秒，等不到就失败（可直接重跑）。
SET lock_timeout = '5s';
ALTER TABLE "secret_quota_usage" ADD COLUMN "total_ms" BIGINT;
