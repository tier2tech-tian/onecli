-- 调用方用户 ID：代理用户名里带的（CCVM runner 每轮填当前用户），供按人统计用量。可空：老数据、没带的为空。
-- 同 ttft_ms 列：加可空列不重写旧数据，拿锁最多等 5 秒，等不到就失败（可直接重跑）。
SET lock_timeout = '5s';
ALTER TABLE "secret_quota_usage" ADD COLUMN "client_user" TEXT;
