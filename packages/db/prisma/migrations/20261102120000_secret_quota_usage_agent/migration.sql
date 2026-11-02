-- 每条用量记下是哪个 agent（= 账号池）发起的，用来按池统计 token。可空：老数据、没认出 agent 的请求为空。
-- 加可空列不重写旧数据，但仍要瞬间拿 AccessExclusiveLock；碰上长事务会排队并挡住后续读写，
-- 所以拿锁最多等 5 秒，等不到就失败（迁移可直接重跑），不让网关写入跟着排队。
-- 不建外键：agent 删除后历史用量照样保留。
SET lock_timeout = '5s';
ALTER TABLE "secret_quota_usage" ADD COLUMN "agent_id" TEXT;
