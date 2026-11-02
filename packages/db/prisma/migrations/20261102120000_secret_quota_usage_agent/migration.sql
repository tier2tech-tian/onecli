-- 每条用量记下是哪个 agent（= 账号池）发起的，用来按池统计 token。可空：老数据、没认出 agent 的请求为空。
-- 加可空列只改表定义，不重写表、不长时间锁表。不建外键：agent 删除后历史用量照样保留。
ALTER TABLE "secret_quota_usage" ADD COLUMN "agent_id" TEXT;
