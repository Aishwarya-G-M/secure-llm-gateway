from redis.asyncio import Redis, from_url

_redis: Redis | None = None

async def initialise_redis(redis_url: str) -> None:
    global _redis
    client = from_url(
        redis_url,
        decode_responses=True,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
        health_check_interval=30,
    )
    await client.ping()
    _redis = client

def get_redis() -> Redis:
    if _redis is None:
        raise RuntimeError("Redis client is not initialized")
    return _redis

async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None