import redis
from rq import Worker, Queue

from app.core.config import settings

if __name__ == "__main__":
    conn = redis.from_url(settings.redis_url)
    queues = [Queue(connection=conn)]
    worker = Worker(queues, connection=conn)
    worker.work()
