from redis import Redis
from rq import Connection, Queue, Worker

from backend.app.core.config import settings

if __name__ == "__main__":
    redis_conn = Redis.from_url(settings.redis_url)
    with Connection(redis_conn):
        queue = Queue("recon")
        worker = Worker([queue])
        worker.work()
