from redis import Redis
from rq import Connection, Worker

from api.app.config import settings


if __name__ == "__main__":
    connection = Redis.from_url(settings.redis_url)
    with Connection(connection):
        worker = Worker(["apkspider"])
        worker.work()
