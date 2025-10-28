from celery import Celery

celery_app = Celery(
    "vulnmanager",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1"
)

celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
)

celery_app.autodiscover_tasks(["app.tasks.cpe_tasks", "app.tasks.cve_tasks", "app.tasks.vuln_tasks"])