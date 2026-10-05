#!/bin/bash
echo "Ejecutando migraciones..."
alembic upgrade head
echo "Iniciando servidor..."
exec uvicorn main:app --host 0.0.0.0 --port 8000