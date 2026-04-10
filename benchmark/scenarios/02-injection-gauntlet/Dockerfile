FROM python:3.12-slim

WORKDIR /app
COPY agent.py .

EXPOSE 8002
ENV PORT=8002

CMD ["python", "agent.py"]
