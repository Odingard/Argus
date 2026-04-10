FROM python:3.12-slim

WORKDIR /app
COPY mcp_server.py .

EXPOSE 8001
ENV PORT=8001

CMD ["python", "mcp_server.py"]
