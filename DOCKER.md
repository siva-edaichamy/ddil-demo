# Docker Deployment Guide

This guide explains how to deploy the GemFire DDIL Demo using Docker.

## Prerequisites

- Docker (version 20.10 or higher)
- Docker Compose (version 2.0 or higher)

## Quick Start

### 1. Build and Run with Docker Compose

```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

### 2. Access the Dashboards

- **Control Dashboard**: http://localhost:5004
- **Demo Dashboard**: http://localhost:5002

## Configuration

### Environment Variables

Create a `.env` file in the project root with your configuration:

```env
# Postgres (for latency check)
POSTGRES_HOST=your_postgres_host
POSTGRES_PORT=5432
POSTGRES_DB=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password

# Demo Dashboard URL
DEMO_DASHBOARD_URL=http://localhost:5002
```

### SSH Keys

If you need SSH access to remote nodes, mount your SSH keys:

```yaml
# In docker-compose.yml, uncomment:
volumes:
  - ~/.ssh:/root/.ssh:ro
```

**Note**: Make sure your SSH keys have proper permissions (600 for private keys).

### Persistent Data

The following directories are mounted as volumes for data persistence:

- `./config` - Configuration files (last_session.json)
- `./logs` - Application logs

## Building the Image

### Build locally:

```bash
docker build -t ddil-demo .
```

### Run the container:

```bash
docker run -d \
  -p 5004:5004 \
  -p 5002:5002 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/logs:/var/log/supervisor \
  --env-file .env \
  --name ddil-demo \
  ddil-demo
```

## Viewing Logs

### Using Docker Compose:

```bash
# All logs
docker-compose logs -f

# Control dashboard logs
docker-compose logs -f control_dashboard

# Demo dashboard logs
docker-compose logs -f demo_dashboard
```

### Using Docker:

```bash
# All logs
docker logs -f ddil-demo

# Supervisor logs
docker exec ddil-demo tail -f /var/log/supervisor/control.log
docker exec ddil-demo tail -f /var/log/supervisor/demo.log
```

## Troubleshooting

### Container won't start

1. Check logs: `docker-compose logs`
2. Verify ports 5004 and 5002 are not in use: `lsof -i :5004 -i :5002`
3. Check Docker resources: `docker stats`

### SSH connection issues

1. Ensure SSH keys are mounted correctly
2. Check key permissions: `chmod 600 ~/.ssh/id_rsa`
3. Verify SSH keys are accessible in container: `docker exec ddil-demo ls -la /root/.ssh`

### Postgres connection issues

1. Verify `.env` file has correct Postgres credentials
2. Check if Postgres is accessible from container: `docker exec ddil-demo ping your_postgres_host`
3. Test connection: `docker exec ddil-demo python -c "import psycopg2; psycopg2.connect(...)"`

## Production Considerations

1. **Security**: Don't commit `.env` file with secrets
2. **Networking**: Use Docker networks for service isolation
3. **Resource Limits**: Set CPU/memory limits in docker-compose.yml
4. **Health Checks**: Add healthcheck configuration
5. **Backup**: Regularly backup the `config` directory

## Example docker-compose.yml for Production

```yaml
version: '3.8'

services:
  ddil-demo:
    build: .
    container_name: ddil-demo
    ports:
      - "5004:5004"
      - "5002:5002"
    volumes:
      - ./config:/app/config
      - ./logs:/var/log/supervisor
    env_file:
      - .env
    restart: always
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5004"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - ddil-network

networks:
  ddil-network:
    driver: bridge
```

