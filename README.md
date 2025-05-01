# InboxGuard - Email DNS Verification System

InboxGuard helps small business owners and email marketers verify and analyze their email DNS settings (SPF, DKIM, and DMARC) to improve email deliverability and security.

## Features

- **Comprehensive DNS Analysis**: Verify SPF, DKIM, and DMARC records for any domain
- **Actionable Recommendations**: Get clear, human-readable advice on how to fix missing or misconfigured DNS records
- **Background Processing**: Handle verification tasks asynchronously for improved performance
- **Modern Architecture**: Built with FastAPI, Celery, and Redis for scalability and maintainability

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Python 3.10 or higher (for local development)

### Running with Docker Compose

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/inboxguard.git
   cd inboxguard
   ```

2. Create a `.env` file from the template:
   ```
   cp .env.example .env
   ```

3. Start the services:
   ```
   docker-compose up -d
   ```

4. Access the API documentation at http://localhost:8000/api/v1/docs

### Local Development

1. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```
   pip install -e ".[dev]"
   ```

3. Create a `.env` file:
   ```
   cp .env.example .env
   ```

4. Run the FastAPI application:
   ```
   uvicorn app.main:app --reload
   ```

5. In a separate terminal, start a Redis server:
   ```
   redis-server
   ```

6. And in another terminal, start the Celery worker:
   ```
   celery -A app.worker.celery_app worker --loglevel=info
   ```

## API Usage

### Verify a Domain

```http
POST /api/v1/dns/verify
Content-Type: application/json
```

Request body:
```json
{
  "domain": "example.com",
  "check_spf": true,
  "check_dkim": true,
  "check_dmarc": true,
  "email_selector": "_domainkey"
}
```

Response:
```json
{
  "domain": "example.com",
  "overall_status": "issues",
  "spf_analysis": {
    "record_type": "SPF",
    "status": "valid",
    "value": "v=spf1 include:_spf.example.com ~all",
    "issues": [],
    "recommendations": ["Your SPF record looks good!"]
  },
  "dkim_analysis": {
    "record_type": "DKIM",
    "status": "missing",
    "value": null,
    "issues": ["No DKIM record found for selector '_domainkey'"],
    "recommendations": [
      "Configure DKIM for your domain with your email provider",
      "Create a TXT record for _domainkey.example.com"
    ]
  },
  "dmarc_analysis": {
    "record_type": "DMARC",
    "status": "warning",
    "value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
    "issues": [
      "DMARC policy is set to 'none' which only monitors and doesn't protect against spoofing"
    ],
    "recommendations": [
      "Consider moving to 'p=quarantine' or 'p=reject' after monitoring period"
    ]
  },
  "timestamp": "2023-04-24T12:34:56.789Z"
}
```

## Running Tests

```
pytest
```

## Deployment

The project includes GitHub Actions workflows for CI/CD. To use them:

1. Add the following secrets to your GitHub repository:
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN`
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `AWS_REGION`

2. Push to the main branch to trigger the CI/CD pipeline.

## Future Enhancements

- Dashboard UI (React or Svelte)
- Email alerting for scheduled checks
- User authentication (JWT or API keys)
- Historical data storage and trend analysis

## License

This project is licensed under the MIT License - see the LICENSE file for details.