# Contributing to SentinelAI IDS

Thank you for your interest in contributing. This guide covers everything you need to get started.

## Setting Up the Development Environment

1. Clone the repository:

```bash
git clone https://github.com/your-username/sentinel-ai-ids.git
cd sentinel-ai-ids
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Start the infrastructure services:

```bash
docker compose up -d
```

## Running Tests

```bash
pytest
```

To run tests with verbose output:

```bash
pytest -v
```

## Running the Linter

```bash
ruff check .
```

To automatically fix issues where possible:

```bash
ruff check . --fix
```

## Submitting a Pull Request

1. Fork the repository and create a new branch from `main`.
2. Make your changes and ensure all tests pass.
3. Run the linter and fix any issues.
4. Commit with a clear, descriptive message.
5. Push your branch and open a pull request against `main`.
6. Fill out the pull request template completely.

Please keep pull requests focused on a single change. If you have multiple unrelated changes, submit them as separate pull requests.
