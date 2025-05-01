#!/bin/bash
cd ~/backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
