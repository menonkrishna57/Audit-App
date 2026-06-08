# 1. Index your repo (run once, or re-run when code changes)
python ingest.py /path/to/your/repo

# 2. Run the audit
python agent.py

# 3. Optional: also get JSON output
python agent.py json