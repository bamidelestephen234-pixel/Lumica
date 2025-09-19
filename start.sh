#!/bin/bash

# Kill any existing Streamlit processes
pkill -f streamlit
sleep 2

# Clear any stale PID files
find ~/.streamlit -type f -name "*.pid" -delete

# Run Streamlit with minimal file watching
export STREAMLIT_SERVER_FILE_WATCHER_TYPE="none"
export STREAMLIT_SERVER_WATCH_DIRS="false"
export WATCHDOG_NO_ALLOW_INOTIFY="1"

streamlit run app.py --server.port 8501 --server.maxUploadSize 5