import signal
import sys
from waitress import serve
from app import app  # Assuming your Flask app is named 'app' in app.py

def signal_handler(sig, frame):
    print('Shutting down gracefully...')
    sys.exit(0)

# Register handlers for both SIGINT and SIGTERM to capture different termination signals
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Serve the application
app.run(host='0.0.0.0', port=8000)
