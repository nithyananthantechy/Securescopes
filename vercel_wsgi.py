import os
import sys

# Add project root to python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from securescope.web.app import app

# Vercel looks for the handler variable by default
app = app
