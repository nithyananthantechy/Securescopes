from flask import Blueprint, session, redirect, url_for, request
from datetime import datetime, timedelta
import uuid

# Import the global stored_scan_results from app (will do it inside the function to avoid circular imports if necessary, or just import app)
from securescope.web.demo_fixtures import DEMO_TARGETS

demo_bp = Blueprint('demo', __name__)

@demo_bp.route('/demo')
def start_demo():
    from securescope.web.app import stored_scan_results, llm_store
    
    # Set demo session flags
    session.clear()
    session['demo_session'] = True
    session['logged_in'] = True
    session['username'] = 'Demo User'
    session['role'] = 'guest'
    session['org_id'] = 'demo-org-1'
    session['demo_expiry'] = (datetime.utcnow() + timedelta(minutes=30)).timestamp()
    session['csrf_token'] = uuid.uuid4().hex
    
    # Load demo data into the global in-memory store if not present
    for target_key, target_data in DEMO_TARGETS.items():
        stored_scan_results[target_key] = target_data

    # Log demo visit
    try:
        ip_addr = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Log to the mock demo_visits table (or activity log)
        # Using raw SQL to insert into demo_visits table which we will create in llm_store
        with llm_store._conn() as conn:
            conn.execute(
                """
                INSERT INTO demo_visits (id, ip_address, user_agent, timestamp, pages_viewed)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), ip_addr, user_agent, datetime.utcnow().isoformat(), 0)
            )
    except Exception as e:
        import traceback
        traceback.print_exc()

    return redirect(url_for('dashboard'))
