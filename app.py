import os
import subprocess
import threading
import time
import re
from flask import Flask, abort, render_template, jsonify, Response, request, redirect, url_for, flash, session, send_from_directory
from obswebsocket import obsws, requests
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import secrets
from functools import wraps
from flask_cors import CORS

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/hls/*": {"origins": "*"}})
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['LOGIN_TIMEOUT'] = int(os.getenv('LOGIN_TIMEOUT', 60 * 60))  # 1 hour by default

# Initialize CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per day", "20 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# OBS WebSocket settings
obs_host = os.getenv('OBS_HOST')
obs_port = int(os.getenv('OBS_PORT'))
obs_password = os.getenv('OBS_PASSWORD')

# Login credentials from env
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
if ADMIN_PASSWORD == 'password':
    # Create hash of default password
    ADMIN_PASSWORD_HASH = generate_password_hash('password')
else:
    ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

# Rickroll URL for suspicious requests
RICKROLL_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

# Global variable for stream process
stream_process = None

# Suspicious request patterns (regex)
SUSPICIOUS_PATTERNS = [
    r'\.\./', # Directory traversal
    r'etc/passwd',
    r'wp-admin',
    r'wp-login',
    r'\.env',
    r'\.git',
    r'administrator',
    r'admin\.php',
    r'config\.php',
    r'phpinfo',
    r'eval\(',
    r'exec\(',
    r'shell_exec',
    r'SELECT.*FROM',
    r'UNION.*SELECT',
    r'INSERT.*INTO',
    r'DELETE.*FROM',
    r'DROP.*TABLE',
    r'script',
    r'<.*>.*<\/.*>',  # Basic XSS attempt
]

# Compile regex patterns
COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS]

# Before request handler to check for suspicious activities
@app.before_request
def check_request_security():
    # Skip security checks for static and HLS routes
    if request.path.startswith('/static/') or request.path.startswith('/hls/'):
        return None
    
    full_url = request.url
    for pattern in COMPILED_PATTERNS:
        if pattern.search(full_url):
            app.logger.warning(f"Suspicious request detected: {full_url}")
            return redirect(RICKROLL_URL)
    
    # Check query parameters
    for key, value in request.args.items():
        for pattern in COMPILED_PATTERNS:
            if pattern.search(key) or pattern.search(value):
                app.logger.warning(f"Suspicious query parameter detected: {key}={value}")
                return redirect(RICKROLL_URL)
    
    # Check form data if it's a POST request
    if request.method == 'POST' and request.form:
        for key, value in request.form.items():
            if key == 'csrf_token':  # Skip CSRF token check
                continue
            for pattern in COMPILED_PATTERNS:
                if pattern.search(key) or pattern.search(value):
                    app.logger.warning(f"Suspicious form data detected: {key}={value}")
                    return redirect(RICKROLL_URL)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            return redirect(url_for('login', next=request.url))
        
        # Check if session has expired
        last_active = session.get('last_active', 0)
        if time.time() - last_active > app.config['LOGIN_TIMEOUT']:
            session.clear()
            return redirect(url_for('login', next=request.url))
        
        # Update last active time
        session['last_active'] = time.time()
        return f(*args, **kwargs)
    return decorated_function

# Connect to OBS with error handling
def connect_obs():
    try:
        ws = obsws(obs_host, obs_port, obs_password, legacy=False)
        ws.connect()
        return ws, None
    except Exception as e:
        return None, str(e)

def generate_mjpeg():
    cmd = [
        'ffmpeg',
        '-f', 'x11grab',
        '-framerate', '30',
        '-video_size', '2560x1440',
        '-i', ':0.0',
        '-probesize', '5000000',
        '-analyzeduration', '1000000',
        '-vf', 'scale=1280:-1',
        '-q:v', '3',
        '-r', '30',
        '-f', 'mjpeg',
        'pipe:1',
        '-loglevel', 'debug'
    ]

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    buffer = b''
    try:
        while True:
            chunk = process.stdout.read(1024)
            if not chunk:
                break
            buffer += chunk
            while b'\xff\xd9' in buffer:
                end = buffer.index(b'\xff\xd9') + 2
                frame = buffer[:end]
                buffer = buffer[end:]
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    except Exception as e:
        print(f"Stream error: {e}")
    finally:
        process.terminate()
        process.wait()

def generate_hls_stream():
    hls_dir = 'static/hls'
    os.makedirs(hls_dir, exist_ok=True)
    
    # Clean old files
    for file in os.listdir(hls_dir):
        if file.endswith('.ts') or file.endswith('.m3u8') or file.endswith('.tmp'):
            try:
                os.remove(os.path.join(hls_dir, file))
            except:
                pass
    
    # Create a simple initial playlist file
    with open(os.path.join(hls_dir, 'stream.m3u8'), 'w') as f:
        f.write('#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:4\n#EXT-X-MEDIA-SEQUENCE:0\n')
    
    # Simpler command with fewer options
    cmd = [
        'ffmpeg',
        '-f', 'x11grab',
        '-framerate', '10',
        '-video_size', '2560x1440',
        '-i', ':0.0',
        '-f', 'pulse',
        '-i', 'bluez_output.80_C3_BA_53_0C_DA.1.monitor',
        '-vf', 'scale=1280:-1',
        '-c:v', 'mpeg2video',
        '-q:v', '7',
        '-c:a', 'aac',
        '-b:a', '128k',
        '-ar', '44100',
        '-ac', '2',
        '-hls_time', '4',
        '-hls_list_size', '6',  
        '-hls_flags', 'delete_segments',
        '-hls_segment_type', 'mpegts',
        '-f', 'hls',
        'static/hls/stream.m3u8'
    ]
    
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def log_process_output(process):
    for line in iter(process.stderr.readline, b''):
        print(f"FFMPEG: {line.decode().strip()}")

# Routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute, 10 per hour")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            session['username'] = username
            session['last_active'] = time.time()
            session['failed_attempts'] = 0
            
            next_url = request.args.get('next', url_for('index'))
            return redirect(next_url)
        else:
            session['failed_attempts'] = session.get('failed_attempts', 0) + 1
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('viewer.html')

@app.route('/video_feed')
@login_required
@limiter.limit("40 per minute")
def video_feed():
    return Response(generate_mjpeg(),
                   mimetype='multipart/x-mixed-replace; boundary=frame')

# Updated HLS route - EXEMPT from rate limiting
@app.route('/hls/<path:filename>')
@limiter.exempt
def serve_hls(filename):
    try:
        file_path = os.path.join('static/hls', filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            app.logger.error(f"HLS file not found: {file_path}")
            return jsonify({"error": "File not found"}), 404
            
        # For m3u8 files, set specific content type
        if filename.endswith('.m3u8'):
            response = send_from_directory('static/hls', filename, 
                                         mimetype='application/vnd.apple.mpegurl')
        else:
            response = send_from_directory('static/hls', filename)
            
        # Add CORS and cache headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Cache-Control'] = 'no-cache'
        return response
        
    except Exception as e:
        app.logger.error(f"Error serving HLS file: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/start_hls')
@login_required
@limiter.exempt
def start_hls():
    global stream_process
    try:
        # Clear any existing process
        if stream_process and stream_process.poll() is None:
            try:
                stream_process.terminate()
                stream_process.wait(timeout=3)
            except:
                pass  # Ignore errors during cleanup
        
        # Clean output directory without checking for existence first
        hls_dir = 'static/hls'
        os.makedirs(hls_dir, exist_ok=True)
        try:
            for file in os.listdir(hls_dir):
                if file.endswith('.ts') or file.endswith('.m3u8'):
                    try:
                        os.remove(os.path.join(hls_dir, file))
                    except:
                        pass  # Skip files we can't delete
        except Exception as e:
            print(f"Error clearing HLS directory: {str(e)}")
        
        # Start new process
        stream_process = generate_hls_stream()
        
        # Simpler check - just make sure process started successfully
        if stream_process.poll() is not None:
            error_output = stream_process.stderr.read().decode() if stream_process.stderr else "Unknown error"
            print(f"FFmpeg failed to start: {error_output}")
            return jsonify({"status": "error", "message": "Failed to start stream process"}), 500
            
        # Return success without waiting for file creation
        return jsonify({"status": "success", "message": "Stream started successfully"})
        
    except Exception as e:
        print(f"Exception in start_hls: {str(e)}")
        return jsonify({"status": "error", "message": f"Error: {str(e)}"}), 500

@app.route('/stop_hls')
@login_required
@limiter.exempt
def stop_hls():
    global stream_process
    try:
        if stream_process and stream_process.poll() is None:
            stream_process.terminate()
            stream_process.wait()
            stream_process = None
            return jsonify({"status": "success", "message": "Stream stopped"})
        return jsonify({"status": "info", "message": "No stream running"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error stopping stream: {str(e)}"})

@app.route('/start_stream')
@login_required
@limiter.limit("3 per minute")
def start_stream():
    ws, err = connect_obs()
    if ws is None:
        return jsonify({'status': 'error', 'message': err}), 500
    
    ws.call(requests.StartStreaming())
    return jsonify({'status': 'success', 'message': 'OBS stream started'}), 200

@app.route('/stop_stream')
@login_required
@limiter.limit("3 per minute")
def stop_stream():
    ws, err = connect_obs()
    if ws is None:
        return jsonify({'status': 'error', 'message': err}), 500
    
    ws.call(requests.StopStreaming())
    return jsonify({'status': 'success', 'message': 'OBS stream stopped'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)