# Screen Sharing Web Application

Flask-based web application for secure screen sharing with audio streaming via HLS and OBS WebSocket integration.

## Features

**Streaming**
- Real-time screen capture with audio
- HLS (HTTP Live Streaming) support
- MJPEG streaming fallback
- OBS Studio integration via WebSocket
- Fullscreen viewing mode

**Security**
- Login authentication with session management
- CSRF protection
- Rate limiting
- Suspicious request detection with rickroll redirect
- Secure password hashing

**Interface**
- Responsive web viewer
- Stream controls (start/stop)
- OBS remote control
- Auto-reconnection on stream failure

## Setup

**Environment Variables**
```
SECRET_KEY=your_secret_key_here
LOGIN_TIMEOUT=3600
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password
OBS_HOST=localhost
OBS_PORT=4455
OBS_PASSWORD=your_obs_websocket_password
```

**Dependencies**
```bash
pip install flask flask-wtf flask-limiter flask-cors
pip install obs-websocket-py python-dotenv werkzeug
```

**System Requirements**
- FFmpeg with X11 screen capture support
- PulseAudio for audio capture
- OBS Studio with WebSocket plugin

**Run Application**
```bash
python app.py
```

## Usage

**Access Interface**
- Navigate to `http://localhost:5000`
- Login with admin credentials
- Use stream controls to start/stop

**Stream Types**
- **HLS Stream**: `/start_hls` - Creates HLS playlist for web playback
- **OBS Stream**: `/start_stream` - Controls OBS Studio streaming
- **MJPEG**: `/video_feed` - Direct MJPEG stream

**API Endpoints**
- `POST /login` - Authentication
- `GET /start_hls` - Start HLS streaming
- `GET /stop_hls` - Stop HLS streaming
- `GET /start_stream` - Start OBS stream
- `GET /stop_stream` - Stop OBS stream

## Configuration

**FFmpeg Settings**
- Screen resolution: 2560x1440 (scaled to 1280x720)
- Frame rate: 30fps (HLS: 10fps)
- Audio: PulseAudio monitor capture
- HLS segment duration: 4 seconds

**Security Features**
- Session timeout: 1 hour default
- Rate limits: 50/day, 20/hour
- Blocks SQL injection, XSS, directory traversal
- Redirects suspicious requests to rickroll

**OBS Integration**
- WebSocket v5 protocol
- Remote start/stop streaming
- Configurable host/port/password

## File Structure

```
├── app.py              # Main Flask application
├── templates/
│   ├── login.html      # Login page
│   └── viewer.html     # Stream viewer
└── static/hls/         # HLS output directory (auto-created)
```

## Notes

- Requires X11 display server
- Audio capture uses PulseAudio monitor
- HLS files auto-cleanup on stream stop
- CORS enabled for HLS endpoints
- Auto-disconnects inactive sessions
