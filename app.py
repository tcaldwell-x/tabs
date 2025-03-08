import os
import json
from flask import Flask, render_template, request, redirect, url_for, session
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import secrets
import base64
import hashlib

# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)

# Configure session
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
# Using cookies instead of filesystem for serverless compatibility 
# app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True  # Set to True for cookie-based sessions
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('VERCEL_ENV') == 'production'  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

# For production environments like Vercel, ensure HTTPS is used for callbacks
if os.getenv('VERCEL_ENV') == 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
    app.config['PREFERRED_URL_SCHEME'] = 'https'
else:
    # For local development only - remove in production
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# X OAuth 2.0 Settings
X_CLIENT_ID = os.getenv('X_CLIENT_ID')
X_CLIENT_SECRET = os.getenv('X_CLIENT_SECRET')

# Get the appropriate redirect URI based on environment
if os.getenv('VERCEL_URL'):
    # Vercel deployment
    X_REDIRECT_URI = f"https://{os.getenv('VERCEL_URL')}/callback"
elif os.getenv('X_REDIRECT_URI'):
    # Custom configured redirect URI
    X_REDIRECT_URI = os.getenv('X_REDIRECT_URI')
else:
    # Local development
    X_REDIRECT_URI = "http://127.0.0.1:5000/callback"

# X OAuth2 endpoints
AUTHORIZATION_BASE_URL = 'https://x.com/i/oauth2/authorize'
TOKEN_URL = 'https://api.x.com/2/oauth2/token'
USERINFO_URL = 'https://api.x.com/2/users/me'

# Scopes needed for the application
SCOPES = ['tweet.read', 'users.read', 'offline.access']

# Helper function to generate a code verifier for PKCE
def generate_code_verifier(length=64):
    """Generate a code verifier string of specified length for PKCE"""
    return secrets.token_urlsafe(length)

# Helper function to generate a code challenge from a code verifier
def generate_code_challenge(code_verifier):
    """Generate a code challenge (S256) from a code verifier"""
    sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')

@app.route('/')
def index():
    """Main page that displays login option"""
    return render_template('index.html')


@app.route('/login')
def login():
    """Redirect to X authorization page with PKCE"""
    # Generate code verifier and challenge for PKCE
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store the verifier in session for later use in callback
    session['code_verifier'] = code_verifier
    
    # Create a combined state that includes the verifier
    # This is a backup in case sessions don't work
    combined_state = f"{secrets.token_urlsafe(16)}:{code_verifier}"
    
    # Create OAuth session
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        scope=SCOPES
    )
    
    # Create the authorization URL with PKCE
    authorization_url, state = x_session.authorization_url(
        AUTHORIZATION_BASE_URL,
        code_challenge=code_challenge,
        code_challenge_method='S256',
        state=combined_state  # Use our combined state
    )
    
    # Debug prints
    print(f"Code Verifier: {code_verifier}")
    print(f"Code Challenge: {code_challenge}")
    print(f"Authorization URL: {authorization_url}")
    print(f"Combined State: {combined_state}")
    print(f"Redirect URI: {X_REDIRECT_URI}")
    
    # Store the state for later use
    session['oauth_state'] = combined_state
    
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    """Process the X OAuth 2.0 callback"""
    # Get request params
    request_state = request.args.get('state')
    
    # Try to get state and code verifier from the session
    session_state = session.get('oauth_state')
    code_verifier = session.get('code_verifier')
    
    # Debug prints
    print(f"Callback received")
    print(f"State from request: {request_state}")
    print(f"State from session: {session_state}")
    print(f"Code verifier from session: {code_verifier}")
    print(f"Request URL: {request.url}")
    
    # If session state is missing but request state is present
    if not session_state and request_state:
        # We'll use the state from the request, which should include the code_verifier
        print("Session state missing, using request state")
        session_state = request_state
        
        # Try to extract code_verifier from state
        if ':' in request_state:
            # Our state format is "random:code_verifier"
            state_parts = request_state.split(':', 1)
            if len(state_parts) == 2:
                code_verifier = state_parts[1]
                print(f"Extracted code_verifier from state: {code_verifier}")
    
    # If state or code_verifier is still None, return error
    if not session_state:
        return render_template('error.html', error="State is missing from session. Session may have expired.")
    if not code_verifier:
        return render_template('error.html', error="Code verifier is missing. Session may have expired.")
    
    # Create the OAuth session with state
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        state=session_state
    )
    
    try:
        # Get the full URL for authorization response
        if request.url.startswith('http://') and os.getenv('VERCEL_URL'):
            # Fix for Vercel deployment - transform HTTP to HTTPS
            auth_response_url = request.url.replace('http://', 'https://', 1)
        else:
            auth_response_url = request.url
        
        print(f"Auth response URL: {auth_response_url}")
            
        # Fetch the access token using the authorization code and code verifier
        token = x_session.fetch_token(
            TOKEN_URL,
            client_secret=X_CLIENT_SECRET,
            authorization_response=auth_response_url,
            code_verifier=code_verifier
        )
        
        # Store the token in the session
        session['oauth_token'] = token
        
        # Fetch user information
        user_info = fetch_user_info(token)
        session['user_info'] = user_info
        
        return redirect(url_for('profile'))
    
    except Exception as e:
        print(f"Error in callback: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return render_template('error.html', error=str(e))


def fetch_user_info(token):
    """Fetch the user's information from X API"""
    x_session = OAuth2Session(X_CLIENT_ID, token=token)
    
    # Include user fields to get more information
    params = {
        'user.fields': 'name,username,profile_image_url,description'
    }
    
    # Make the request to the userinfo endpoint
    response = x_session.get(USERINFO_URL, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        # Handle error
        return {'error': f"Error fetching user info: {response.status_code}"}


@app.route('/profile')
def profile():
    """Display the user's profile information"""
    # Check if the user is logged in
    user_info = session.get('user_info')
    
    if not user_info:
        return redirect(url_for('index'))
    
    return render_template('profile.html', user=user_info['data'])


@app.route('/logout')
def logout():
    """Log the user out by clearing the session"""
    session.clear()
    return redirect(url_for('index'))


@app.route('/debug')
def debug_twitter():
    """Debug page for Twitter OAuth configuration"""
    # Create a debug info dictionary
    debug_info = {
        "client_id": X_CLIENT_ID,
        "redirect_uri": X_REDIRECT_URI,
        "scopes": SCOPES,
        "auth_url": AUTHORIZATION_BASE_URL,
        "token_url": TOKEN_URL,
        "vercel_url": os.getenv('VERCEL_URL'),
        "x_redirect_uri_env": os.getenv('X_REDIRECT_URI')
    }
    
    # Generate a test code verifier and challenge (without storing in session)
    test_verifier = generate_code_verifier()
    test_challenge = generate_code_challenge(test_verifier)
    
    # Create a test authorization URL
    test_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        scope=SCOPES
    )
    
    test_auth_url, test_state = test_session.authorization_url(
        AUTHORIZATION_BASE_URL,
        code_challenge=test_challenge,
        code_challenge_method='S256'
    )
    
    # Add test values to debug info
    debug_info["test_verifier"] = test_verifier
    debug_info["test_challenge"] = test_challenge
    debug_info["test_auth_url"] = test_auth_url
    debug_info["test_state"] = test_state
    
    # Check for common configuration issues
    issues = []
    
    if not X_CLIENT_ID:
        issues.append("X_CLIENT_ID is not set")
    
    if not X_CLIENT_SECRET:
        issues.append("X_CLIENT_SECRET is not set")
    
    if not X_REDIRECT_URI:
        issues.append("X_REDIRECT_URI is not configured")
    
    if X_REDIRECT_URI and "localhost" in X_REDIRECT_URI:
        issues.append("Redirect URI contains 'localhost' which Twitter might not accept. Use 127.0.0.1 instead.")
    
    # For Vercel deployments
    if os.getenv('VERCEL_URL') and not X_REDIRECT_URI.startswith(f"https://{os.getenv('VERCEL_URL')}"):
        issues.append(f"Redirect URI doesn't match Vercel URL. Expected: https://{os.getenv('VERCEL_URL')}/callback")
    
    debug_info["issues"] = issues
    debug_info["session_cookie_secure"] = app.config.get('SESSION_COOKIE_SECURE', False)
    
    return render_template('debug.html', debug=debug_info)


if __name__ == '__main__':
    app.run(debug=True) 