import os
import json
from flask import Flask, render_template, request, redirect, url_for, session
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import secrets

# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)

# Configure session
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False

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


@app.route('/')
def index():
    """Main page that displays login option"""
    return render_template('index.html')


@app.route('/login')
def login():
    """Redirect to X authorization page"""
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        scope=SCOPES
    )
    
    # Create the authorization URL with PKCE
    authorization_url, state = x_session.authorization_url(
        AUTHORIZATION_BASE_URL,
        code_challenge_method='S256'
    )
    
    # Store the state for later use
    session['oauth_state'] = state
    
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    """Process the X OAuth 2.0 callback"""
    # Get the state from the session
    state = session.get('oauth_state', None)
    
    # Create the OAuth session
    x_session = OAuth2Session(
        X_CLIENT_ID,
        redirect_uri=X_REDIRECT_URI,
        state=state
    )
    
    try:
        # Get the full URL for authorization response
        if request.url.startswith('http://') and os.getenv('VERCEL_URL'):
            # Fix for Vercel deployment - transform HTTP to HTTPS
            auth_response_url = request.url.replace('http://', 'https://', 1)
        else:
            auth_response_url = request.url
            
        # Fetch the access token using the authorization code
        token = x_session.fetch_token(
            TOKEN_URL,
            client_secret=X_CLIENT_SECRET,
            authorization_response=auth_response_url
        )
        
        # Store the token in the session
        session['oauth_token'] = token
        
        # Fetch user information
        user_info = fetch_user_info(token)
        session['user_info'] = user_info
        
        return redirect(url_for('profile'))
    
    except Exception as e:
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


if __name__ == '__main__':
    app.run(debug=True) 