import os
import google.generativeai as genai
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from dotenv import load_dotenv
from twilio.rest import Client
from supabase import create_client, Client as SupabaseClient
from supabase.lib.client_options import ClientOptions # Added for auth callback
from postgrest.exceptions import APIError as PostgrestAPIError # Added for specific error handling
import stripe
from datetime import datetime as dt, timedelta, time as dt_time, timezone
import threading
import time # For the scheduler sleep
from functools import wraps # Added for decorators
import pkce # Added for PKCE

load_dotenv() # Load environment variables from .env file

app = Flask(__name__)
# --- Flask Session Configuration ---
# Ensure FLASK_SECRET_KEY is set in your .env file for session management
FLASK_SECRET_KEY_FROM_ENV = os.getenv("FLASK_SECRET_KEY")
if FLASK_SECRET_KEY_FROM_ENV:
    app.secret_key = FLASK_SECRET_KEY_FROM_ENV
    print("INFO: Flask secret key loaded.")
else:
    print("CRITICAL ERROR: FLASK_SECRET_KEY not found in .env file.")
    print("CRITICAL ERROR: Sessions will not work, and authentication will fail.")
    # You might want to exit here if the secret key is absolutely critical at startup
    # For now, it will proceed but sessions will be insecure/non-functional.
    app.secret_key = "default_unsafe_key_please_replace" # Fallback, highly insecure

# --- Configuration ---
GEMINI_API_KEY_FROM_ENV = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY_FROM_ENV:
    GEMINI_API_KEY = GEMINI_API_KEY_FROM_ENV
    print("INFO: Gemini API key loaded from .env file.")
else:
    GEMINI_API_KEY = None # Explicitly set to None if not found in env
    print("CRITICAL ERROR: Gemini API key (GEMINI_API_KEY) not found in .env file.")
    print("CRITICAL ERROR: Please ensure GEMINI_API_KEY is set in your .env file for the application to generate messages.")

model = None
if GEMINI_API_KEY:
    try:
        print(f"INFO: Attempting to configure Gemini API with key: {GEMINI_API_KEY[:10]}... (partially masked)")
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.0-flash')
        print("INFO: Gemini API configured and model initialized successfully.")
    except Exception as e:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"CRITICAL ERROR: Failed to configure Gemini API or initialize model: {e}")
        print("CRITICAL ERROR: The application will likely not be able to generate messages.")
        print("CRITICAL ERROR: Check your API key, internet connection, and google-generativeai installation.")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        model = None
else:
    print("CRITICAL ERROR: Gemini API key is missing. Cannot initialize AI model.")

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase_client: SupabaseClient = None

# Stripe configuration
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        print(f"INFO: Attempting to initialize Supabase client with URL: {SUPABASE_URL}")
        # For server-side auth handling (like exchanging code for session),
        # it's often useful to have autoRefreshToken set to False if you manage sessions explicitly.
        # However, for provider sign-in and session establishment, the default (True) is usually fine.
        # We might need to explicitly handle session refresh or ensure the client is correctly
        # set up to manage the user's session after callback.
        client_options = ClientOptions(auto_refresh_token=True, persist_session=True) # persist_session is true by default
        supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY, options=client_options)
        print("INFO: Supabase client initialized successfully.")
    except Exception as e:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"CRITICAL ERROR: Failed to initialize Supabase client: {e}")
        print("CRITICAL ERROR: Database operations will fail.")
        print("CRITICAL ERROR: Check your SUPABASE_URL (should be API URL) and SUPABASE_SERVICE_KEY in .env file.")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        supabase_client = None
else:
    print("CRITICAL ERROR: Supabase URL or Service Key is missing in .env file. Cannot initialize Supabase client.")

# --- User Profile and Role Management ---
def get_or_create_user_profile(user_auth_data):
    """
    Retrieves a user's profile from the 'users' table or creates one if it doesn't exist.
    Assumes user_auth_data is the user object from supabase_client.auth.get_user().
    """
    if not user_auth_data or not user_auth_data.user or not user_auth_data.user.id:
        print("ERROR: Invalid user_auth_data provided to get_or_create_user_profile.")
        return None

    auth_user_id = user_auth_data.user.id
    auth_user_email = user_auth_data.user.email
    profile_data = None

    # Use the global supabase_client (potentially with user session) for SELECT
    # This assumes RLS allows users to select their own profile, or it's fine if it fails with 204/None
    if supabase_client:
        try:
            print(f"INFO: Checking for existing profile for user {auth_user_id} using main client.")
            profile_response = supabase_client.table('users').select('*').eq('id', auth_user_id).maybe_single().execute()
            profile_data = profile_response.data
            if profile_data:
                print(f"INFO: Profile found for user {auth_user_id} via main client: {profile_data}")
        except Exception as e_select:
            is_postgrest_204_error = False
            if hasattr(e_select, 'code') and e_select.code == '204':
                is_postgrest_204_error = True # Variable not used further, but logic is sound
                print(f"INFO: Profile for user {auth_user_id} not found via main client (Postgrest 204). Will attempt to create.")
                profile_data = None
            elif isinstance(e_select, AttributeError) and "'NoneType' object has no attribute 'data'" in str(e_select):
                print(f"INFO: Profile for user {auth_user_id} not found via main client (execute returned None). Will attempt to create.")
                profile_data = None
            else:
                print(f"ERROR: Exception during profile select for {auth_user_id} using main client: {e_select} (Type: {type(e_select)})")
                profile_data = None # Assume not found if select errors out, proceed to create
    else:
        # This case (supabase_client being None) is problematic for select too, but was handled before.
        # If global supabase_client is None, the app has bigger issues.
        # For robustness, if it IS None, we should still try to use a service client for creation.
        print("WARN: Main Supabase client not available in get_or_create_user_profile for select. Will attempt creation with service client.")
        profile_data = None # Ensure we attempt creation

    if profile_data:
        return profile_data
    else:
        print(f"INFO: No profile found for user {auth_user_id}. Attempting to create profile.")
        new_profile_data = {
            'id': auth_user_id,
            'email': auth_user_email,
            'role': 'user'  # Default role
        }
        print(f"DEBUG: Attempting to insert profile with data: {new_profile_data}")

        # --- MODIFIED APPROACH: Use a new client instance for insert, configured with user's token --- 
        user_specific_client = None
        access_token_for_insert = session.get('access_token') # Get token from Flask session

        if not access_token_for_insert:
            print("ERROR: Access token not found in Flask session. Cannot create user-specific client for insert.")
            return None

        if SUPABASE_URL and os.getenv("SUPABASE_ANON_KEY"): # Use ANON key for this client init
            try:
                # NEW METHOD: Inject Authorization header directly
                print(f"INFO: Creating user-specific client for {auth_user_id} by directly injecting Authorization header.")
                client_headers = {
                    "apikey": os.getenv("SUPABASE_ANON_KEY"), # PostgREST still needs an API key
                    "Authorization": f"Bearer {access_token_for_insert}" # User's JWT for authentication
                }
                # auto_refresh_token and persist_session are false as we are using a short-lived client with a specific token.
                options = ClientOptions(auto_refresh_token=False, persist_session=False, headers=client_headers)
                # TRY USING SERVICE KEY FOR THE CLIENT INIT, WHILE HEADERS CONTAIN USER TOKEN + ANON KEY
                user_specific_client = create_client(SUPABASE_URL, os.getenv("SUPABASE_SERVICE_KEY"), options=options)
                print(f"INFO: User-specific Supabase client created with SERVICE_KEY for init, and direct Authorization header for user {auth_user_id}.")

            except Exception as e_client_init:
                print(f"CRITICAL ERROR: Failed to initialize or set session for user-specific client for profile insert: {e_client_init}")
                return None
        else:
            print("CRITICAL ERROR: Supabase URL or ANON Key missing for user-specific client in profile insert.")
            return None
        
        if not user_specific_client:
            print("ERROR: User-specific client for insert is unexpectedly None after init attempt.")
            return None

        # <<< START DIAGNOSTIC STEP >>>
        diagnostic_uid_from_rpc = None
        rpc_call_successful = False
        rpc_error_details = "No specific error details captured."

        try:
            print(f"DIAGNOSTIC: User-specific client before RPC: {user_specific_client}")
            if not user_specific_client:
                print("DIAGNOSTIC: user_specific_client is None before RPC call!")
                rpc_error_details = "user_specific_client was None before RPC attempt."
            else:
                function_to_call = 'get_current_auth_uid' # Ensure this is the correct function
                print(f"DIAGNOSTIC: Attempting to prepare RPC invoker for {function_to_call}() with user-specific client for auth_user_id: {auth_user_id}")
                
                invoker = None
                try:
                    invoker = user_specific_client.rpc(function_to_call, {})
                except Exception as e_rpc_prepare:
                    print(f"DIAGNOSTIC: Exception during user_specific_client.rpc() call itself (before execute): {e_rpc_prepare}")
                    rpc_error_details = f"Exception preparing RPC invoker: {e_rpc_prepare}"
                
                if invoker is None:
                    print(f"DIAGNOSTIC: user_specific_client.rpc('{function_to_call}') returned None directly. Cannot execute.")
                    rpc_error_details = f"RPC invoker for {function_to_call} was None."
                else:
                    print(f"DIAGNOSTIC: RPC invoker for {function_to_call} created: {invoker}. Attempting execute().")
                    raw_rpc_result = None
                    try:
                        # Perform the RPC call
                        raw_rpc_result = invoker.execute()
                        print(f"DIAGNOSTIC: Raw RPC Result for {function_to_call} (type: {type(raw_rpc_result)}): {raw_rpc_result}")

                        # Check if the result is an APIResponse object (has .data or .error)
                        if hasattr(raw_rpc_result, 'data') and raw_rpc_result.data is not None:
                            diagnostic_uid_from_rpc = raw_rpc_result.data
                            rpc_call_successful = True
                            print(f"DIAGNOSTIC: Successfully retrieved UID from {function_to_call} RPC (from .data): {diagnostic_uid_from_rpc}")
                        elif hasattr(raw_rpc_result, 'error') and raw_rpc_result.error is not None:
                            rpc_error_details = f"RPC call to {function_to_call} returned an error in response object: {raw_rpc_result.error}"
                            print(f"DIAGNOSTIC: {rpc_error_details}")
                        elif not hasattr(raw_rpc_result, 'data') and not hasattr(raw_rpc_result, 'error'):
                            # This case handles direct scalar returns (like UUID string or the 'Hello World' string)
                            diagnostic_uid_from_rpc = raw_rpc_result 
                            rpc_call_successful = True # Assume success if we got a scalar back from execute()
                            print(f"DIAGNOSTIC: RPC call to {function_to_call} returned a direct scalar value: {diagnostic_uid_from_rpc}")
                        else:
                            # Should not be reached if the above conditions are comprehensive
                            rpc_error_details = f"RPC response from {function_to_call} had unexpected structure. Content: {vars(raw_rpc_result) if hasattr(raw_rpc_result, '__dict__') else str(raw_rpc_result)}"
                            print(f"DIAGNOSTIC: {rpc_error_details}")
                    
                    except Exception as e_rpc_exec: # Catches errors from invoker.execute() or subsequent handling
                        rpc_error_details = f"Exception directly from {function_to_call} RPC execute() or its immediate handling: {e_rpc_exec} (Type: {type(e_rpc_exec)})"
                        print(f"DIAGNOSTIC: {rpc_error_details}")
                        # Adding more details from the exception if available
                        if hasattr(e_rpc_exec, 'message') : print(f"DIAGNOSTIC: Underlying error message: {e_rpc_exec.message}")
                        if hasattr(e_rpc_exec, 'details') : print(f"DIAGNOSTIC: Underlying error details: {e_rpc_exec.details}")
                        if hasattr(e_rpc_exec, 'hint') : print(f"DIAGNOSTIC: Underlying error hint: {e_rpc_exec.hint}")

            if rpc_call_successful and diagnostic_uid_from_rpc is not None:
                if str(diagnostic_uid_from_rpc) == str(auth_user_id):
                    print(f"DIAGNOSTIC: SUCCESS - {function_to_call} RPC UID MATCHES the expected auth_user_id ({auth_user_id}).")
                else:
                    print(f"DIAGNOSTIC: !!! MISMATCH !!! {function_to_call} RPC UID ({diagnostic_uid_from_rpc}) DOES NOT MATCH expected auth_user_id ({auth_user_id}).")
            else:
                print(f"DIAGNOSTIC: RPC call to {function_to_call} was not successful or did not return a comparable UID. Error context: {rpc_error_details}")
        
        except Exception as e_diag_outer:
            print(f"DIAGNOSTIC: Outer exception in diagnostic block: {e_diag_outer} (Type: {type(e_diag_outer)})")
            rpc_error_details = f"Outer diagnostic exception: {e_diag_outer}"
            print(f"DIAGNOSTIC: Falling back due to outer diagnostic error. Error context: {rpc_error_details}") # Added fallback log

        # <<< END DIAGNOSTIC STEP >>>

        try:
            # Use the new user_specific_client for the insert operation
            insert_response = user_specific_client.table('users').insert(new_profile_data).execute()
            
            if insert_response.data and len(insert_response.data) > 0:
                print(f"INFO: Profile created successfully for user {auth_user_id} using user-specific client.")
                return insert_response.data[0]
            else:
                print(f"ERROR: Failed to create profile for user {auth_user_id} using user-specific client. Insert response had no data/unexpected. Resp: {insert_response}")
                # Fallback: try to re-fetch with the same user_specific_client
                try:
                    refetch_response = user_specific_client.table('users').select('*').eq('id', auth_user_id).maybe_single().execute()
                    if refetch_response.data:
                        print(f"INFO: Successfully re-fetched profile for {auth_user_id} after user-specific client insert.")
                        return refetch_response.data
                    else:
                         print(f"ERROR: Re-fetch (user-specific client) after insert also found no profile for {auth_user_id}.")
                except Exception as refetch_e:
                    print(f"ERROR: Failed to re-fetch profile for {auth_user_id} (user-specific client): {refetch_e}")
                return None
        except PostgrestAPIError as e_postgrest_insert: # Catch Postgrest errors specifically
             print(f"ERROR: PostgrestAPIError during profile INSERT for user {auth_user_id} using user-specific client: Code: {e_postgrest_insert.code}, Message: {e_postgrest_insert.message}, Details: {getattr(e_postgrest_insert, 'details', 'N/A')}")
             return None
        except Exception as e_insert: # Catch other exceptions
            print(f"ERROR: Generic Exception during profile INSERT for user {auth_user_id} using user-specific client: {e_insert} (Type: {type(e_insert)})")
            return None
        # --- END MODIFIED APPROACH ---

# --- Authentication Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'user_role' not in session:
            print("INFO: login_required - User not in session. Redirecting to login.")
            return redirect(url_for('login', next=request.url))
        # Optional: Verify session with Supabase to ensure it's still valid
        # try:
        #     user_info = supabase_client.auth.get_user() # Requires access token in client
        #     if not user_info or not user_info.user:
        #         session.clear()
        #         return redirect(url_for('login', next=request.url))
        # except Exception as e:
        #     print(f"Session validation error: {e}")
        #     session.clear()
        #     return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(roles):
    """
    Decorator to ensure user has one of the required roles.
    `roles` should be a list of strings, e.g., ['admin', 'member']
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or 'user_role' not in session:
                print("INFO: roles_required - User not in session. Redirecting to login.")
                return redirect(url_for('login', next=request.url))
            user_role = session.get('user_role')
            if user_role not in roles:
                print(f"INFO: roles_required - User role '{user_role}' not in allowed roles: {roles}. Forbidden.")
                return jsonify({"error": "Forbidden: You do not have the required role."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Token Management ---
def get_user_token_balance(user_id: str) -> int:
    if not supabase_client or not user_id:
        return 0
    try:
        resp = supabase_client.table('payment_tokens').select('token_balance').eq('user_id', user_id).maybe_single().execute()
        if resp.data and 'token_balance' in resp.data:
            return resp.data['token_balance']
    except Exception as e:
        print(f"ERROR retrieving token balance for {user_id}: {e}")
    return 0


def add_user_tokens(user_id: str, delta: int) -> bool:
    if not supabase_client:
        return False
    try:
        current = get_user_token_balance(user_id)
        new_balance = current + delta
        supabase_client.table('payment_tokens').upsert({
            'user_id': user_id,
            'token_balance': new_balance,
            'updated_at': dt.now(timezone.utc).isoformat()
        }).execute()
        return True
    except Exception as e:
        print(f"ERROR updating token balance for {user_id}: {e}")
        return False


# --- Gemini and Twilio Functions (Existing) ---
def generate_scammer_message_gemini(language="en"):
    """
    Generates a kind and heartfelt message using the Gemini API in the specified language.
    """
    if not model:
        print("ERROR: generate_scammer_message_gemini called but Gemini model is not initialized.")
        return "Error: Gemini model not initialized."

    prompt = (
        f"Compose a single, unique, kind, and heartfelt SMS message, strictly under 150 characters, in {language}. "
        f"This message is for an individual potentially involved in scamming. "
        f"It should gently suggest considering a new direction, highlight that change is possible, "
        f"and propose using their abilities positively. Maintain an empathetic, hopeful tone, avoiding accusation or preaching. "
        f"Concentrate on the prospect of positive change and achieving peace or legitimate success. "
        f"The output MUST be ONLY the SMS message text itself, ready to send, and nothing else. "
        f"Generate a new, distinct message each time."
    )
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error generating message with Gemini: {e}")
        return f"I hope you find peace and a path that brings good to the world. It's never too late to choose a different way. (Error generating localized message, please try again)"

def send_sms_via_provider(phone_number, message):
    """Sends an SMS message using the configured Twilio provider."""
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    twilio_phone_number = os.environ.get('TWILIO_PHONE_NUMBER')

    if not all([account_sid, auth_token, twilio_phone_number]):
        print("ERROR: Twilio credentials (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER) not found in .env file.")
        return False, "SMS sending failed: Twilio credentials not configured."

    client = Client(account_sid, auth_token)
    try:
        message_response = client.messages.create(
            body=message,
            from_=twilio_phone_number,
            to=phone_number
        )
        print(f"SMS sent successfully! SID: {message_response.sid}")
        return True, f"SMS sent successfully! SID: {message_response.sid}"
    except Exception as e:
        print(f"Error sending SMS via Twilio: {e}")
        return False, str(e)

@app.route('/')
def index():
    token_balance = 0
    if 'user_id' in session:
        token_balance = get_user_token_balance(session['user_id'])
    return render_template('index.html', token_balance=token_balance)

# --- Authentication Routes ---
@app.route('/login')
def login():
    """Initiates the Google OAuth flow via Supabase."""
    if not supabase_client:
        return "Error: Supabase client not configured.", 500
    
    redirect_url_for_provider = url_for('auth_callback', _external=True)
    print(f"INFO: Initiating login, will redirect provider to: {redirect_url_for_provider}")

    try:
        # Removed PKCE code generation
        auth_url_response = supabase_client.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": redirect_url_for_provider,
                # "code_challenge": code_challenge, # Removed
                # "code_challenge_method": "S256",   # Removed
                # You can add 'scopes' here if needed, e.g., "email profile openid"
            }
        })
        if auth_url_response and auth_url_response.url:
            return redirect(auth_url_response.url)
        else:
            print(f"ERROR: Could not get auth URL from Supabase. Response: {auth_url_response}")
            return "Error: Could not initiate Google Sign-In. Check Supabase configuration.", 500
    except Exception as e:
        print(f"ERROR: Exception during sign_in_with_oauth: {e}") # Keep this for logging
        return "Error: Exception while initiating Google Sign-In.", 500

@app.route('/auth/callback')
def auth_callback():
    """Handles the OAuth callback from Supabase/Google by serving the JS handler page."""
    # This route now serves an HTML page with JS to handle the URL fragment.
    # It needs to pass Supabase URL and Anon Key to the template.
    
    supabase_url_for_client = os.getenv("SUPABASE_URL")
    supabase_anon_key_for_client = os.getenv("SUPABASE_ANON_KEY")

    if not supabase_url_for_client or not supabase_anon_key_for_client:
        print("CRITICAL ERROR: SUPABASE_URL or SUPABASE_ANON_KEY not found in .env for client-side JS in auth_callback_handler.html.")
        return "Configuration Error: Cannot provide necessary details to authentication handler. Please check server logs.", 500
        
    # Store the intended 'next' URL if it was passed to /login
    # So that /establish_flask_session can redirect appropriately after login
    next_url_param = request.args.get('next') # 'next' might be in query params from initial /login redirect
    if next_url_param:
        session['next_url_after_login'] = next_url_param
    # If not in args, check if it was already set in session by a previous step (less likely here but safe)
    elif 'next_url_after_login' not in session:
        session.pop('next_url_after_login', None) # Clear if not passed and not already set

    return render_template('auth_callback_handler.html', 
                           supabase_url=supabase_url_for_client, 
                           supabase_anon_key=supabase_anon_key_for_client)

@app.route('/establish_flask_session', methods=['POST'])
# This route is NOW primary for OAuth token processing from client-side
def establish_flask_session():
    """
    Receives token from client-side JS (after it's extracted from URL fragment),
    verifies it with Supabase, and establishes Flask session.
    """
    if not supabase_client:
        return jsonify({"error": "Supabase client not configured."}), 500

    data = request.get_json()
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token') # Optional but good to have

    if not access_token:
        return jsonify({"error": "Access token is required."}), 400

    try:
        # Set the session for the Supabase client using the provided tokens
        # This allows `get_user()` to work correctly using this server-side client instance.
        print(f"INFO: Received access token. Attempting to set session with Supabase.")
        set_session_response = supabase_client.auth.set_session(access_token, refresh_token)
        
        # Now get the user details using the authenticated client
        user_auth_response = supabase_client.auth.get_user() # Uses the token from set_session

        if user_auth_response and user_auth_response.user:
            # Store tokens in Flask session *before* calling get_or_create_user_profile
            # so that it can use them if it needs to create a user-specific client for insert.
            session['access_token'] = access_token
            if refresh_token:
                session['refresh_token'] = refresh_token

            user_profile = get_or_create_user_profile(user_auth_response)
            if user_profile and user_profile.get('id'):
                session['user_id'] = user_profile['id']
                session['user_email'] = user_profile['email']
                session['user_role'] = user_profile['role']
                # The tokens are already in the session from above.
                
                print(f"INFO: Flask session established for user {user_profile['id']}, role {user_profile['role']}")
                
                next_url = session.pop('next_url_after_login', url_for('profile')) # Redirect to profile or intended page
                return jsonify({"success": True, "message": "Session established.", "redirect_url": next_url})
            else:
                print(f"ERROR: Could not get or create user profile after setting session. Profile: {user_profile}")
                session.clear() # Clear session if profile retrieval/creation fails
                return jsonify({"error": "Failed to retrieve or create user profile."}), 500
        else:
            print(f"ERROR: Could not get user from Supabase with the provided token. Response: {user_auth_response}")
            session.clear() # Clear session if user cannot be fetched
            return jsonify({"error": "Invalid token or failed to get user from Supabase."}), 401

    except Exception as e:
        print(f"ERROR: Exception in establish_flask_session: {e}")
        session.clear() # Clear session on any exception
        # Check if the error is from Supabase and has a specific message
        if hasattr(e, 'message'): # Supabase APIError often has a message
            error_message = str(e.message) if isinstance(e.message, dict) else e.message
            if "Invalid JWT" in error_message or "Unauthorized" in error_message or "token is expired" in error_message.lower():
                 return jsonify({"error": f"Authentication failed: {error_message}"}), 401
        return jsonify({"error": f"Server error during session establishment: {str(e)}"}), 500


@app.route('/logout')
def logout():
    """Clears the Flask session and signs the user out from Supabase (client-side)."""
    if not supabase_client:
        # Even if supabase_client isn't there, clear local session.
        session.clear()
        return redirect(url_for('index'))

    access_token = session.get('access_token')
    if access_token:
        try:
            # We need to use the user's access token to sign them out from Supabase side.
            # The service key client cannot sign out a user directly like this.
            # This requires the user's context.
            # A better way is for the client (JS) to call supabase.auth.signOut().
            # Server-side can revoke refresh tokens, but global sign-out is tricky without user context.
            # For now, we primarily clear the Flask session.
            # supabase_client.auth.sign_out(access_token) # This would need the user's token
            # The service client cannot call supabase.auth.sign_out() for a user.
            # signOut should be called by the client (e.g., Supabase JS).
            # The server clears its own session.
            print(f"INFO: Signing out user {session.get('user_id')}. Global sign out should be handled by client.")
        except Exception as e:
            print(f"WARN: Error trying to sign out from Supabase, usually client-side task: {e}")
    
    session.clear()
    # Redirect to a page that can inform the user or use Supabase JS to ensure global signout
    # For now, just redirect to index.
    return redirect(url_for('index'))


@app.route('/profile')
# @login_required
def profile():
    """Displays user profile information."""
    if 'user_id' in session:
        user_info = {
            "id": session['user_id'],
            "email": session.get('user_email'),
            "role": session.get('user_role')
        }
        return jsonify(user_info)
    else:
        # This case should ideally be caught by @login_required
        return redirect(url_for('login'))


@app.route('/create_checkout_session', methods=['POST'])
@login_required
def create_checkout_session():
    if not STRIPE_PRICE_ID:
        return jsonify({'error': 'Stripe price not configured'}), 500
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            mode='payment',
            line_items=[{'price': STRIPE_PRICE_ID, 'quantity': 1}],
            success_url=url_for('index', _external=True),
            cancel_url=url_for('index', _external=True),
            metadata={'user_id': session['user_id'], 'tokens': 1}
        )
        return jsonify({'checkout_url': checkout_session.url})
    except Exception as e:
        print(f"Stripe checkout error: {e}")
        return jsonify({'error': 'Failed to create checkout session'}), 500


@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    if not STRIPE_WEBHOOK_SECRET:
        return '', 400
    payload = request.get_data()
    sig = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        print(f"Webhook error: {e}")
        return '', 400

    if event['type'] == 'checkout.session.completed':
        session_obj = event['data']['object']
        user_id = session_obj['metadata'].get('user_id')
        tokens = int(session_obj['metadata'].get('tokens', '1'))
        add_user_tokens(user_id, tokens)

    return '', 200

@app.route('/send_sms', methods=['POST'])
@login_required
def handle_send_sms():
    if not supabase_client:
        return jsonify({"error": "Database service not configured. Cannot schedule messages."}), 500
    if not model: 
         print("ERROR: /send_sms called but Gemini model not initialized. Sending error to client.")
         return jsonify({"error": "Backend AI service not configured. Cannot generate/schedule message."}), 500

    data = request.get_json()
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Authentication required."}), 401
    phone_number = data.get('phone_number')
    language = data.get('language', 'en')
    num_messages = data.get('num_messages', 1)
    num_days = data.get('num_days', 1) # For scheduled sends
    send_time_str = data.get('send_time') # HH:MM format or empty

    if not phone_number:
        return jsonify({"error": "Phone number is required."}), 400
    if not isinstance(num_messages, int) or num_messages < 1:
        return jsonify({"error": "Number of messages must be a positive integer."}), 400
    if not send_time_str: # For instant send, num_days is effectively 1 (all messages now)
        pass # num_days is not strictly validated here for instant send
    elif not isinstance(num_days, int) or num_days < 1: # For scheduled send
        return jsonify({"error": "Number of days must be a positive integer for scheduled send."}), 400

    # Check token balance
    token_balance = get_user_token_balance(user_id)
    if token_balance < num_messages:
        return jsonify({"error": "Insufficient token balance."}), 400

    messages_to_schedule = []
    
    if not send_time_str: # Instant Send
        current_utc_dt = dt.now(timezone.utc)
        message_stagger_offset_seconds = 0
        for _ in range(num_messages):
            send_at_dt = current_utc_dt + timedelta(seconds=message_stagger_offset_seconds)
            messages_to_schedule.append({
                'phone_number': phone_number,
                'language': language,
                'send_at': send_at_dt.isoformat(),
                'status': 'pending'
            })
            message_stagger_offset_seconds += 5 
    else: # Scheduled Send
        try:
            target_time_obj = dt_time.fromisoformat(send_time_str)
        except ValueError:
            return jsonify({"error": "Invalid time format. Please use HH:MM."}), 400

        current_server_local_dt = dt.now() 
        schedule_start_date_local = current_server_local_dt.date()

        potential_first_schedule_dt_local_naive = dt.combine(schedule_start_date_local, target_time_obj)
        if potential_first_schedule_dt_local_naive < current_server_local_dt:
            schedule_start_date_local += timedelta(days=1)

        base_msgs_per_day = num_messages // num_days
        extra_msgs = num_messages % num_days

        for day_idx in range(num_days):
            daily_message_stagger_offset_seconds = 0 

            messages_for_this_day = base_msgs_per_day + (1 if day_idx < extra_msgs else 0)
            
            if messages_for_this_day == 0:
                if num_messages > 0 and day_idx < num_messages: 
                    messages_for_this_day = 1
                else:
                    continue 

            actual_scheduled_date_for_day_local = schedule_start_date_local + timedelta(days=day_idx)
            base_naive_dt_to_send_local = dt.combine(actual_scheduled_date_for_day_local, target_time_obj)

            for _ in range(messages_for_this_day):
                local_tz = current_server_local_dt.astimezone().tzinfo 
                
                if base_naive_dt_to_send_local.tzinfo is not None: # Ensure it's naive
                     base_naive_dt_to_send_local = base_naive_dt_to_send_local.replace(tzinfo=None)

                aware_dt_local = local_tz.localize(base_naive_dt_to_send_local) # Apply local timezone
                utc_dt_to_send = aware_dt_local.astimezone(timezone.utc)  # Convert to UTC
                
                final_utc_dt_to_send = utc_dt_to_send + timedelta(seconds=daily_message_stagger_offset_seconds)
                
                messages_to_schedule.append({
                    'phone_number': phone_number,
                    'language': language,
                    'send_at': final_utc_dt_to_send.isoformat(),
                    'status': 'pending'
                })
                daily_message_stagger_offset_seconds += 5

    if not messages_to_schedule:
         if num_messages > 0: 
              return jsonify({"error": "Failed to calculate any send times. Please check scheduling parameters."}), 400  
         else: 
              return jsonify({"message": "No messages to schedule (0 requested)."}), 200

    try:
        print(f"Attempting to insert: {messages_to_schedule}") 
        response_tuple, exec_count = supabase_client.table('scheduled_messages').insert(messages_to_schedule).execute()
        
        if response_tuple and \
           isinstance(response_tuple, tuple) and \
           len(response_tuple) == 2 and \
           response_tuple[0] == 'data' and \
           isinstance(response_tuple[1], list):
            
            inserted_items_list = response_tuple[1]
            num_inserted = len(inserted_items_list)
            add_user_tokens(user_id, -num_inserted)
            new_balance = get_user_token_balance(user_id)
            return jsonify({"message": f"{num_inserted} message(s) scheduled successfully.", "token_balance": new_balance})
        
        elif hasattr(response_tuple, 'data') and isinstance(response_tuple.data, list):
            num_affected = len(response_tuple.data)
            add_user_tokens(user_id, -num_affected)
            new_balance = get_user_token_balance(user_id)
            return jsonify({"message": f"{num_affected} item(s) processed successfully.", "token_balance": new_balance})
            
        else: 
            print(f"WARNING: Supabase operation executed but response data format is unexpected. Response: {response_tuple}, Count: {exec_count}")
            return jsonify({"message": "Request processed, but confirmation or count of affected items is unclear. Please check logs."}), 200

    except Exception as e:
        print(f"Error inserting into Supabase. Type: {type(e)}")
        print(f"Error details (str): {e}") 
        print(f"Error details (repr): {repr(e)}")
        # Enhanced debugging for APIError specifically
        if hasattr(e, 'json') and callable(e.json):
            try:
                print(f"Parsed e.json() payload: {e.json()}") # Supabase APIError often has a json payload
            except:
                print("Could not parse e.json()")
        if hasattr(e, 'message'):
            print(f"Exception e.message: {e.message}")
        if hasattr(e, 'details'):
             print(f"Exception e.details: {e.details}")
        if hasattr(e, 'args'):
            print(f"Exception e.args: {e.args}")
        
        return jsonify({"error": f"An error occurred while scheduling the messages: {str(e)}"}), 500

# --- Background Scheduler ---
def process_pending_messages():
    if not supabase_client:
        print("SCHEDULER: Supabase client not initialized. Cannot process messages.")
        return
    if not model:
        print("SCHEDULER: Gemini model not initialized. Cannot generate messages.")
        return

    current_pid = os.getpid()
    print(f"SCHEDULER (PID: {current_pid}): Checking for pending messages at {dt.now(timezone.utc).isoformat()}...")

    try:
        while True: # Loop to try and process multiple messages if available, one by one
            now_utc_iso = dt.now(timezone.utc).isoformat()
            potential_message_row = None # Initialize
            
            try:
                # 1. Fetch ONE due pending message
                fetch_response = supabase_client.table('scheduled_messages')\
                    .select('*')\
                    .eq('status', 'pending')\
                    .lte('send_at', now_utc_iso)\
                    .order('send_at', desc=False)\
                    .limit(1)\
                    .maybe_single()\
                    .execute()
                
                potential_message_row = fetch_response.data

            except PostgrestAPIError as e_api: # Specifically catch PostgrestAPIError
                if (hasattr(e_api, 'code') and e_api.code == '204') or \
                   (hasattr(e_api, 'code') and e_api.code == 'PGRST116'): # PGRST116 is 'Requested range not satisfiable'
                    # These codes indicate no message was found, which is normal for the scheduler.
                    # print(f"SCHEDULER (PID: {current_pid}): No pending messages found (APIError code {e_api.code}: {e_api.message}).")
                    potential_message_row = None
                else:
                    # For other Postgrest API errors during fetch, log it and break.
                    print(f"SCHEDULER (PID: {current_pid}): PostgrestAPIError during Supabase fetch operation: {e_api} (Code: {e_api.code}, Message: {e_api.message}, Details: {getattr(e_api, 'details', 'N/A')})")
                    break # Exit the while True loop for this processing cycle
            except AttributeError as e_attr: # Catch if fetch_response is None and .data is accessed
                if "'NoneType' object has no attribute 'data'" in str(e_attr):
                    # This can happen if .execute() returns None directly and .data is accessed before PostgrestAPIError is raised/caught.
                    # print(f"SCHEDULER (PID: {current_pid}): No pending messages found (fetch returned NoneType, AttributeError).")
                    potential_message_row = None
                else:
                    print(f"SCHEDULER (PID: {current_pid}): AttributeError during Supabase fetch: {e_attr}")
                    break
            except Exception as e_fetch: # Catch any other generic exceptions during fetch
                print(f"SCHEDULER (PID: {current_pid}): Generic error during Supabase fetch: {e_fetch} (Type: {type(e_fetch)})")
                break
            
            if not potential_message_row:
                # print(f"SCHEDULER (PID: {current_pid}): No pending messages due at this time.")
                break # No more messages to process in this cycle, exit while True

            message_id = potential_message_row['id']
            phone_number = potential_message_row['phone_number']
            language = potential_message_row['language']
            processing_status_val = f'processing_pid{current_pid}_at{dt.now(timezone.utc).timestamp()}'

            print(f"SCHEDULER (PID: {current_pid}): Potential message ID {message_id} for {phone_number}. Attempting to claim...")

            # 2. Atomically claim the message by updating its status
            #    Only update if it's still 'pending'. Use returning='representation' 
            #    to get the updated row if successful.
            claim_update_payload = {'status': processing_status_val, 'send_result': 'Claimed for processing'}
            claim_response = supabase_client.table('scheduled_messages')\
                .update(claim_update_payload)\
                .eq('id', message_id)\
                .eq('status', 'pending')\
                .execute() # Removed returning='representation' for now, as it might vary by client version if default is already representation. Let's test success by checking data.

            # Check if the update was successful by seeing if data is returned (many clients return data on successful update)
            if claim_response.data and len(claim_response.data) == 1:
                claimed_message_row = claim_response.data[0]
                print(f"SCHEDULER (PID: {current_pid}): Successfully claimed message ID {message_id}. Current status: {claimed_message_row.get('status')}")
                
                # 3. Process the claimed message (Generate and Send)
                generated_message_body = None
                generation_error = None
                final_status = claimed_message_row.get('status') # Should be our processing_status_val
                final_send_result = claimed_message_row.get('send_result')

                try:
                    generated_message_body = generate_scammer_message_gemini(language)
                    if "Error:" in generated_message_body:
                        generation_error = generated_message_body
                        generated_message_body = None
                except Exception as e:
                    generation_error = str(e)
                    print(f"SCHEDULER (PID: {current_pid}): Error generating message for ID {message_id}: {e}")

                if generation_error or not generated_message_body:
                    final_status = 'failed_generation'
                    final_send_result = f"Generation failed: {generation_error or 'Unknown error'}"
                else:
                    # Send SMS if generation was successful
                    send_success, send_result_details = False, "Provider send error"
                    try:
                        send_success, send_result_details = send_sms_via_provider(phone_number, generated_message_body)
                        final_send_result = send_result_details
                    except Exception as e:
                        final_send_result = str(e)
                        print(f"SCHEDULER (PID: {current_pid}): Error sending SMS for ID {message_id} via provider: {e}")
                    
                    final_status = 'sent' if send_success else 'failed_send'

                # 4. Final update for the processed message
                final_update_payload = {
                    'message_body': generated_message_body,
                    'status': final_status,
                    'send_result': final_send_result
                }
                try:
                    supabase_client.table('scheduled_messages')\
                        .update(final_update_payload)\
                        .eq('id', message_id)\
                        .execute()
                    print(f"SCHEDULER (PID: {current_pid}): Message ID {message_id} final update. Status: {final_status}, Result: {(final_send_result or '')[:100]}")
                except Exception as e:
                    print(f"SCHEDULER (PID: {current_pid}): CRITICAL - Failed to do FINAL update for message ID {message_id}: {e}")
            
            elif claim_response.data and len(claim_response.data) > 1:
                # Should not happen with .eq('id', message_id)
                print(f"SCHEDULER (PID: {current_pid}): WARNING - Claim update for message ID {message_id} returned multiple rows: {len(claim_response.data)}")
            else:
                # This case means claim_response had no data or len(data) == 0
                # Could be that status was not 'pending' or ID didn't match (less likely for ID)
                print(f"SCHEDULER (PID: {current_pid}): Failed to claim message ID {message_id} (already processed or status changed). Moving on.")
                # No need to break here, the outer loop will try to fetch the next available message
                # If there was a message but we couldn't claim it, it means another instance got it. We can try fetching another one.
        
        # print(f"SCHEDULER (PID: {current_pid}): Finished processing cycle.")

    except Exception as e:
        print(f"SCHEDULER (PID: {current_pid}): Error in process_pending_messages main try block: {e}")
        import traceback
        traceback.print_exc() # Print full traceback for debugging

def scheduler_loop():
    print("SCHEDULER: Background scheduler loop started.")
    while True:
        try:
            process_pending_messages()
        except Exception as e:
            # Catch broad exceptions to prevent the scheduler thread from crashing
            print(f"SCHEDULER: Unhandled exception in scheduler_loop: {e}")
            # Potentially add more robust error reporting here (e.g., to a log file or monitoring service)
        time.sleep(15) # Check every 15 seconds

if __name__ == '__main__':
    current_pid = os.getpid()
    # When using the Flask reloader (app.debug=True), WERKZEUG_RUN_MAIN is set to 'true' 
    # only in the reloaded child process that actually runs the app.
    # If not in debug mode, WERKZEUG_RUN_MAIN will not be set, so we start directly.
    
    should_start_scheduler = False
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        print(f"INFO: Werkzeug reloader's child process (PID: {current_pid}). Will start scheduler.")
        should_start_scheduler = True
    elif not app.debug: # os.environ.get("FLASK_DEBUG") != "1" might also be a check if app.debug is not yet set
        print(f"INFO: Non-debug mode / No reloader (PID: {current_pid}). Will start scheduler.")
        should_start_scheduler = True
    else:
        print(f"INFO: Flask reloader's parent/monitor process (PID: {current_pid}). Scheduler will start in the child process.")

    if should_start_scheduler:
        # Simple check to prevent starting multiple threads if this block were somehow re-entered.
        # For daemon threads, this is less critical but good practice.
        if not hasattr(app, '_scheduler_thread_started_in_pid') or app._scheduler_thread_started_in_pid != current_pid:
            scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
            scheduler_thread.start()
            app._scheduler_thread_started_in_pid = current_pid
            print(f"INFO: Background scheduler thread initiated (PID: {current_pid}).")
        else:
            print(f"INFO: Background scheduler thread already noted as started for PID {current_pid}. Not starting again.")
            
    app.run(debug=True, port=5001) 