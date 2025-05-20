#!/bin/bash

echo "🚀 Starting project setup..."

# --- Check for Python 3 ---
if ! command -v python3 &> /dev/null
then
    echo "❌ ERROR: Python 3 could not be found. Please install Python 3 and try again."
    exit 1
fi
echo "✅ Python 3 found."

# --- Create Virtual Environment ---
VENV_NAME=".venv"
if [ -d "$VENV_NAME" ]; then
    echo "ℹ️ Virtual environment '$VENV_NAME' already exists."
else
    echo "🐍 Creating Python virtual environment named '$VENV_NAME'..."
    python3 -m venv $VENV_NAME
    if [ $? -ne 0 ]; then
        echo "❌ ERROR: Failed to create virtual environment."
        exit 1
    fi
    echo "✅ Virtual environment created."
fi

echo ""
echo "👉 IMPORTANT: Activate the virtual environment by running:"
echo "   source $VENV_NAME/bin/activate"
echo ""
echo "   After activating, run the next step in this script or install requirements manually:"
echo "   pip install -r requirements.txt"
echo ""
echo "Waiting for you to activate the virtual environment in this terminal..."
echo "If you have ALREADY ACTIVATED it in THIS terminal session, you can ignore the prompt below."
echo "If not, please open a NEW terminal, activate it, then re-run this script OR run 'pip install -r requirements.txt' manually there."
echo ""

# --- Attempt to Install Requirements (User must have activated venv) ---
# This part is a bit tricky as the script itself can't activate the venv for the current shell.
# We rely on the user to do it.

echo "⚙️ Trying to install dependencies from requirements.txt..."
echo "   If this step fails, please ensure your virtual environment ('$VENV_NAME') is activated"
echo "   (source $VENV_NAME/bin/activate) and then run 'pip install -r requirements.txt' manually."

# Check if pip is from the virtual environment (a heuristic)
PIP_PATH=$(which pip)
if [[ "$PIP_PATH" == *"$VENV_NAME/bin/pip"* ]]; then
    echo "✅ Pip seems to be from the virtual environment. Proceeding with installation..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "⚠️ WARNING: 'pip install -r requirements.txt' failed. "
        echo "   Please ensure the virtual environment is active and try installing manually."
    else
        echo "✅ Dependencies installed successfully."
    fi
else
    echo "⚠️ WARNING: Pip does not seem to be from the '$VENV_NAME' virtual environment."
    echo "   Path to pip: $PIP_PATH"
    echo "   Skipping automatic dependency installation. Please activate the venv and run 'pip install -r requirements.txt' manually."
fi


# --- .env File Setup ---
echo ""
echo "🔑 Setting up .env file..."
if [ -f ".env" ]; then
    echo "ℹ️ '.env' file already exists. Please ensure it contains all necessary variables."
else
    echo "📝 '.env' file not found. Please create a '.env' file in the root directory"
    echo "   and add the following environment variables with your actual values:"
    echo ""
    echo "   FLASK_SECRET_KEY=your_strong_random_secret_key"
    echo "   GEMINI_API_KEY=your_gemini_api_key"
    echo "   SUPABASE_URL=your_supabase_project_url"
    echo "   SUPABASE_ANON_KEY=your_supabase_anon_key"
    echo "   SUPABASE_SERVICE_KEY=your_supabase_service_role_key"
    echo "   # Optional: Twilio credentials if you use the SMS functionality"
    echo "   TWILIO_ACCOUNT_SID=your_twilio_account_sid"
    echo "   TWILIO_AUTH_TOKEN=your_twilio_auth_token"
    echo "   TWILIO_PHONE_NUMBER=your_twilio_phone_number"
    echo ""
fi

echo ""
echo "🎉 Setup script finished."
echo "--- Next Steps ---"
echo "1. Ensure your virtual environment ('source $VENV_NAME/bin/activate') is active."
echo "2. If dependencies didn't install, run: pip install -r requirements.txt"
echo "3. Populate your '.env' file with the necessary API keys and URLs."
echo "4. Run the application using: python3 app.py"
echo ""
echo "Happy coding! ✨" 