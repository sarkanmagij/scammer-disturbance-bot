# Scammer Disturbance Bot (Kind Words of Change)

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![Gemini API](https://img.shields.io/badge/Gemini%20API-v2.0-purple.svg)](https://ai.google.dev/)
[![Twilio](https://img.shields.io/badge/Twilio-SMS-red.svg)](https://www.twilio.com/)
[![Supabase](https://img.shields.io/badge/Supabase-Database-orange.svg)](https://supabase.io/)

## Overview

The Scammer Disturbance Bot is a Flask-based web application designed to send a series of kind, heartfelt, and unique SMS messages to individuals who might be involved in scamming activities. The goal is to gently encourage them to reconsider their path and use their skills for positive endeavors. Messages are generated by Google's Gemini AI and can be scheduled to be sent over several days at a specific time, or sent instantly.

## Features

*   **AI-Powered Message Generation:** Uses Google Gemini 2.0 Flash model to create unique, empathetic messages.
*   **Multi-Language Support:** Generate messages in different languages (default is English).
*   **SMS Delivery:** Sends messages via Twilio API.
*   **Message Scheduling:** Schedule messages to be sent at a specific time daily for a defined number of days.
*   **Instant Send:** Option to send all messages immediately with a small stagger.
*   **Web Interface:** Simple Flask frontend to input phone number, language, message count, schedule parameters.
*   **Background Scheduler:** A persistent background thread processes scheduled messages from a Supabase database.
*   **Secure Configuration:** Relies on environment variables for API keys and sensitive credentials.
*   **Token Payments:** Users can purchase SMS tokens via Stripe which are stored in Supabase.

## Tech Stack

*   **Backend:** Python, Flask
*   **AI Model:** Google Gemini API (via `google-generativeai` library)
*   **SMS Provider:** Twilio API (via `twilio` library)
*   **Database & Scheduling Backend:** Supabase (via `supabase-py` library)
*   **Environment Management:** `python-dotenv`

## Prerequisites

*   Python 3.7+ and `pip`
*   A Twilio account with an active phone number, Account SID, and Auth Token.
*   A Google Gemini API Key.
*   A Supabase project with a database.

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/sarkanmagij/scammer-disturbance-bot.git
    cd scammer-disturbance-bot
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up Environment Variables:**
    Create a `.env` file in the root directory of the project and add the following credentials:

    ```env
    GEMINI_API_KEY="YOUR_GEMINI_API_KEY"

    TWILIO_ACCOUNT_SID="YOUR_TWILIO_ACCOUNT_SID"
    TWILIO_AUTH_TOKEN="YOUR_TWILIO_AUTH_TOKEN"
    TWILIO_PHONE_NUMBER="+YOUR_TWILIO_PHONE_NUMBER"

    SUPABASE_URL="YOUR_SUPABASE_PROJECT_API_URL"
    SUPABASE_SERVICE_KEY="YOUR_SUPABASE_PROJECT_SERVICE_ROLE_KEY"

    # Stripe configuration for purchasing SMS tokens
    STRIPE_SECRET_KEY="YOUR_STRIPE_SECRET_KEY"
    STRIPE_WEBHOOK_SECRET="YOUR_STRIPE_WEBHOOK_SECRET"
    STRIPE_PRICE_ID="PRICE_ID_FOR_TOKEN_PACKAGE"
    ```

    *   Replace placeholders with your actual credentials.
    *   `SUPABASE_URL` is your project's API URL (e.g., `https://your-project-id.supabase.co`).
    *   `SUPABASE_SERVICE_KEY` is your project's `service_role` key (found in Project Settings > API). **Keep this key secure!**

5.  **Set up Supabase Database Table:**
    In your Supabase project, create a table named `scheduled_messages` with the following schema. You can use the Supabase SQL Editor:

    ```sql
    CREATE TABLE public.scheduled_messages (
        id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
        phone_number TEXT NOT NULL,
        language TEXT DEFAULT 'en' NOT NULL,
        send_at TIMESTAMPTZ NOT NULL,
        status TEXT DEFAULT 'pending' NOT NULL, -- e.g., pending, processing_pidX_atY, sent, failed_generation, failed_send
        message_body TEXT NULL, -- Populated after message generation
        send_result TEXT NULL -- Populated after SMS send attempt
    );

    -- Optional: Add an index for faster querying by the scheduler
    CREATE INDEX idx_scheduled_messages_status_send_at ON public.scheduled_messages (status, send_at);
    ```

6.  **Set up Payment Tokens Table:**
    Create a simple table to track SMS token balances:

    ```sql
    CREATE TABLE public.payment_tokens (
        user_id UUID PRIMARY KEY,
        token_balance INTEGER DEFAULT 0,
        updated_at TIMESTAMPTZ DEFAULT now()
    );
    ```

## Running the Application

1.  Ensure your virtual environment is activated and all environment variables are correctly set in the `.env` file.
2.  Start the Flask development server:
    ```bash
    python3 app.py
    ```
3.  The application will typically be available at `http://127.0.0.1:5001`.

## Using the Application

1.  Open your web browser and navigate to `http://127.0.0.1:5001`.
2.  Fill in the form:
    *   **Phone Number:** The target phone number (international format, e.g., `+12223334444`).
    *   **Language Code:** ISO 639-1 language code for message generation (e.g., `en` for English, `es` for Spanish).
    *   **Number of Messages:** Total messages to send.
    *   **Number of Days (for scheduled send):** Distribute messages over this many days.
    *   **Send Time (HH:MM, for scheduled send):** Time to send messages each day (server's local time). Leave blank for instant sending.
3.  Click "Schedule/Send Messages".

## How It Works

*   **Frontend:** A simple HTML page (`templates/index.html`) served by Flask allows users to input parameters.
*   **API Endpoint (`/send_sms`):**
    *   Receives form data.
    *   Calculates send times for each message (either instant with a stagger or scheduled daily).
    *   Inserts message details into the `scheduled_messages` table in Supabase with a `pending` status.
*   **Background Scheduler (`scheduler_loop` in `app.py`):
    *   Runs in a separate thread, periodically (every 15 seconds) checking the `scheduled_messages` table for due messages.
    *   Atomically claims a due message by updating its status to `processing_pidX_atY` to prevent multiple workers from processing the same message (important for scalability or multiple instances, though current setup is single-threaded scheduler).
    *   **Message Generation:** Calls `generate_scammer_message_gemini` which uses the Gemini API to compose a message.
    *   **SMS Sending:** Calls `send_sms_via_provider` which uses the Twilio API.
    *   Updates the message record in Supabase with the generated message body, final status (`sent`, `failed_generation`, `failed_send`), and send result.

## Troubleshooting

*   **API Key Errors:** Ensure all API keys (`GEMINI_API_KEY`, Twilio, Supabase) are correctly set in the `.env` file and that the services are active and have sufficient quotas.
*   **Scheduler Not Processing Messages:**
    *   Check the application logs for errors from the scheduler thread.
    *   Verify Supabase connectivity and that the `scheduled_messages` table exists with the correct schema.
    *   The `AttributeError: 'NoneType' object has no attribute 'data'` in the scheduler logs might indicate issues with the Supabase query returning `None` unexpectedly. Recent fixes aim to handle this more gracefully by logging and skipping the cycle.
*   **Old Processes After Code Changes:** If you see errors from old Process IDs (PIDs) in the logs after Flask reloads, it might be due to old scheduler threads not terminating cleanly. It's good practice to fully stop and restart the `python3 app.py` process after significant code changes to ensure only the new code is running.
*   **Twilio Errors:** Check your Twilio dashboard for specific error codes if SMS sending fails. Ensure the `TWILIO_PHONE_NUMBER` is correctly formatted and capable of sending SMS to the target region.

## Contributing

Contributions, issues, and feature requests are welcome. Please feel free to fork the repository, make changes, and submit a pull request.

## License

This project is open source. Please feel free to use, modify, and distribute it as you see fit. (Consider adding a specific license like MIT if you wish).

---

*This README was generated with assistance from an AI coding partner.* 
