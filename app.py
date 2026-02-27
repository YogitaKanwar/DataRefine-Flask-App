import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')


if not hasattr(np, 'VisibleDeprecationWarning'):
    np.VisibleDeprecationWarning = type('VisibleDeprecationWarning', (DeprecationWarning,), {})


try:
    import pkg_resources
except ImportError:
    try:
        import pip._vendor.pkg_resources as pkg_resources
    except ImportError:
        pkg_resources = None
    sys.modules['pkg_resources'] = pkg_resources

# STANDARD IMPORTS
import os
import io
import pandas as pd
import requests
import sweetviz as sv
import cachecontrol
import google.auth.transport.requests
from flask import Flask, session, abort, redirect, url_for, request, render_template, send_from_directory, send_file
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from werkzeug.utils import secure_filename

app = Flask("Google Login App")
app.secret_key = "CodeSpecialist.com"

#FOLDER SETUP
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
REPORT_FOLDER = os.path.join(BASE_DIR, 'static', 'reports')

# Folder creation logic
for folder in [UPLOAD_FOLDER, REPORT_FOLDER, os.path.join(BASE_DIR, 'templates')]:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# GOOGLE OAUTH SETUP
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = '1'
GOOGLE_CLIENT_ID = "72442361807-4iapfrqgejg139jio41drciihb9dmuqa.apps.googleusercontent.com"
client_secrets_file = os.path.join(BASE_DIR, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


# LOGIC HELPERS
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)

    wrapper.__name__ = function.__name__
    return wrapper


def perform_cleaning(df):

    initial_count = len(df)
    df = df.drop_duplicates()
    removed_duplicates = initial_count - len(df)

    for col in df.columns:
        if df[col].isnull().any():
            if df[col].dtype in ['float64', 'int64']:
                df[col] = df[col].fillna(df[col].mean())
            else:
                df[col] = df[col].fillna('Unknown')
    return df, removed_duplicates


#ROUTES
@app.route("/")
def index():
    if "google_id" in session:
        return redirect("/dashboard")
    return "Welcome! Please <a href='/login'><button>Login with Google</button></a>"


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    if session.get("state") != request.args.get("state"):
        abort(403)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    request_session = requests.Session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)
    id_info = id_token.verify_oauth2_token(id_token=credentials.id_token, request=token_request,
                                           audience=GOOGLE_CLIENT_ID)
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/dashboard")


@app.route("/dashboard")
@login_is_required
def dashboard():
    return render_template('index.html', name=session.get("name"))


@app.route("/process", methods=['POST'])
@login_is_required
def process():
    if 'file' not in request.files:
        return render_template('index.html', msg="No file selected", name=session.get("name"))

    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', msg="No selected file", name=session.get("name"))

    action = request.form.get('action')
    df = pd.read_csv(file)
    if action == 'profile':

        filename = secure_filename(file.filename)
        report_filename = f"report_{session['google_id']}.html"  \
        report_path = os.path.join(REPORT_FOLDER, report_filename)


        report = sv.analyze(df)


        report.show_html(
            filepath=report_path,
            open_browser=False,
            layout='vertical',
            scale=1.0
        )

        return render_template('index.html',
                                msg="Profiling Complete!",
                                link=url_for('static', filename='reports/' + report_filename),
                                name=session.get("name"))

    elif action == 'clean':

        df_cleaned, count = perform_cleaning(df)


        buffer = io.BytesIO()
        df_cleaned.to_csv(buffer, index=False)
        buffer.seek(0)


        return send_file(
            buffer,
            as_attachment=True,
            download_name="cleaned_data.csv",
            mimetype='text/csv'
        )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)