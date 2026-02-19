"""
JWT Hacking Workshop - Intentionally Vulnerable Application
FOR EDUCATIONAL PURPOSES ONLY

This application contains intentional security vulnerabilities to teach JWT attacks.
DO NOT deploy this in production or on any publicly accessible server.
"""

from flask import Flask, render_template, request, redirect, url_for, make_response
import jwt
import os
import base64

app = Flask(__name__)

# ============================================================================
# CONFIGURATION - Intentionally weak/vulnerable settings
# ============================================================================

# Lab 3: Weak secret key (easily brute-forced)
WEAK_SECRET = "secret1"

# Lab 5: RSA Keys
KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys')

def load_keys():
    """Load RSA keys for Lab 5"""
    try:
        with open(os.path.join(KEYS_DIR, 'private.pem'), 'r') as f:
            private_key = f.read()
        with open(os.path.join(KEYS_DIR, 'public.pem'), 'r') as f:
            public_key = f.read()
        return private_key, public_key
    except FileNotFoundError:
        return None, None

PRIVATE_KEY, PUBLIC_KEY = load_keys()

# Flags for each lab
FLAGS = {
    'lab1': 'FLAG{unverified_signature_bypass}',
    'lab2': 'FLAG{none_algorithm_attack}',
    'lab3': 'FLAG{weak_secret_cracked}',
    'lab4': 'FLAG{kid_path_traversal_pwned}',
    'lab5': 'FLAG{algorithm_confusion_rs256_to_hs256}'
}

# ============================================================================
# HOMEPAGE
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')

# ============================================================================
# LAB 1: Unverified Signature
# Vulnerability: Server decodes JWT without verifying signature
# ============================================================================

@app.route('/lab1', methods=['GET'])
def lab1_login():
    return render_template('login.html',
                         lab_num=1,
                         lab_title="Unverified Signature",
                         description="The server decodes JWT tokens but doesn't verify the signature. Can you become admin?",
                         hint="Try modifying the payload after getting a valid token...")

@app.route('/lab1', methods=['POST'])
def lab1_auth():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Simple login - any credentials work
    if username and password:
        # Create a token with role=user
        token = jwt.encode(
            {"username": username, "role": "user"},
            "lab1_secret_key",
            algorithm="HS256"
        )

        response = make_response(redirect(url_for('lab1_dashboard')))
        response.set_cookie('token', token)
        return response

    return render_template('login.html',
                         lab_num=1,
                         lab_title="Unverified Signature",
                         error="Please provide credentials")

@app.route('/lab1/dashboard')
def lab1_dashboard():
    token = request.cookies.get('token')

    if not token:
        return redirect(url_for('lab1_login'))

    try:
        # VULNERABILITY: Signature verification is disabled!
        # This allows attackers to modify the payload without knowing the secret
        payload = jwt.decode(token, options={"verify_signature": False})

        if payload.get('role') == 'admin':
            return render_template('success.html',
                                 lab_num=1,
                                 flag=FLAGS['lab1'],
                                 message="You bypassed signature verification!")
        else:
            return render_template('dashboard.html',
                                 lab_num=1,
                                 username=payload.get('username', 'unknown'),
                                 role=payload.get('role', 'unknown'),
                                 token=token)
    except Exception as e:
        return render_template('error.html', error=str(e), lab_num=1)

# ============================================================================
# LAB 2: None Algorithm
# Vulnerability: Server accepts 'none' algorithm, skipping verification
# ============================================================================

@app.route('/lab2', methods=['GET'])
def lab2_login():
    return render_template('login.html',
                         lab_num=2,
                         lab_title="None Algorithm Attack",
                         description="The server accepts the 'none' algorithm. Can you exploit this?",
                         hint="What happens if you change the algorithm to 'none' and remove the signature?")

@app.route('/lab2', methods=['POST'])
def lab2_auth():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if username and password:
        token = jwt.encode(
            {"username": username, "role": "user"},
            "lab2_secret_key",
            algorithm="HS256"
        )

        response = make_response(redirect(url_for('lab2_dashboard')))
        response.set_cookie('token', token)
        return response

    return render_template('login.html',
                         lab_num=2,
                         lab_title="None Algorithm Attack",
                         error="Please provide credentials")

@app.route('/lab2/dashboard')
def lab2_dashboard():
    token = request.cookies.get('token')

    if not token:
        return redirect(url_for('lab2_login'))

    try:
        # Get the header to check algorithm
        header = jwt.get_unverified_header(token)

        # VULNERABILITY: If algorithm is 'none', skip verification entirely
        if header.get('alg', '').lower() == 'none':
            # Manually decode without verification for 'none' algorithm
            parts = token.split('.')
            if len(parts) >= 2:
                # Decode payload (add padding if needed)
                payload_b64 = parts[1]
                payload_b64 += '=' * (4 - len(payload_b64) % 4)
                import json
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            else:
                raise ValueError("Invalid token format")
        else:
            payload = jwt.decode(token, "lab2_secret_key", algorithms=["HS256"])

        if payload.get('role') == 'admin':
            return render_template('success.html',
                                 lab_num=2,
                                 flag=FLAGS['lab2'],
                                 message="You exploited the none algorithm vulnerability!")
        else:
            return render_template('dashboard.html',
                                 lab_num=2,
                                 username=payload.get('username', 'unknown'),
                                 role=payload.get('role', 'unknown'),
                                 token=token)
    except Exception as e:
        return render_template('error.html', error=str(e), lab_num=2)

# ============================================================================
# LAB 3: Weak Secret Key
# Vulnerability: Uses easily brute-forceable secret "secret1"
# ============================================================================

@app.route('/lab3', methods=['GET'])
def lab3_login():
    return render_template('login.html',
                         lab_num=3,
                         lab_title="Weak Secret Key",
                         description="The server uses HS256 with a weak secret key. Can you crack it?",
                         hint="Try common passwords or use a tool like hashcat/john with jwt2john...")

@app.route('/lab3', methods=['POST'])
def lab3_auth():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if username and password:
        # VULNERABILITY: Using weak secret "secret1"
        token = jwt.encode(
            {"username": username, "role": "user"},
            WEAK_SECRET,
            algorithm="HS256"
        )

        response = make_response(redirect(url_for('lab3_dashboard')))
        response.set_cookie('token', token)
        return response

    return render_template('login.html',
                         lab_num=3,
                         lab_title="Weak Secret Key",
                         error="Please provide credentials")

@app.route('/lab3/dashboard')
def lab3_dashboard():
    token = request.cookies.get('token')

    if not token:
        return redirect(url_for('lab3_login'))

    try:
        # Proper verification, but weak secret can be brute-forced
        payload = jwt.decode(token, WEAK_SECRET, algorithms=["HS256"])

        if payload.get('role') == 'admin':
            return render_template('success.html',
                                 lab_num=3,
                                 flag=FLAGS['lab3'],
                                 message="You cracked the weak secret key!")
        else:
            return render_template('dashboard.html',
                                 lab_num=3,
                                 username=payload.get('username', 'unknown'),
                                 role=payload.get('role', 'unknown'),
                                 token=token)
    except jwt.InvalidSignatureError:
        return render_template('error.html', error="Invalid signature!", lab_num=3)
    except Exception as e:
        return render_template('error.html', error=str(e), lab_num=3)

# ============================================================================
# LAB 4: KID Path Traversal
# Vulnerability: Server reads file specified in 'kid' header as secret key
# ============================================================================

@app.route('/lab4', methods=['GET'])
def lab4_login():
    return render_template('login.html',
                         lab_num=4,
                         lab_title="KID Path Traversal",
                         description="The server uses the 'kid' header to locate the signing key file. Can you abuse this?",
                         hint="What if you point 'kid' to a file with known content like /dev/null or static/js/switch.js?")

@app.route('/lab4', methods=['POST'])
def lab4_auth():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if username and password:
        token = jwt.encode(
            {"username": username, "role": "user"},
            "lab4_default_secret",
            algorithm="HS256",
            headers={"kid": "keys/lab4_key.txt"}
        )

        response = make_response(redirect(url_for('lab4_dashboard')))
        response.set_cookie('token', token)
        return response

    return render_template('login.html',
                         lab_num=4,
                         lab_title="KID Path Traversal",
                         error="Please provide credentials")

@app.route('/lab4/dashboard')
def lab4_dashboard():
    token = request.cookies.get('token')

    if not token:
        return redirect(url_for('lab4_login'))

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get('kid', '')

        # VULNERABILITY: Directly reading file from user-controlled 'kid' parameter
        # No path validation - allows path traversal!
        try:
            with open(kid, 'r') as f:
                secret_key = f.read().strip()
        except FileNotFoundError:
            secret_key = "default_fallback_key"
        except Exception:
            secret_key = ""  # /dev/null returns empty string

        payload = jwt.decode(token, secret_key, algorithms=["HS256"])

        if payload.get('role') == 'admin':
            return render_template('success.html',
                                 lab_num=4,
                                 flag=FLAGS['lab4'],
                                 message="You exploited the KID path traversal!")
        else:
            return render_template('dashboard.html',
                                 lab_num=4,
                                 username=payload.get('username', 'unknown'),
                                 role=payload.get('role', 'unknown'),
                                 token=token)
    except jwt.InvalidSignatureError:
        return render_template('error.html', error="Invalid signature!", lab_num=4)
    except Exception as e:
        return render_template('error.html', error=str(e), lab_num=4)

# ============================================================================
# LAB 5: Algorithm Confusion (RS256 -> HS256)
# Vulnerability: Server uses public key as HMAC secret when alg is changed to HS256
# ============================================================================

@app.route('/lab5', methods=['GET'])
def lab5_login():
    # Expose the public key for this lab
    return render_template('login.html',
                         lab_num=5,
                         lab_title="Algorithm Confusion",
                         description="The server uses RS256 but might accept HS256. The public key is available at /lab5/public.pem",
                         hint="What if you sign with HS256 using the public key as the secret?",
                         extra_info="Public key available at: /lab5/public.pem")

@app.route('/lab5/public.pem')
def lab5_public_key():
    """Expose public key - this is normal for RS256"""
    response = make_response(PUBLIC_KEY)
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/lab5', methods=['POST'])
def lab5_auth():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if username and password:
        # Sign with RS256 (asymmetric)
        token = jwt.encode(
            {"username": username, "role": "user"},
            PRIVATE_KEY,
            algorithm="RS256"
        )

        response = make_response(redirect(url_for('lab5_dashboard')))
        response.set_cookie('token', token)
        return response

    return render_template('login.html',
                         lab_num=5,
                         lab_title="Algorithm Confusion",
                         error="Please provide credentials")

@app.route('/lab5/dashboard')
def lab5_dashboard():
    token = request.cookies.get('token')

    if not token:
        return redirect(url_for('lab5_login'))

    try:
        header = jwt.get_unverified_header(token)
        alg = header.get('alg', 'RS256')

        # VULNERABILITY: Algorithm confusion!
        # If attacker changes alg to HS256, we use public key as HMAC secret
        if alg == 'HS256':
            # This is the vulnerability - using public key as symmetric secret
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=["HS256"])
        elif alg == 'RS256':
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

        if payload.get('role') == 'admin':
            return render_template('success.html',
                                 lab_num=5,
                                 flag=FLAGS['lab5'],
                                 message="You exploited algorithm confusion!")
        else:
            return render_template('dashboard.html',
                                 lab_num=5,
                                 username=payload.get('username', 'unknown'),
                                 role=payload.get('role', 'unknown'),
                                 token=token)
    except jwt.InvalidSignatureError:
        return render_template('error.html', error="Invalid signature!", lab_num=5)
    except Exception as e:
        return render_template('error.html', error=str(e), lab_num=5)

# ============================================================================
# UTILITY ROUTES
# ============================================================================

@app.route('/decode')
def decode_tool():
    """Helper tool to decode JWT tokens"""
    return render_template('decode.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
