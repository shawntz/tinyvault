"""
Google Workspace Client-Side Encryption (CSE) KACLS Endpoint
Implements the Key Access Control List Service for Google Workspace encryption
"""
import os
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from functools import wraps
from urllib.parse import urlparse
from kms_service import KMSService
from auth import verify_service_account, verify_okta_token, verify_workspace_token

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import unicodedata

def sanitize_for_log(value):
    """
    Sanitizes user-controlled values for safe inclusion in logs.
    Removes all ASCII and Unicode linebreak/control characters that could result in log injection.
    """
    # Only allow safe types for string conversion
    if isinstance(value, (str, int, float, bool)):
        value_str = str(value)
    else:
        value_str = "<non-primitive>"

    # Explicitly remove all ASCII and Unicode newlines, carriage returns, tabs, line/paragraph separator, and all control characters
    # This is needed to avoid log injection via any form of line break/control sep
    NEWLINES_AND_CONTROLS_RE = re.compile(
        r'['
        r'\x00-\x1F'        # ASCII control chars, including \n, \r, \t
        r'\x7F'             # ASCII DEL
        r'\u2028'           # Unicode Line Separator
        r'\u2029'           # Unicode Paragraph Separator
        r'\u0085'           # Next line
        r']'
    )
    sanitized = NEWLINES_AND_CONTROLS_RE.sub('', value_str)

    # Remove other dangerous Unicode categories (general controls, etc):
    sanitized = ''.join(
        ch for ch in sanitized
        if unicodedata.category(ch) not in ('Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp')
    )
    # Remove delimiter chars that could confuse logs
    sanitized = sanitized.replace('"', '').replace('|', '').replace("'", '')
    # Optionally limit length to 256 chars to prevent log flooding
    return sanitized[:256]

app = Flask(__name__)

# Enable CORS for Google Workspace CSE
# Google requires CORS to access from multiple Google domains
CORS(app,
     resources={
         r"/*": {
             "origins": [
                 "https://admin.google.com",
                 "https://client-side-encryption.google.com",
                 "https://mail.google.com",
                 "https://drive.google.com",
                 "https://docs.google.com",
                 "https://calendar.google.com",
                 "https://meet.google.com"
             ],
             "methods": ["GET", "POST", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
             "expose_headers": ["Content-Type"],
             "supports_credentials": True
         }
     })

# Log all incoming requests early
@app.before_request
def log_incoming_request():
    try:
        sanitized_method = sanitize_for_log(request.method)
        sanitized_path = sanitize_for_log(request.path)
        sanitized_origin = sanitize_for_log(request.headers.get('Origin', ''))
        logger.info(f">>> {sanitized_method} \"{sanitized_path}\" Origin=\"{sanitized_origin}\"")
    except Exception:
        logger.exception("Exception occurred during request logging")

# Attach CORS headers to all responses when appropriate
@app.after_request
def apply_cors_on_response(response):
    try:
        return add_cors_headers(response)
    except Exception:
        return response

# Initialize KMS service
kms_service = KMSService(
    project_id=os.environ.get('GCP_PROJECT_ID'),
    location_id=os.environ.get('KMS_LOCATION', 'us-central1'),
    key_ring_id=os.environ.get('KMS_KEYRING', 'cse-keyring'),
    key_id=os.environ.get('KMS_KEY', 'cse-key')
)


def require_auth(f):
    """Decorator to verify Google service account authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            logger.warning("Missing or invalid authorization header")
            return jsonify({'error': 'Unauthorized'}), 401

        token = auth_header.split('Bearer ')[1]

        try:
            # Verify the token and get user info
            user_email = verify_service_account(token)
            request.user_email = user_email
            logger.info(f"Authenticated request from {user_email}")
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return jsonify({'error': 'Unauthorized'}), 401

        return f(*args, **kwargs)

    return decorated_function


def add_cors_headers(response):
    """
    Attach CORS headers for Google CSE callers, including on error responses.
    """
    origin = request.headers.get('Origin', '')
    hostname = urlparse(origin).hostname or None
    if hostname and hostname.endswith('.google.com'):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        requested_headers = request.headers.get('Access-Control-Request-Headers', '')
        response.headers['Access-Control-Allow-Headers'] = requested_headers or 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Max-Age'] = '3600'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


@app.route('/', methods=['GET'])
def root():
    """Root endpoint - Service information"""
    return jsonify({
        'service': 'TinyVault KACLS',
        'description': 'Google Workspace Client-Side Encryption Key Service',
        'version': '1.0',
        'endpoints': {
            'health': '/health',
            'status': '/status',
            'wrap': '/v1/wrap',
            'unwrap': '/v1/unwrap',
            'privileged_unwrap': '/v1/privileged_unwrap'
        }
    }), 200


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200


@app.route('/status', methods=['GET'])
def status():
    """Status endpoint for Google Workspace CSE discovery"""
    return jsonify({
        'server_type': 'KACLS',
        'vendor_id': 'TinyVault',
        'version': '1.0',
        'name': 'TinyVault KACLS',
        'operations_supported': [
            'wrap',
            'unwrap',
            'privilegedunwrap',
            'keys:wrap',
            'keys:unwrap'
        ]
    }), 200


@app.route('/.well-known/cse-configuration', methods=['GET'])
def cse_configuration():
    """CSE configuration endpoint for identity provider discovery"""
    # Identity provider configuration from environment variables
    # Supports both Google Identity and third-party IdPs (like Okta)
    idp_name = os.environ.get('IDP_NAME', 'Google')
    client_id = os.environ.get('IDP_CLIENT_ID', '')
    discovery_uri = os.environ.get('IDP_DISCOVERY_URI', 'https://accounts.google.com/.well-known/openid-configuration')
    audience = os.environ.get('IDP_AUDIENCE', 'cse-authorization')

    return jsonify({
        'name': idp_name,
        'client_id': client_id,
        'discovery_uri': discovery_uri,
        'audience': audience
    }), 200


@app.route('/wrap', methods=['POST', 'OPTIONS'])
@app.route('/v1/wrap', methods=['POST', 'OPTIONS'])
@app.route('/keys:wrap', methods=['POST', 'OPTIONS'])
@app.route('/v1/keys:wrap', methods=['POST', 'OPTIONS'])
def wrap_key():
    """
    Wrap a data encryption key (DEK) using the master key in KMS

    Request format from Google Workspace:
    {
        "key": "<base64-encoded-plaintext-DEK>",
        "authorization": {
            "resource_name": "<resource-identifier>",
            "user_email": "<user-email>"
        }
    }
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        logger.info("=== WRAP OPTIONS (preflight) ===")
        origin_header = request.headers.get('Origin', '')
        safe_origin_header = origin_header.replace('\r\n', '').replace('\r', '').replace('\n', '')
        logger.info(f"Origin: {safe_origin_header}")
        acrh_header = request.headers.get('Access-Control-Request-Headers', '')
        safe_acrh_header = acrh_header.replace('\r\n', '').replace('\r', '').replace('\n', '')
        logger.info(f"Access-Control-Request-Headers: {safe_acrh_header}")
        sanitized_origin = re.sub(r'[\r\n]+', '', request.headers.get('Origin', ''))
        logger.info(f"Origin: {sanitized_origin}")
        # Remove all non-printable/control characters to prevent log injection
        sanitized_headers = re.sub(r'[^\x20-\x7E]', '', request.headers.get('Access-Control-Request-Headers', ''))
        logger.info(f"Access-Control-Request-Headers: {sanitized_headers}")
        response = jsonify({})
        origin = request.headers.get('Origin', '')
        host = ''
        if origin:
            parsed = urlparse(origin)
            if parsed.hostname is None:
                logger.warning(f"Malformed or missing hostname in Origin header: '{origin}'")
            else:
                host = parsed.hostname
        if host == 'google.com' or host.endswith('.google.com'):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            # Echo requested headers to satisfy browser CORS checks
            requested_headers = request.headers.get('Access-Control-Request-Headers', '')
            response.headers['Access-Control-Allow-Headers'] = requested_headers or 'Content-Type, Authorization, X-Requested-With'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200

    # Log request for debugging
    logger.info(f"=== WRAP REQUEST ===")
    sanitized_headers = {k: v.replace('\r', '').replace('\n', '') for k, v in request.headers.items()}
    logger.info(f"Headers: {sanitized_headers}")
    origin_val = request.headers.get('Origin', 'No origin header')
    origin_val = origin_val.replace('\r', '').replace('\n', '')
    logger.info(f"Request origin: {origin_val}")

    try:
        data = request.get_json()
        if data:
            # Sanitize keys to prevent log injection (CR/LF). See Security Alert: LOG-INJECTION-CRLF.
            safe_keys = [str(key).replace('\r', '').replace('\n', '') for key in data.keys()]
            logger.info("Request body keys: %s", safe_keys)
        else:
            logger.info("Request body keys: None")
        if data:
            # Sanitize 'authorization' user input before logging to avoid log injection
            authorization = data.get('authorization', 'None')
            if not isinstance(authorization, str):
                authorization = str(authorization)
            safe_auth = authorization.replace('\r', '').replace('\n', '')
            logger.info(f"Full request body (excluding sensitive key): {{'authentication': '***', 'authorization': {safe_auth}, 'key': '[REDACTED]'}}")
            authorization = data.get('authorization', None)
            if isinstance(authorization, dict):
                # Log only the keys of the authorization dict to avoid sensitive data
                safe_auth = {k: '[REDACTED]' for k in authorization.keys()}
            elif isinstance(authorization, str):
                # Remove newlines and carriage returns to prevent log injection
                safe_auth = authorization.replace('\r', '').replace('\n', '')
            else:
                # Sanitize any representation of authorization to prevent log injection
                safe_auth = str(authorization).replace('\r', '').replace('\n', '')
            logger.info(f"Full request body (excluding sensitive key): {{'authentication': '***', 'authorization': {safe_auth}, 'key': '[REDACTED]'}}")

        if not data or 'key' not in data:
            return jsonify({'error': 'Missing key in request'}), 400

        # Validate authentication token (from Okta IdP)
        authentication_token = data.get('authentication', '')
        if not authentication_token:
            logger.warning("No authentication token provided")
            return jsonify({'error': 'Authentication required'}), 401

        try:
            # Verify the Okta JWT token
            user_info = verify_okta_token(authentication_token)
            user_email = user_info['user_email']
            logger.info(f"Authenticated user: {user_email}")
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return jsonify({'error': 'Unauthorized'}), 401

        # Check authorization (optional - can be used for access control)
        # The authorization token can be used to determine if this specific user
        # should have access to this specific resource, but for single-user setup
        # we just verify the user is authenticated

        plaintext_dek = data['key']

        # Wrap the DEK using KMS
        wrapped_key = kms_service.wrap(plaintext_dek)

        # Include both camelCase and snake_case for client compatibility
        response_data = {
            'wrappedKey': wrapped_key,
            'wrapped_key': wrapped_key,
            'status': 'success'
        }
        logger.info(f"Returning wrap response: wrappedKey length={len(wrapped_key)} chars")
        logger.info(f"Response JSON: {response_data}")

        # Create response with explicit headers for Google CSE
        response = jsonify(response_data)
        response.status_code = 200
        response.headers['Content-Type'] = 'application/json'

        # Explicitly set CORS headers to ensure they're present
        origin = request.headers.get('Origin', '')
        origin_hostname = urlparse(origin).hostname or '' if origin else ''
        # Allow CORS only for google.com and its subdomains
        if origin_hostname and (origin_hostname == 'google.com' or origin_hostname.endswith('.google.com')):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            requested_headers = request.headers.get('Access-Control-Request-Headers', '')
            response.headers['Access-Control-Allow-Headers'] = requested_headers or 'Content-Type, Authorization, X-Requested-With'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Access-Control-Allow-Credentials'] = 'true'

        logger.info(f"Wrap response headers: {dict(response.headers)}")
        logger.info(f"=== WRAP COMPLETE - waiting for unwrap request ===")

        return response

    except Exception as e:
        logger.error(f"Wrap operation failed: {str(e)}", exc_info=True)
        response = jsonify({'error': 'Internal server error'})
        response.status_code = 500
        response.headers['Content-Type'] = 'application/json'
        return add_cors_headers(response)


@app.route('/unwrap', methods=['POST', 'OPTIONS'])
@app.route('/v1/unwrap', methods=['POST', 'OPTIONS'])
@app.route('/keys:unwrap', methods=['POST', 'OPTIONS'])
@app.route('/v1/keys:unwrap', methods=['POST', 'OPTIONS'])
def unwrap_key():
    """
    Unwrap a data encryption key (DEK) using the master key in KMS

    Request format from Google Workspace:
    {
        "wrappedKey": "<base64-encoded-wrapped-DEK>",
        "authorization": {
            "resource_name": "<resource-identifier>",
            "user_email": "<user-email>"
        }
    }
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        logger.info("=== UNWRAP OPTIONS (preflight) ===")
        origin = request.headers.get('Origin', '')
        sanitized_origin = origin.replace('\r', '').replace('\n', '')
        logger.info(f"Origin: {sanitized_origin}")
        acrh = request.headers.get('Access-Control-Request-Headers', '')
        sanitized_acrh = acrh.replace('\r\n', '').replace('\r', '').replace('\n', '')
        logger.info(f"Access-Control-Request-Headers: {sanitized_acrh}")
        response = jsonify({})
        # origin already assigned above; sanitize and parse it
        parsed = urlparse(origin)
        host = (parsed.hostname or '').lower().rstrip('.')
        # Only allow origins that are google.com or subdomains of google.com, and require HTTPS scheme
        if parsed.scheme == 'https' and host and (host == "google.com" or host.endswith(".google.com")):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Vary'] = 'Origin'
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            requested_headers = request.headers.get('Access-Control-Request-Headers', '')
            response.headers['Access-Control-Allow-Headers'] = requested_headers or 'Content-Type, Authorization, X-Requested-With'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200

    # Log request for debugging
    logger.info(f"=== UNWRAP REQUEST ===")
    # Redact sensitive headers and sanitize values before logging
    safe_headers = {k: ('<redacted>' if k.lower() in {'authorization','cookie','set-cookie'} else str(v).replace('\r','').replace('\n','')) for k, v in request.headers.items()}
    logger.info(f"Headers: {safe_headers}")
    origin_val = request.headers.get('Origin', 'No origin header')
    origin_val = origin_val.replace('\r', '').replace('\n', '')
    logger.info("Request origin: %s", origin_val)
    sanitized_headers = { 
        k.replace('\r', '').replace('\n', ''): v.replace('\r', '').replace('\n', '') 
        for k, v in dict(request.headers).items() 
    }
    logger.info(f"Headers: {sanitized_headers}")
    logger.info(f"Request origin: {request.headers.get('Origin', 'No origin header')}")

    try:
        data = request.get_json()
        logger.info(f"Request body keys: {data.keys() if data else 'None'}")
        def sanitize_for_log(obj):
            if isinstance(obj, dict):
                return {k: sanitize_for_log(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [sanitize_for_log(v) for v in obj]
            elif isinstance(obj, str):
                # Remove CR and LF characters and any non-printable ascii control chars
                return re.sub(r'[\r\n\x00-\x1F\x7F]', '', obj)
            else:
                return obj
        if data:
            authorization_sanitized = sanitize_for_log(data.get('authorization', 'None'))
            logger.info(f"Full request body (excluding sensitive key): {{'authentication': '***', 'authorization': {authorization_sanitized}, 'wrappedKey': '[REDACTED]'}}")
        # Accept both camelCase and snake_case for wrapped key field
        has_wrapped_camel = bool(data and 'wrappedKey' in data)
        has_wrapped_snake = bool(data and 'wrapped_key' in data)

        if not data or (not has_wrapped_camel and not has_wrapped_snake):
            sanitized_keys = (
                ', '.join([repr(k) for k in data.keys()])
                if data else 'None'
            )
            logger.warning(f"Missing wrapped key in request body. Keys present: {sanitized_keys}")
            resp = jsonify({'error': 'Missing wrappedKey/wrapped_key in request'})
            resp.status_code = 400
            resp.headers['Content-Type'] = 'application/json'
            return add_cors_headers(resp)

        # Validate authentication tokens: prefer Okta, fall back to Google authorization token
        authentication_token = data.get('authentication', '')
        authorization_token = data.get('authorization', '')

        user_email = ''
        authenticated = False

        if authentication_token:
            try:
                user_info = verify_okta_token(authentication_token)
                user_email = user_info['user_email']
                authenticated = True
                logger.info(f"Authenticated via Okta: {user_email}")
            except Exception as e:
                logger.warning(f"Okta authentication failed, will attempt Google authorization fallback: {str(e)}")
        else:
            logger.warning("No Okta authentication token provided; attempting Google authorization fallback")

        if not authenticated:
            if authorization_token:
                try:
                    expected_aud = os.environ.get('IDP_AUDIENCE', 'cse-authorization')
                    ws_info = verify_workspace_token(authorization_token, expected_audience=expected_aud)
                    user_email = ws_info.get('user_email', '')
                    logger.info(f"Authenticated via Google authorization token: {user_email}")
                except Exception as e:
                    logger.error(f"Google authorization token validation failed: {str(e)}")
                    resp = jsonify({'error': 'Unauthorized'})
                    resp.status_code = 401
                    resp.headers['Content-Type'] = 'application/json'
                    return add_cors_headers(resp)
            else:
                logger.error("Neither Okta authentication nor Google authorization token provided")
                resp = jsonify({'error': 'Authentication required'})
                resp.status_code = 401
                resp.headers['Content-Type'] = 'application/json'
                return add_cors_headers(resp)

        # Proceed with unwrap
        wrapped_key = data['wrappedKey'] if has_wrapped_camel else data['wrapped_key']
        logger.info(f"Unwrap payload received: wrapped_key length={len(wrapped_key) if isinstance(wrapped_key, str) else 'n/a'}")
        plaintext_key = kms_service.unwrap(wrapped_key)

        response = jsonify({'key': plaintext_key, 'status': 'success'})
        response.status_code = 200
        response.headers['Content-Type'] = 'application/json'
        response = add_cors_headers(response)
        logger.info(f"Unwrap response headers: {dict(response.headers)}")
        return response

    except Exception as e:
        logger.error(f"Unwrap operation failed: {str(e)}", exc_info=True)
        resp = jsonify({'error': 'An internal error has occurred.'})
        resp.status_code = 500
        resp.headers['Content-Type'] = 'application/json'
        return add_cors_headers(resp)


@app.route('/privileged_unwrap', methods=['POST', 'OPTIONS'])
@app.route('/v1/privileged_unwrap', methods=['POST', 'OPTIONS'])
def privileged_unwrap():
    """
    Privileged unwrap for admin access or audit scenarios
    This allows unwrapping without normal authorization checks
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        logger.info("=== PRIVILEGED UNWRAP OPTIONS (preflight) ===")
        origin_val = request.headers.get('Origin', '')
        origin_val = origin_val.replace('\r', '').replace('\n', '')
        logger.info(f"Origin: {origin_val}")
        acrh_val = request.headers.get('Access-Control-Request-Headers', '')
        acrh_val = acrh_val.translate({ord('\r'): None, ord('\n'): None})
        logger.info(f"Access-Control-Request-Headers: {acrh_val}")
        response = jsonify({})
        origin = request.headers.get('Origin', '')
        # Only allow CORS from google.com or its subdomains
        try:
            parsed = urlparse(origin)
            host = parsed.hostname
        except ValueError:
            host = None
        if host == "google.com" or (host and host.endswith(".google.com")):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            requested_headers = request.headers.get('Access-Control-Request-Headers', '')
            response.headers['Access-Control-Allow-Headers'] = requested_headers or 'Content-Type, Authorization, X-Requested-With'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200

    # Log request for debugging
    logger.info(f"=== PRIVILEGED UNWRAP REQUEST ===")

    try:
        data = request.get_json()

        if not data or 'wrappedKey' not in data:
            resp = jsonify({'error': 'Missing wrappedKey in request'})
            resp.status_code = 400
            resp.headers['Content-Type'] = 'application/json'
            return add_cors_headers(resp)

        # Validate authentication token (from Okta IdP)
        authentication_token = data.get('authentication', '')
        if not authentication_token:
            logger.warning("No authentication token provided for privileged unwrap")
            resp = jsonify({'error': 'Authentication required'})
            resp.status_code = 401
            resp.headers['Content-Type'] = 'application/json'
            return add_cors_headers(resp)

        try:
            # Verify the Okta JWT token
            user_info = verify_okta_token(authentication_token)
            user_email = user_info['user_email']
            if isinstance(user_email, str):
                user_email = user_email.replace('\r', '').replace('\n', '')
            else:
                user_email = str(user_email).replace('\r', '').replace('\n', '')
            logger.info(f"Privileged unwrap - Authenticated user: {user_email}")
        except Exception as e:
            logger.error(f"Privileged unwrap authentication failed: {str(e)}")
            resp = jsonify({'error': 'Unauthorized'})
            resp.status_code = 401
            resp.headers['Content-Type'] = 'application/json'
            return add_cors_headers(resp)

        wrapped_key = data['wrappedKey']
        reason = data.get('reason', 'Admin access')
        # Sanitize user input to mitigate log injection
        if isinstance(reason, str):
            reason = reason.replace('\r', '').replace('\n', '')

        logger.warning(f"Privileged unwrap requested by {user_email}. Reason: {reason}")

        # For single user setup, privileged unwrap just uses same logic
        plaintext_key = kms_service.unwrap(wrapped_key)

        return jsonify({
            'key': plaintext_key
        }), 200

    except Exception as e:
        logger.error(f"Privileged unwrap operation failed: {str(e)}", exc_info=True)
        resp = jsonify({'error': 'Privileged unwrap operation failed.'})
        resp.status_code = 500
        resp.headers['Content-Type'] = 'application/json'
        return add_cors_headers(resp)


def is_authorized(user_email):
    """
    Check if user is authorized to access encrypted content
    For single user setup, check against allowed email(s)
    """
    allowed_emails = os.environ.get('ALLOWED_EMAILS', '').split(',')
    allowed_emails = [email.strip() for email in allowed_emails if email.strip()]

    # If no emails specified, allow all (not recommended for production)
    if not allowed_emails:
        logger.warning("No ALLOWED_EMAILS configured - allowing all users")
        return True

    return user_email in allowed_emails


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # For local development only
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
