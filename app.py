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
from kms_service import KMSService
from auth import verify_service_account, verify_okta_token, verify_workspace_token

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        logger.info(f">>> {request.method} {request.path} Origin={request.headers.get('Origin', '')}")
    except Exception:
        pass

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
    if 'google.com' in origin:
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
        logger.info(f"Origin: {request.headers.get('Origin', '')}")
        logger.info(f"Access-Control-Request-Headers: {request.headers.get('Access-Control-Request-Headers', '')}")
        response = jsonify({})
        origin = request.headers.get('Origin', '')
        if 'google.com' in origin:
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
    logger.info(f"Headers: {dict(request.headers)}")
    logger.info(f"Request origin: {request.headers.get('Origin', 'No origin header')}")

    try:
        data = request.get_json()
        logger.info(f"Request body keys: {data.keys() if data else 'None'}")
        if data:
            logger.info(f"Full request body (excluding sensitive key): {{'authentication': '***', 'authorization': {data.get('authorization', 'None')}, 'key': '[REDACTED]'}}")

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
        authorization_token = data.get('authorization', '')
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
        if 'google.com' in origin:
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
        logger.info(f"Origin: {request.headers.get('Origin', '')}")
        logger.info(f"Access-Control-Request-Headers: {request.headers.get('Access-Control-Request-Headers', '')}")
        response = jsonify({})
        origin = request.headers.get('Origin', '')
        if 'google.com' in origin:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            requested_headers = request.headers.get('Access-Control-Request-Headers', '')
            response.headers['Access-Control-Allow-Headers'] = requested_headers or 'Content-Type, Authorization, X-Requested-With'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200

    # Log request for debugging
    logger.info(f"=== UNWRAP REQUEST ===")
    logger.info(f"Headers: {dict(request.headers)}")
    logger.info(f"Request origin: {request.headers.get('Origin', 'No origin header')}")

    try:
        data = request.get_json()
        logger.info(f"Request body keys: {data.keys() if data else 'None'}")
        if data:
            logger.info(f"Full request body (excluding sensitive key): {{'authentication': '***', 'authorization': {data.get('authorization', 'None')}, 'wrappedKey': '[REDACTED]'}}")

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
                    authenticated = True
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
        logger.info(f"Origin: {request.headers.get('Origin', '')}")
        logger.info(f"Access-Control-Request-Headers: {request.headers.get('Access-Control-Request-Headers', '')}")
        response = jsonify({})
        origin = request.headers.get('Origin', '')
        if 'google.com' in origin:
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
