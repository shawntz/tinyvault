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
from auth import verify_service_account

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Enable CORS for Google Workspace CSE
# Google requires CORS to access from multiple Google domains
CORS(app,
     origins=[
         "https://admin.google.com",
         "https://client-side-encryption.google.com",
         "https://mail.google.com",
         "https://drive.google.com",
         "https://docs.google.com",
         "https://calendar.google.com",
         "https://meet.google.com"
     ],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

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
            'privilegedunwrap'
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


@app.route('/v1/wrap', methods=['POST'])
@require_auth
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
    try:
        data = request.get_json()

        if not data or 'key' not in data:
            return jsonify({'error': 'Missing key in request'}), 400

        plaintext_dek = data['key']
        resource_name = data.get('authorization', {}).get('resource_name', '')
        user_email = data.get('authorization', {}).get('user_email', '')
        # Sanitize user input before logging to prevent log injection
        # Remove all control/non-printable characters, not just line breaks
        safe_resource_name = re.sub(r'[^\x20-\x7E]', '', resource_name)
        safe_user_email = re.sub(r'[^\x20-\x7E]', '', user_email)
        logger.info(f"Wrap request for resource: {safe_resource_name}, user: {safe_user_email}")

        # Check authorization (for single user, this is simple)
        if user_email and not is_authorized(user_email):
            sanitized_user_email = user_email.replace('\r', '').replace('\n', '')
            logger.warning(f"Unauthorized user: {sanitized_user_email}")
            return jsonify({'error': 'User not authorized'}), 403

        # Wrap the DEK using KMS
        wrapped_key = kms_service.wrap(plaintext_dek)

        return jsonify({
            'wrappedKey': wrapped_key,
            'status': 'success'
        }), 200

    except Exception as e:
        logger.error(f"Wrap operation failed: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/v1/unwrap', methods=['POST'])
@require_auth
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
    try:
        data = request.get_json()

        if not data or 'wrappedKey' not in data:
            return jsonify({'error': 'Missing wrappedKey in request'}), 400

        wrapped_key = data['wrappedKey']
        resource_name = data.get('authorization', {}).get('resource_name', '')
        user_email = data.get('authorization', {}).get('user_email', '')

        safe_resource_name = resource_name.replace('\r', '').replace('\n', '')
        safe_user_email = user_email.replace('\r', '').replace('\n', '')
        logger.info(f"Unwrap request for resource: {safe_resource_name}, user: {safe_user_email}")

        # Check authorization
        if user_email and not is_authorized(user_email):
            safe_user_email = user_email.replace("\n", "").replace("\r", "")
            logger.warning(f"Unauthorized user: {safe_user_email}")
            return jsonify({'error': 'User not authorized'}), 403

        # Unwrap the DEK using KMS
        plaintext_key = kms_service.unwrap(wrapped_key)

        return jsonify({
            'key': plaintext_key,
            'status': 'success'
        }), 200

    except Exception as e:
        logger.error(f"Unwrap operation failed: {str(e)}")
        return jsonify({'error': 'An internal error has occurred.'}), 500


@app.route('/v1/privileged_unwrap', methods=['POST'])
@require_auth
def privileged_unwrap():
    """
    Privileged unwrap for admin access or audit scenarios
    This allows unwrapping without normal authorization checks
    """
    try:
        data = request.get_json()

        if not data or 'wrappedKey' not in data:
            return jsonify({'error': 'Missing wrappedKey in request'}), 400

        wrapped_key = data['wrappedKey']
        reason = data.get('reason', 'Admin access')
        # Sanitize user input to mitigate log injection
        if isinstance(reason, str):
            reason = reason.replace('\r', '').replace('\n', '')
        user_email_log = getattr(request, 'user_email', '')
        if isinstance(user_email_log, str):
            user_email_log = user_email_log.replace('\r', '').replace('\n', '')

        logger.warning(f"Privileged unwrap requested. Reason: {reason}, User: {user_email_log}")

        # For single user setup, privileged unwrap just uses same logic
        plaintext_key = kms_service.unwrap(wrapped_key)

        return jsonify({
            'key': plaintext_key,
            'status': 'success'
        }), 200

    except Exception as e:
        logger.error(f"Privileged unwrap operation failed: {str(e)}")
        return jsonify({'error': 'Privileged unwrap operation failed.'}), 500


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
