"""
Authentication module for verifying Google Workspace service account tokens
"""
import logging
from google.oauth2 import id_token
from google.auth.transport import requests

logger = logging.getLogger(__name__)


def verify_service_account(token):
    """
    Verify a Google service account bearer token

    Args:
        token: JWT bearer token from Authorization header

    Returns:
        User email from the token

    Raises:
        Exception if token is invalid
    """
    try:
        # Verify the token
        # Google Workspace sends tokens that can be verified using Google's public keys
        request = requests.Request()
        id_info = id_token.verify_oauth2_token(token, request)

        # Extract user email from token
        user_email = id_info.get('email', id_info.get('sub', 'unknown'))

        logger.info(f"Token verified for user: {user_email}")
        return user_email

    except ValueError as e:
        # Token is invalid
        logger.error(f"Token verification failed: {str(e)}")
        raise Exception(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        raise Exception(f"Authentication failed: {str(e)}")


def verify_workspace_token(token, expected_audience=None):
    """
    Verify a Google Workspace-specific token with audience validation

    Args:
        token: JWT bearer token
        expected_audience: Expected audience claim (optional)

    Returns:
        Dict with user_email and other claims
    """
    try:
        request = requests.Request()

        if expected_audience:
            id_info = id_token.verify_oauth2_token(
                token, request, audience=expected_audience
            )
        else:
            id_info = id_token.verify_oauth2_token(token, request)

        return {
            'user_email': id_info.get('email', ''),
            'domain': id_info.get('hd', ''),  # Hosted domain
            'subject': id_info.get('sub', ''),
            'claims': id_info
        }

    except Exception as e:
        logger.error(f"Workspace token verification failed: {str(e)}")
        raise Exception(f"Invalid Workspace token: {str(e)}")
