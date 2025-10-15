"""
Authentication module for verifying Google Workspace service account tokens
and Okta identity provider tokens
"""
import logging
import os
import jwt
from jwt import PyJWKClient
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


def verify_okta_token(token, issuer=None, audience=None, client_id=None):
    """
    Verify an Okta JWT token for Google Workspace CSE

    Args:
        token: JWT token from the 'authentication' field
        issuer: Okta issuer URL (e.g., https://acme.okta.com/oauth2/default)
        audience: Expected audience claim
        client_id: Okta client ID

    Returns:
        Dict with user_email and other claims

    Raises:
        Exception if token is invalid
    """
    try:
        # Get configuration from environment if not provided
        if not issuer:
            # Derive issuer from IDP_DISCOVERY_URI
            discovery_uri = os.environ.get('IDP_DISCOVERY_URI', '')
            if discovery_uri:
                # Remove /.well-known/openid-configuration to get issuer
                issuer = discovery_uri.replace('/.well-known/openid-configuration', '')
            else:
                # Fallback to OKTA_DOMAIN with default auth server
                okta_domain = os.environ.get('OKTA_DOMAIN', '')
                if not okta_domain:
                    raise Exception("OKTA_DOMAIN or IDP_DISCOVERY_URI environment variable not set")
                issuer = f"https://{okta_domain}/oauth2/default"

        if not audience:

        if not client_id:
            client_id = os.environ.get('IDP_CLIENT_ID', '')

        # Get JWKS from Okta to verify token signature
        # For org auth servers: https://domain/oauth2/v1/keys
        # For custom auth servers: https://domain/oauth2/{name}/v1/keys
        if '/oauth2/' in issuer and issuer.endswith('/oauth2/default'):
            # Custom authorization server
            jwks_uri = f"{issuer}/v1/keys"
        elif '/oauth2/' not in issuer:
            # Org authorization server (root level)
            jwks_uri = f"{issuer}/oauth2/v1/keys"
        else:
            # Generic fallback
            jwks_uri = f"{issuer}/v1/keys"

        logger.info(f"Using issuer: {issuer}")
        logger.info(f"Fetching JWKS from: {jwks_uri}")
        jwks_client = PyJWKClient(jwks_uri)

        # Get signing key from token header
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Verify and decode the token
        decoded_token = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False}  # CSE tokens might not have standard audience
        )

        logger.info(f"Token issuer claim: {decoded_token.get('iss', 'N/A')}")

        # Extract user information
        user_email = decoded_token.get('email', decoded_token.get('sub', ''))

        logger.info(f"Okta token verified for user: {user_email}")

        return {
            'user_email': user_email,
            'subject': decoded_token.get('sub', ''),
            'claims': decoded_token
        }

    except jwt.ExpiredSignatureError:
        logger.error("Okta token has expired")
        raise Exception("Token has expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Okta token validation failed: {str(e)}")
        raise Exception(f"Invalid Okta token: {str(e)}")
    except Exception as e:
        logger.error(f"Okta token verification error: {str(e)}")
        raise Exception(f"Okta authentication failed: {str(e)}")
