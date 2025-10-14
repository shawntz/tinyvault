"""
Google Cloud KMS Service for key wrapping and unwrapping operations
"""
import base64
import logging
from google.cloud import kms

logger = logging.getLogger(__name__)


class KMSService:
    """Handles encryption/decryption operations using Google Cloud KMS"""

    def __init__(self, project_id, location_id, key_ring_id, key_id):
        """
        Initialize KMS service

        Args:
            project_id: GCP project ID
            location_id: KMS location (e.g., 'us-central1')
            key_ring_id: KMS key ring name
            key_id: KMS key name
        """
        self.project_id = project_id
        self.location_id = location_id
        self.key_ring_id = key_ring_id
        self.key_id = key_id

        # Initialize KMS client
        self.client = kms.KeyManagementServiceClient()

        # Build the key name
        self.key_name = self.client.crypto_key_path(
            project_id, location_id, key_ring_id, key_id
        )

        logger.info(f"Initialized KMS service with key: {self.key_name}")

    def wrap(self, plaintext_key):
        """
        Wrap (encrypt) a plaintext data encryption key

        Args:
            plaintext_key: Base64-encoded plaintext DEK

        Returns:
            Base64-encoded wrapped (encrypted) DEK
        """
        try:
            # Decode the base64 plaintext key
            plaintext_bytes = base64.b64decode(plaintext_key)

            # Encrypt using KMS
            encrypt_response = self.client.encrypt(
                request={
                    'name': self.key_name,
                    'plaintext': plaintext_bytes
                }
            )

            # Return base64-encoded ciphertext
            wrapped_key = base64.b64encode(encrypt_response.ciphertext).decode('utf-8')
            logger.info("Successfully wrapped key")
            return wrapped_key

        except Exception as e:
            logger.error(f"Key wrap failed: {str(e)}")
            raise Exception(f"Failed to wrap key: {str(e)}")

    def unwrap(self, wrapped_key):
        """
        Unwrap (decrypt) a wrapped data encryption key

        Args:
            wrapped_key: Base64-encoded wrapped DEK

        Returns:
            Base64-encoded plaintext DEK
        """
        try:
            # Decode the base64 wrapped key
            ciphertext_bytes = base64.b64decode(wrapped_key)

            # Decrypt using KMS
            decrypt_response = self.client.decrypt(
                request={
                    'name': self.key_name,
                    'ciphertext': ciphertext_bytes
                }
            )

            # Return base64-encoded plaintext
            plaintext_key = base64.b64encode(decrypt_response.plaintext).decode('utf-8')
            logger.info("Successfully unwrapped key")
            return plaintext_key

        except Exception as e:
            logger.error(f"Key unwrap failed: {str(e)}")
            raise Exception(f"Failed to unwrap key: {str(e)}")

    def create_kms_resources(self):
        """
        Create KMS key ring and key if they don't exist
        This is a helper method for initial setup
        """
        try:
            # Create key ring
            key_ring_parent = self.client.location_path(self.project_id, self.location_id)

            try:
                key_ring = self.client.create_key_ring(
                    request={
                        'parent': key_ring_parent,
                        'key_ring_id': self.key_ring_id
                    }
                )
                logger.info(f"Created key ring: {key_ring.name}")
            except Exception as e:
                if 'ALREADY_EXISTS' in str(e):
                    logger.info(f"Key ring already exists: {self.key_ring_id}")
                else:
                    raise

            # Create crypto key
            try:
                key = self.client.create_crypto_key(
                    request={
                        'parent': self.client.key_ring_path(
                            self.project_id, self.location_id, self.key_ring_id
                        ),
                        'crypto_key_id': self.key_id,
                        'crypto_key': {
                            'purpose': kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
                            'version_template': {
                                'algorithm': kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
                            }
                        }
                    }
                )
                logger.info(f"Created crypto key: {key.name}")
            except Exception as e:
                if 'ALREADY_EXISTS' in str(e):
                    logger.info(f"Crypto key already exists: {self.key_id}")
                else:
                    raise

            return True

        except Exception as e:
            logger.error(f"Failed to create KMS resources: {str(e)}")
            raise
