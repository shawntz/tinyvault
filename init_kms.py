#!/usr/bin/env python3
"""
Initialize Google Cloud KMS resources for CSE
Run this script to create the key ring and key if they don't exist
"""
import os
import sys
from kms_service import KMSService


def main():
    # Get configuration from environment or prompt
    project_id = os.environ.get('GCP_PROJECT_ID')
    if not project_id:
        project_id = input("Enter GCP Project ID: ").strip()

    location = os.environ.get('KMS_LOCATION', 'us-central1')
    keyring = os.environ.get('KMS_KEYRING', 'cse-keyring')
    key = os.environ.get('KMS_KEY', 'cse-key')

    print(f"\nInitializing KMS resources:")
    print(f"  Project: {project_id}")
    print(f"  Location: {location}")
    print(f"  Key Ring: {keyring}")
    print(f"  Key: {key}")
    print()

    try:
        # Initialize KMS service
        kms = KMSService(
            project_id=project_id,
            location_id=location,
            key_ring_id=keyring,
            key_id=key
        )

        # Create resources
        print("Creating KMS resources...")
        kms.create_kms_resources()

        print("\n✓ KMS resources created successfully!")
        print(f"\nKey name: {kms.key_name}")
        print("\nYou can now deploy the service to Cloud Run.")

    except Exception as e:
        print(f"\n✗ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
