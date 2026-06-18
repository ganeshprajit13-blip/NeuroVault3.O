# Secure File Management System

A secure file management system built with Flask, featuring encryption, user authentication, and file sharing.

## Features

- User registration and login with OTP verification
- Password hashing and forgot password functionality
- File upload with size limits and type validation
- AES encryption for files, RSA for key exchange (hybrid encryption)
- Secure file sharing with password protection, expiry, and download limits
- Access control with roles (admin/user)
- Logging and monitoring of activities
- File integrity checks with SHA-256 hashes
- QR code generation for sharing links

## Installation

1. Clone or download the project.
2. Install dependencies: `pip install -r requirements.txt`
3. Set environment variables for email (MAIL_USERNAME, MAIL_PASSWORD)
4. Run the application: `python run.py`

## Usage

- Register a new account
- Verify with OTP sent to email
- Login and upload files
- Files are automatically encrypted
- Share files with secure links
- Download and decrypt files

## Security Notes

- Uses hybrid encryption (AES + RSA)
- Passwords hashed with bcrypt
- OTP for verification
- File integrity checks
- Activity logging

## API Routes

- `/auth/register` - User registration
- `/auth/login` - User login
- `/files/upload` - Upload file
- `/files/download/<file_id>` - Download file
- `/files/share/<file_id>` - Share file
- `/shared/<share_link>` - Access shared file

## Modules

- `auth/` - Authentication routes
- `files/` - File management routes
- `encryption/` - Encryption utilities
- `utils/` - Helper functions