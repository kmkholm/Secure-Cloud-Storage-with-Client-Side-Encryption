# ☁️ Secure Cloud Storage with Client-Side Encryption

**Author:** Dr. Mohammed Tawfik  
**Institution:** Ajloun National University, Jordan  
**Project:** Bachelor Degree Cybersecurity Project  
**Date:** November 9, 2024  

A comprehensive secure cloud storage application implementing zero-knowledge architecture with client-side encryption, file sharing, versioning, and secure deletion.

---

## 🎯 Project Overview

This application demonstrates a **zero-knowledge cloud storage system** where all files are encrypted on the client side before being uploaded to the "cloud" (simulated with local storage). The server never sees unencrypted data, ensuring maximum privacy and security.

### Key Concept: Zero-Knowledge Architecture

**Zero-knowledge** means the storage server has zero knowledge of your data:
- Files are encrypted on YOUR computer before upload
- Server only stores encrypted data
- Only YOU have the decryption keys
- Even if the server is compromised, your data remains secure

This is how services like ProtonDrive, Tresorit, and secure password managers work.

---

## ✨ Features

### 🔐 Encryption & Security
- **Client-Side Encryption**: All encryption happens on your computer
- **Multiple Algorithms**: 
  - AES-256-GCM (NIST approved, hardware accelerated)
  - ChaCha20-Poly1305 (Modern, excellent on all platforms)
- **Authenticated Encryption**: Prevents tampering
- **Secure Key Management**: Keys stored locally, never transmitted

### 📁 File Management
- **Upload & Download**: Seamless encrypted file operations
- **File Versioning**: Keep multiple versions of files
- **Version Rollback**: Restore previous versions
- **File Metadata**: Track size, upload time, algorithms used

### 🤝 Sharing & Access Control
- **File Sharing**: Share encrypted files with other users
- **Permission Levels**: 
  - Read-only access
  - Read & Write access
- **Access Revocation**: Remove access anytime

### 🗑️ Secure Deletion
- **Data Overwriting**: Files overwritten 3 times before deletion
- **Complete Removal**: Removes file, versions, and metadata
- **No Recovery**: Ensures data cannot be recovered

### 📊 Analytics & Visualization
- **Storage Statistics**: View total usage, file counts
- **Algorithm Distribution**: See which algorithms you use most
- **Encryption Overhead**: Track space used by encryption
- **Version Tracking**: Monitor file version history

---

## 🛠️ Technical Specifications

### Encryption Details

#### AES-256-GCM
- **Standard**: NIST FIPS 197
- **Key Size**: 256 bits (32 bytes)
- **Mode**: GCM (Galois/Counter Mode)
- **Authentication**: 128-bit tag
- **Performance**: Excellent (hardware acceleration on modern CPUs)
- **Security**: Approved for TOP SECRET information
- **Best For**: General purpose, maximum compatibility

#### ChaCha20-Poly1305
- **Standard**: RFC 8439
- **Key Size**: 256 bits (32 bytes)
- **Mode**: Stream cipher with Poly1305 MAC
- **Authentication**: Poly1305 authentication tag
- **Performance**: Excellent on all platforms (pure software)
- **Security**: Military-grade, modern alternative to AES
- **Best For**: Mobile devices, systems without AES hardware support

### File Structure

Encrypted files are stored with this structure:
```
[NONCE][AUTH_TAG][ENCRYPTED_DATA]
```

Metadata is stored separately in JSON format:
```json
{
  "files": {
    "file_id": {
      "filename": "document.pdf",
      "user_id": "user1",
      "algorithm": "AES-256-GCM",
      "upload_time": "2024-11-09T12:00:00",
      "size": 1048576,
      "encrypted_size": 1048608,
      "original_hash": "sha256...",
      "encrypted_hash": "sha256...",
      "version": 1,
      "current_version": 1
    }
  },
  "versions": { ... },
  "shares": { ... }
}
```

---

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Step 1: Install Dependencies

```bash
pip install cryptography
```

Or use the requirements file:
```bash
pip install -r cloud_requirements.txt
```

### Step 2: Run Application

```bash
python secure_cloud_storage.py
```

---

## 📖 User Guide

### First Time Setup

1. **Launch Application**
   ```bash
   python secure_cloud_storage.py
   ```

2. **Generate Encryption Key**
   - Go to "Upload File" tab
   - Click "Generate New Key"
   - Enter a key name (e.g., "my_main_key")
   - Key is created and stored locally

### Uploading Files

1. Click "Upload File" tab
2. Click "Browse" and select file
3. Choose encryption algorithm:
   - **AES-256-GCM**: Best for general use
   - **ChaCha20-Poly1305**: Best for mobile or older hardware
4. Select your encryption key from dropdown
5. Click "☁️ Upload File"
6. Watch progress bar
7. File is encrypted and "uploaded" to cloud!

### Downloading Files

1. Go to "My Files" tab
2. Select file you want to download
3. Click "📥 Download"
4. Enter the key name you used for encryption
5. Choose where to save
6. File is downloaded and decrypted!

### Sharing Files

1. Go to "Sharing" tab
2. Select file to share from dropdown
3. Enter username to share with
4. Choose permission:
   - **Read Only**: Can download only
   - **Read & Write**: Can download and upload new versions
5. Click "Share File"

**Note**: In a real system, you would share the decryption key securely with the other user (e.g., via secure messaging). For this demo, users need to know the key name.

### Managing Versions

1. Go to "Versions" tab
2. Select file from dropdown
3. Click "Load Versions" to see version history
4. Options:
   - **Create New Version**: Upload new version of file
   - **Rollback**: Restore previous version

### Viewing Statistics

1. Go to "Statistics" tab
2. View:
   - Total files and storage used
   - Encryption overhead
   - Algorithm distribution
   - Version and sharing statistics
3. Click "🔄 Refresh Statistics" to update

---

## 🔐 Security Best Practices

### Key Management
✅ Generate unique keys for different purposes  
✅ Store keys securely (never share via insecure channels)  
✅ Back up keys in secure location  
✅ Use strong key names (not easily guessable)  

### File Handling
✅ Test download/decryption before deleting original  
✅ Keep backup copies of important files  
✅ Verify file integrity after download  
✅ Use secure deletion when removing sensitive files  

### Sharing
✅ Only share with trusted users  
✅ Use read-only permission when possible  
✅ Revoke access when no longer needed  
✅ Share decryption keys through secure channels  

### General
✅ Keep application updated  
✅ Use strong passwords for computer  
✅ Enable full disk encryption  
✅ Regular backups of key storage  

---

## 🧪 Testing

### Run Test Suite

```bash
python test_cloud_storage.py
```

This will test:
- ✅ Both encryption algorithms
- ✅ File upload/download
- ✅ File versioning
- ✅ File sharing and access control
- ✅ Secure deletion
- ✅ Storage statistics
- ✅ Algorithm performance comparison

Expected output: All tests should pass with ✅

---

## 📊 Performance Benchmarks

Based on test results (Intel i5, 16GB RAM):

| File Size | AES-256-GCM | ChaCha20-Poly1305 |
|-----------|-------------|-------------------|
| 1 KB      | 2,065 KB/s  | 2,225 KB/s       |
| 10 KB     | 27,740 KB/s | 34,894 KB/s      |
| 100 KB    | 152,354 KB/s| 195,448 KB/s     |
| 1 MB      | 221,825 KB/s| 302,548 KB/s     |

**Observations:**
- ChaCha20-Poly1305 is slightly faster for small files
- Both algorithms scale well with file size
- Performance is excellent for typical file sizes
- Actual performance depends on hardware

---

## 🎓 Educational Value

This project demonstrates:

### Cryptography Concepts
✓ Client-side encryption  
✓ Zero-knowledge architecture  
✓ Multiple encryption algorithms  
✓ Authenticated encryption (AEAD)  
✓ Key management  
✓ Secure deletion  

### Software Development
✓ Object-oriented design  
✓ GUI development with Tkinter  
✓ File I/O operations  
✓ JSON data management  
✓ Threading for responsive UI  
✓ Comprehensive testing  

### Cloud Security
✓ Zero-knowledge storage principles  
✓ End-to-end encryption  
✓ Access control mechanisms  
✓ Version control systems  
✓ Secure data deletion  

---

## 🔧 Troubleshooting

### Problem: "Module 'cryptography' not found"
**Solution**: Install cryptography library
```bash
pip install cryptography
```

### Problem: Can't decrypt downloaded file
**Solution**: 
- Make sure you use the SAME key name used for encryption
- Verify the key still exists in key storage
- Check that file wasn't corrupted

### Problem: Upload fails
**Solution**:
- Check you have write permissions to cloud_storage directory
- Ensure enough disk space available
- Verify file isn't already open in another program

### Problem: Sharing doesn't work
**Solution**:
- Ensure you're the file owner
- Verify username is correct
- Remember: in this demo, shared user needs same key to decrypt

---

## 📁 Project Structure

```
secure-cloud-storage/
├── secure_cloud_storage.py    # Main application (1400+ lines)
├── test_cloud_storage.py      # Test suite (600+ lines)
├── cloud_requirements.txt     # Dependencies
├── README.md                  # This file
├── cloud_storage/             # Encrypted files (auto-created)
│   ├── metadata.json         # File metadata
│   └── *.enc                 # Encrypted files
└── cloud_keys/               # Encryption keys (auto-created)
    └── keys.json            # Key storage
```

---

## 🔮 Future Enhancements

Possible improvements for extended projects:
- Real cloud storage integration (AWS S3, Google Cloud, Azure)
- Web interface (Flask/Django)
- Multi-user authentication system
- Real-time collaboration features
- Mobile application (Android/iOS)
- Advanced key sharing with public-key cryptography
- File compression before encryption
- Deduplica tion for space efficiency
- Blockchain for audit trail
- Two-factor authentication

---

## 📝 Academic Context

**Suitable For:**
- Bachelor's degree final project
- Cloud security coursework
- Applied cryptography project
- Secure systems design course

**Learning Outcomes:**
- Understanding zero-knowledge architecture
- Implementing client-side encryption
- Designing secure storage systems
- Algorithm selection and comparison
- Access control implementation
- Secure deletion techniques

**Complexity Level:** Advanced (suitable for final year project)

---

## ⚠️ Important Notes

### This is a DEMO System
- Uses local storage to simulate cloud
- User authentication is simplified
- Key sharing is simulated
- Not production-ready without enhancements

### For Production Use, Add:
- Real user authentication
- Network security (TLS/SSL)
- Database for metadata
- Proper key exchange mechanisms
- Backup and recovery systems
- Logging and monitoring
- Rate limiting and quotas

### Privacy Notice
- All encryption happens locally
- Keys are stored on your computer
- "Server" (local storage) never sees unencrypted data
- This demonstrates the principle; real cloud needs network security

---

## 📄 License

Educational use for Bachelor Degree Project  
© 2024 Dr. Mohammed Tawfik - All Rights Reserved

---

## 👨‍💻 Author

**Dr. Mohammed Tawfik**  
Assistant Professor of Cybersecurity  
Ajloun National University, Jordan  
November 9, 2024  

Project Category: Cloud Security & Applied Cryptography  
Bachelor Degree Cybersecurity Project  

---

## 📞 Support

For questions or issues:
1. Check Help menu in application
2. Review this README
3. Run test suite to verify installation
4. Check logs for error messages

---

**Ready to secure your files in the cloud? Start encrypting! 🔐☁️**

---

## 🎉 Quick Start Checklist

- [ ] Install Python 3.7+
- [ ] Install cryptography: `pip install cryptography`
- [ ] Run tests: `python test_cloud_storage.py`
- [ ] Launch app: `python secure_cloud_storage.py`
- [ ] Generate encryption key
- [ ] Upload first file
- [ ] Test download
- [ ] Explore features!

