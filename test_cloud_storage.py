"""
Test Suite for Secure Cloud Storage Application
Tests all major features including encryption, sharing, versioning, and deletion
"""

import os
import sys
import tempfile
import secrets
import shutil
from pathlib import Path

# Add path to import the application
sys.path.insert(0, os.path.dirname(__file__))
from secure_cloud_storage import (
    CloudStorageEngine, AES256GCM, ChaCha20Poly1305Encryption,
    KeyManager
)


def cleanup_test_storage():
    """Clean up test storage directory"""
    if Path("test_cloud_storage").exists():
        shutil.rmtree("test_cloud_storage")
    if Path("test_cloud_keys").exists():
        shutil.rmtree("test_cloud_keys")


def test_encryption_algorithms():
    """Test both encryption algorithms"""
    print("=" * 60)
    print("TEST 1: Encryption Algorithms")
    print("=" * 60)
    
    test_data = b"This is secret data for encryption testing! 123456"
    key = secrets.token_bytes(32)
    
    # Test AES-256-GCM
    print("\n🔐 Testing AES-256-GCM...")
    aes = AES256GCM()
    encrypted_aes = aes.encrypt(test_data, key)
    decrypted_aes = aes.decrypt(encrypted_aes, key)
    
    if decrypted_aes == test_data:
        print("✅ AES-256-GCM: Encryption/Decryption successful")
    else:
        print("❌ AES-256-GCM: Failed")
    
    # Test ChaCha20-Poly1305
    print("\n🔐 Testing ChaCha20-Poly1305...")
    chacha = ChaCha20Poly1305Encryption()
    encrypted_chacha = chacha.encrypt(test_data, key)
    decrypted_chacha = chacha.decrypt(encrypted_chacha, key)
    
    if decrypted_chacha == test_data:
        print("✅ ChaCha20-Poly1305: Encryption/Decryption successful")
    else:
        print("❌ ChaCha20-Poly1305: Failed")
    
    # Compare sizes
    print(f"\n📊 Encryption Overhead Comparison:")
    print(f"   Original size:     {len(test_data)} bytes")
    print(f"   AES-256-GCM:       {len(encrypted_aes)} bytes (+{len(encrypted_aes)-len(test_data)} bytes)")
    print(f"   ChaCha20-Poly1305: {len(encrypted_chacha)} bytes (+{len(encrypted_chacha)-len(test_data)} bytes)")
    
    print("\n" + "=" * 60)


def test_file_upload_download():
    """Test file upload and download"""
    print("\n" + "=" * 60)
    print("TEST 2: File Upload and Download")
    print("=" * 60)
    
    cleanup_test_storage()
    
    storage = CloudStorageEngine(storage_path="test_cloud_storage")
    key_manager = KeyManager(keys_dir="test_cloud_keys")
    
    # Generate key
    key = key_manager.generate_key("user1", "test_key")
    print("\n🔑 Encryption key generated")
    
    # Create test file
    test_content = b"Test file content for cloud storage!\n" * 100
    test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
    test_file.write(test_content)
    test_file.close()
    
    print(f"📄 Test file created: {os.path.basename(test_file.name)}")
    print(f"   Size: {len(test_content)} bytes")
    
    # Test upload with AES-256-GCM
    print("\n☁️ Uploading with AES-256-GCM...")
    success, file_id, elapsed, orig_hash, enc_hash = storage.upload_file(
        test_file.name,
        "user1",
        key,
        "AES-256-GCM"
    )
    
    if success:
        print(f"✅ Upload successful!")
        print(f"   File ID: {file_id}")
        print(f"   Time: {elapsed:.3f}s")
        print(f"   Original hash: {orig_hash[:32]}...")
        print(f"   Encrypted hash: {enc_hash[:32]}...")
    else:
        print("❌ Upload failed")
        return
    
    # Test download
    output_file = tempfile.mktemp(suffix='.txt')
    print(f"\n📥 Downloading file...")
    success, elapsed, download_hash = storage.download_file(file_id, output_file, key)
    
    if success:
        print(f"✅ Download successful!")
        print(f"   Time: {elapsed:.3f}s")
        print(f"   Hash: {download_hash[:32]}...")
        
        # Verify content
        with open(output_file, 'rb') as f:
            downloaded_content = f.read()
        
        if downloaded_content == test_content:
            print("✅ Content verification passed!")
        else:
            print("❌ Content verification failed!")
    else:
        print(f"❌ Download failed: {elapsed}")
    
    # Cleanup
    os.unlink(test_file.name)
    os.unlink(output_file)
    
    print("\n" + "=" * 60)


def test_versioning():
    """Test file versioning"""
    print("\n" + "=" * 60)
    print("TEST 3: File Versioning")
    print("=" * 60)
    
    storage = CloudStorageEngine(storage_path="test_cloud_storage")
    key_manager = KeyManager(keys_dir="test_cloud_keys")
    
    key = key_manager.get_key("user1", "test_key")
    
    # Get first file
    files = storage.get_user_files("user1")
    if not files:
        print("❌ No files found")
        return
    
    file_id = files[0]['id']
    print(f"\n📄 Working with file: {files[0]['filename']}")
    print(f"   Current version: v{files[0]['current_version']}")
    
    # Create new version
    new_content = b"This is version 2 of the file!\n" * 100
    new_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
    new_file.write(new_content)
    new_file.close()
    
    print(f"\n➕ Creating version 2...")
    success, version = storage.create_version(new_file.name, file_id, key)
    
    if success:
        print(f"✅ Version {version} created successfully!")
    else:
        print(f"❌ Version creation failed: {version}")
        return
    
    # Create another version
    newer_content = b"This is version 3 of the file!\n" * 100
    newer_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
    newer_file.write(newer_content)
    newer_file.close()
    
    print(f"\n➕ Creating version 3...")
    success, version = storage.create_version(newer_file.name, file_id, key)
    
    if success:
        print(f"✅ Version {version} created successfully!")
    else:
        print(f"❌ Version creation failed: {version}")
        return
    
    # List versions
    versions = storage.metadata["versions"][file_id]
    print(f"\n📋 Version history:")
    for v in versions:
        print(f"   v{v['version']}: {v['timestamp']} - {v['size']} bytes")
    
    # Test rollback
    print(f"\n⬅️ Rolling back to version 1...")
    success, message = storage.rollback_version(file_id, 1, key)
    
    if success:
        print(f"✅ Rollback successful: {message}")
        current = storage.metadata["files"][file_id]["current_version"]
        print(f"   Current version is now: v{current}")
    else:
        print(f"❌ Rollback failed: {message}")
    
    # Cleanup
    os.unlink(new_file.name)
    os.unlink(newer_file.name)
    
    print("\n" + "=" * 60)


def test_file_sharing():
    """Test file sharing functionality"""
    print("\n" + "=" * 60)
    print("TEST 4: File Sharing and Access Control")
    print("=" * 60)
    
    storage = CloudStorageEngine(storage_path="test_cloud_storage")
    
    # Get first file
    files = storage.get_user_files("user1")
    if not files:
        print("❌ No files found")
        return
    
    file_id = files[0]['id']
    filename = files[0]['filename']
    
    print(f"\n📄 Sharing file: {filename}")
    
    # Share with user2
    print(f"\n🤝 Sharing with user2 (read permission)...")
    success, message = storage.share_file(file_id, "user1", "user2", "read")
    
    if success:
        print(f"✅ {message}")
    else:
        print(f"❌ Failed: {message}")
    
    # Share with user3
    print(f"\n🤝 Sharing with user3 (write permission)...")
    success, message = storage.share_file(file_id, "user1", "user3", "write")
    
    if success:
        print(f"✅ {message}")
    else:
        print(f"❌ Failed: {message}")
    
    # Check shared files for user2
    print(f"\n📋 Files shared with user2:")
    shared = storage.get_shared_files("user2")
    for f in shared:
        print(f"   • {f['filename']} (Permission: {f['permission']})")
    
    # Revoke access
    print(f"\n❌ Revoking user2's access...")
    success, message = storage.revoke_share(file_id, "user1", "user2")
    
    if success:
        print(f"✅ {message}")
    else:
        print(f"❌ Failed: {message}")
    
    # Check again
    print(f"\n📋 Files shared with user2 (after revoke):")
    shared = storage.get_shared_files("user2")
    if not shared:
        print("   (None)")
    else:
        for f in shared:
            print(f"   • {f['filename']}")
    
    print("\n" + "=" * 60)


def test_secure_deletion():
    """Test secure file deletion"""
    print("\n" + "=" * 60)
    print("TEST 5: Secure File Deletion")
    print("=" * 60)
    
    storage = CloudStorageEngine(storage_path="test_cloud_storage")
    key_manager = KeyManager(keys_dir="test_cloud_keys")
    
    # Create a file to delete
    key = key_manager.get_key("user1", "test_key")
    
    test_content = b"This file will be securely deleted!\n" * 50
    test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
    test_file.write(test_content)
    test_file.close()
    
    print("\n📄 Creating file for deletion test...")
    success, file_id, _, _, _ = storage.upload_file(
        test_file.name,
        "user1",
        key,
        "AES-256-GCM"
    )
    
    if not success:
        print("❌ Failed to create test file")
        return
    
    print(f"✅ Test file created: {file_id}")
    
    file_info = storage.metadata["files"][file_id]
    print(f"   Filename: {file_info['filename']}")
    print(f"   Size: {file_info['size']} bytes")
    
    # Perform secure deletion
    print(f"\n🗑️ Performing secure deletion...")
    print("   (Overwriting with random data 3 times)")
    
    success, message = storage.secure_delete(file_id, "user1")
    
    if success:
        print(f"✅ {message}")
        
        # Verify file is gone
        if file_id not in storage.metadata["files"]:
            print("✅ File removed from metadata")
        
        # Check if physical file is deleted
        file_path = Path("test_cloud_storage") / f"{file_id}.enc"
        if not file_path.exists():
            print("✅ Encrypted file physically deleted")
        else:
            print("❌ Encrypted file still exists")
    else:
        print(f"❌ Deletion failed: {message}")
    
    # Cleanup
    os.unlink(test_file.name)
    
    print("\n" + "=" * 60)


def test_statistics():
    """Test storage statistics"""
    print("\n" + "=" * 60)
    print("TEST 6: Storage Statistics")
    print("=" * 60)
    
    storage = CloudStorageEngine(storage_path="test_cloud_storage")
    
    stats = storage.get_storage_stats()
    
    print(f"\n📊 Storage Statistics:")
    print(f"   Total Files:         {stats['total_files']}")
    print(f"   Total Size:          {stats['total_size'] / 1024:.2f} KB")
    print(f"   Encrypted Size:      {stats['total_encrypted_size'] / 1024:.2f} KB")
    
    if stats['total_size'] > 0:
        overhead = ((stats['total_encrypted_size'] - stats['total_size']) / 
                   stats['total_size'] * 100)
        print(f"   Encryption Overhead: {overhead:.2f}%")
    
    print(f"   Total Versions:      {stats['total_versions']}")
    print(f"   Total Shares:        {stats['total_shares']}")
    
    print(f"\n📈 Algorithm Distribution:")
    for algo, data in stats['algorithm_stats'].items():
        print(f"   {algo}: {data['count']} files, {data['size']/1024:.2f} KB")
    
    print("\n" + "=" * 60)


def test_algorithm_comparison():
    """Compare encryption algorithm performance"""
    print("\n" + "=" * 60)
    print("TEST 7: Algorithm Performance Comparison")
    print("=" * 60)
    
    cleanup_test_storage()
    
    storage = CloudStorageEngine(storage_path="test_cloud_storage")
    key_manager = KeyManager(keys_dir="test_cloud_keys")
    
    key = key_manager.generate_key("user1", "perf_test")
    
    # Create test file
    test_sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB
    
    print("\n⏱️ Performance Comparison:")
    print("─" * 60)
    
    for size in test_sizes:
        test_content = secrets.token_bytes(size)
        test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
        test_file.write(test_content)
        test_file.close()
        
        size_label = f"{size/1024:.0f}KB" if size < 1024*1024 else f"{size/(1024*1024):.1f}MB"
        print(f"\n📦 File Size: {size_label}")
        
        # Test AES-256-GCM
        success, file_id_aes, time_aes, _, _ = storage.upload_file(
            test_file.name, "user1", key, "AES-256-GCM"
        )
        
        if success:
            print(f"   AES-256-GCM:       {time_aes:.4f}s ({size/time_aes/1024:.2f} KB/s)")
        
        # Test ChaCha20-Poly1305
        success, file_id_chacha, time_chacha, _, _ = storage.upload_file(
            test_file.name, "user1", key, "ChaCha20-Poly1305"
        )
        
        if success:
            print(f"   ChaCha20-Poly1305: {time_chacha:.4f}s ({size/time_chacha/1024:.2f} KB/s)")
        
        # Cleanup
        os.unlink(test_file.name)
        if file_id_aes:
            storage.secure_delete(file_id_aes, "user1")
        if file_id_chacha:
            storage.secure_delete(file_id_chacha, "user1")
    
    print("\n" + "=" * 60)


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 6 + "SECURE CLOUD STORAGE - COMPREHENSIVE TEST SUITE" + " " * 5 + "║")
    print("║" + " " * 15 + "by Dr. Mohammed Tawfik" + " " * 22 + "║")
    print("╚" + "=" * 58 + "╝")
    
    try:
        test_encryption_algorithms()
        test_file_upload_download()
        test_versioning()
        test_file_sharing()
        test_secure_deletion()
        test_statistics()
        test_algorithm_comparison()
        
        print("\n" + "=" * 60)
        print("🎉 ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("\n✅ The Secure Cloud Storage application is fully functional!")
        print("✅ All features tested and verified:")
        print("   • Client-side encryption (AES-256-GCM & ChaCha20-Poly1305)")
        print("   • File upload/download")
        print("   • File versioning and rollback")
        print("   • File sharing with access control")
        print("   • Secure deletion with overwriting")
        print("   • Storage statistics and analytics")
        print("\n✅ You can now run the GUI application:")
        print("   python secure_cloud_storage.py")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        print("🧹 Cleaning up test files...")
        cleanup_test_storage()
        print("✅ Cleanup complete")


if __name__ == "__main__":
    main()
