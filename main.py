import sys
import argparse
import os
import re
from collections import Counter
from time import perf_counter
from typing import Optional

from encryption import EncryptionManager
from password import PasswordManager
from file_handler import FileHandler
from timer import DecryptionTimer
from metadata import MetadataManager


def _has_encrypt_args(args) -> bool:
    """Return True when all positional encryption parameters are provided."""
    return all(
        [
            args.target_app,
            args.encryption_algorithm,
            args.size_manipulation is not None,
            args.custom_variable,
            args.duration is not None,
        ]
    )


class Encryptomatic:
    """Main Encrypt-o-matic application class"""
    
    def __init__(self):
        """Initialize application"""
        self.password_manager = PasswordManager()
        self.timer_manager = DecryptionTimer()

    @staticmethod
    def _size_mb(data: bytes) -> float:
        """Return size in MB."""
        return len(data) / 1024 / 1024

    @staticmethod
    def _step(index: int, total: int, message: str):
        """Print a uniform progress step."""
        print(f"[{index}/{total}] {message}")
    
    def perform_custom_operation(self, custom_variable: str):
        """
        Perform custom operation X
        
        Args:
            custom_variable: String in format "start-end" (e.g., "0-100000")
        """
        try:
            if '-' in custom_variable:
                start, end = map(int, custom_variable.split('-'))
            else:
                # Single integer means 0..end.
                start = 0
                end = int(custom_variable)
            
            if end <= start:
                print("Custom operation: no iterations needed.")
                return

            print(f"Custom operation: increment from {start} to {end}")

            # Print ~10 updates max for cleaner output.
            total_iters = end - start
            checkpoint = max(1, total_iters // 10)
            next_checkpoint = start + checkpoint

            counter = start
            while counter < end:
                counter += 1
                if counter >= next_checkpoint or counter == end:
                    done = counter - start
                    percent = int((done / total_iters) * 100)
                    print(f"  - custom X progress: {percent}% ({counter}/{end})")
                    next_checkpoint += checkpoint

            print("Custom operation complete.")
        except ValueError:
            print(f"Warning: Invalid format for variable X: {custom_variable}")
            print("Using default value: 0-100000")
            self.perform_custom_operation("0-100000")
    
    def encrypt_file(self, file_path: str, algorithm: str, size_manipulation_mb: int,
                    custom_variable: str, duration_minutes: int, password: str,
                    compression: Optional[str] = None):
        """
        Encrypt file
        
        Args:
            file_path: Path to file
            algorithm: Encryption algorithm
            size_manipulation_mb: Size to increase in MB
            custom_variable: Custom variable X
            duration_minutes: Encryption duration in minutes
            password: Password for encryption
            compression: Compression algorithm (optional)
        """
        print(f"\n=== Encrypt: {file_path} ===")
        print(f"Algorithm={algorithm} | Size+={size_manipulation_mb}MB | Timer={duration_minutes}min")
        
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}\nMake sure the path is correct and the file exists.")
        
        try:
            start_time = perf_counter()

            # Initialize components
            file_handler = FileHandler(size_manipulation_mb, compression)
            encryption_manager = EncryptionManager(algorithm, password)
            total_steps = 6 + int(bool(compression)) + int(size_manipulation_mb > 0) + int(duration_minutes > 0)
            step = 1

            self._step(step, total_steps, "Creating backup")
            file_handler.create_backup(file_path)
            step += 1
            
            self._step(step, total_steps, "Reading file")
            data = file_handler.read_file(file_path)
            print(f"  - original size: {self._size_mb(data):.2f} MB")
            step += 1
            
            if compression:
                self._step(step, total_steps, f"Compressing data ({compression})")
                data = file_handler.compress_data(data)
                print(f"  - compressed size: {self._size_mb(data):.2f} MB")
                step += 1
            
            if size_manipulation_mb > 0:
                self._step(step, total_steps, f"Increasing size by {size_manipulation_mb} MB")
                data = file_handler.increase_file_size(data)
                print(f"  - padded size: {self._size_mb(data):.2f} MB")
                step += 1
            
            self._step(step, total_steps, "Running custom operation X")
            self.perform_custom_operation(custom_variable)
            step += 1
            
            self._step(step, total_steps, "Encrypting payload")
            encrypted_data = encryption_manager.encrypt(data)
            step += 1
            
            self._step(step, total_steps, "Packaging metadata")
            metadata = MetadataManager.create_metadata(algorithm, compression, size_manipulation_mb)
            metadata_bytes = MetadataManager.pack_metadata(metadata)
            step += 1
            
            self._step(step, total_steps, "Writing encrypted file")
            final_data = metadata_bytes + encrypted_data
            file_handler.write_file(file_path, final_data)
            step += 1
            
            if duration_minutes > 0:
                self._step(step, total_steps, f"Saving timer ({duration_minutes} min)")
                self.timer_manager.save_timer(file_path, duration_minutes)
                step += 1
            
            elapsed = perf_counter() - start_time
            print(f"SUCCESS: encrypted ({self._size_mb(final_data):.2f} MB, {elapsed:.2f}s)")
            
        except FileNotFoundError as e:
            print(f"❌ {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            # Restore from backup on error
            try:
                file_handler = FileHandler()
                file_handler.restore_backup(file_path)
            except Exception:
                pass
            raise
    
    def decrypt_file(self, file_path: str, password: str, force: bool = False):
        """
        Decrypt file
        
        Args:
            file_path: Path to encrypted file
            password: Password for decryption
            force: Force decryption (ignore timer)
        """
        print(f"\n=== Decrypt: {file_path} ===")
        
        # Check if file exists
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            print("Make sure the path is correct and the file exists.")
            return False
        
        try:
            start_time = perf_counter()

            # Initialize components
            file_handler = FileHandler()
            if force:
                print("Note: --force used. Active timer bypass enabled.")
            total_steps = 5
            step = 1
            
            self._step(step, total_steps, "Reading encrypted file")
            file_data = file_handler.read_file(file_path)
            step += 1
            
            self._step(step, total_steps, "Parsing metadata")
            metadata = MetadataManager.unpack_metadata(file_data)
            if not metadata:
                print("  - metadata not found; using defaults")
                algorithm = "AES"
                compression = None
                size_manipulation_mb = 0
                metadata_size = 0
                encrypted_data = file_data
            else:
                algorithm = metadata.get("algorithm", "AES")
                compression = metadata.get("compression")
                size_manipulation_mb = metadata.get("size_manipulation_mb", 0)
                metadata_size = MetadataManager.get_metadata_size(file_data)
                encrypted_data = file_data[metadata_size:]
            
            print(f"  - algorithm: {algorithm}")
            if compression:
                print(f"  - compression: {compression}")
            step += 1
            
            encryption_manager = EncryptionManager(algorithm, password)
            
            self._step(step, total_steps, "Decrypting payload")
            data = encryption_manager.decrypt(encrypted_data)
            step += 1
            
            if size_manipulation_mb > 0:
                print("  - restoring original size")
                data = file_handler.decrease_file_size(data)
            
            if compression:
                print(f"  - decompressing ({compression})")
                file_handler.compression = compression
                data = file_handler.decompress_data(data)
            
            self._step(step, total_steps, "Writing decrypted file")
            file_handler.write_file(file_path, data)
            step += 1
            
            self._step(step, total_steps, "Cleaning timer and backup")
            self.timer_manager.remove_timer(file_path)
            file_handler.remove_backup(file_path)
            
            elapsed = perf_counter() - start_time
            print(f"SUCCESS: decrypted ({self._size_mb(data):.2f} MB, {elapsed:.2f}s)")
            return True
            
        except FileNotFoundError as e:
            print(f"❌ {e}")
            return False
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            print("Possibly incorrect password or corrupted file.")
            return False

    def decrypt_when_timer_expired(self, file_path: str) -> bool:
        """
        Restore original file from backup when decryption timer has expired.

        Args:
            file_path: Path to encrypted file

        Returns:
            True on successful restore, False otherwise
        """
        print(f"\n=== Timer Restore: {file_path} ===")

        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return False

        if not self.timer_manager.is_timer_expired(file_path):
            remaining = self.timer_manager.get_remaining_time(file_path)
            if remaining is None:
                print("❌ No decryption timer found for this file.")
            else:
                print(f"❌ Timer not expired yet. Remaining: {remaining}")
            return False

        file_handler = FileHandler()
        backup_path = file_handler.get_backup_path(file_path)
        if not os.path.exists(backup_path):
            print("❌ Timer expired, but backup is missing. Cannot recover without password.")
            return False

        try:
            print("Restoring original file from backup...")
            file_handler.restore_backup(file_path)
            self.timer_manager.remove_timer(file_path)
            print("SUCCESS: restored after timer expiration.")
            return True
        except Exception as e:
            print(f"❌ Timer-based decryption failed: {e}")
            return False

    def timer_blocks_decryption(self, file_path: str) -> bool:
        """Return True when an active timer should block decryption."""
        timers = self.timer_manager.load_timers()
        if file_path not in timers:
            return False
        return not self.timer_manager.is_timer_expired(file_path)

    def show_status(self, file_path: str):
        """Print encryption/timer/backup status for a file."""
        print(f"\n=== Status: {file_path} ===")

        if not os.path.exists(file_path):
            print("exists: no")
            return

        print("exists: yes")
        file_handler = FileHandler()
        backup_path = file_handler.get_backup_path(file_path)
        print(f"backup_exists: {'yes' if os.path.exists(backup_path) else 'no'}")

        try:
            raw = file_handler.read_file(file_path)
        except Exception as e:
            print(f"readable: no ({e})")
            return

        encrypted = MetadataManager.is_encrypted_file(raw)
        print(f"encrypted: {'yes' if encrypted else 'no'}")

        if encrypted:
            metadata = MetadataManager.unpack_metadata(raw)
            if metadata:
                algo = metadata.get("algorithm", "unknown")
                compression = metadata.get("compression") or "none"
                size_mb = metadata.get("size_manipulation_mb", 0)
                print(f"algorithm: {algo}")
                print(f"compression: {compression}")
                print(f"size_manipulation_mb: {size_mb}")

        timers = self.timer_manager.load_timers()
        timer_info = timers.get(file_path)
        if timer_info is None:
            print("timer: none")
            return

        remaining = self.timer_manager.get_remaining_time(file_path)
        if remaining is None:
            print("timer: unknown")
            return
        if remaining.total_seconds() == 0:
            print("timer: expired")
        else:
            print(f"timer: active ({remaining})")
    
    def encrypt_directory(self, directory_path: str, algorithm: str, size_manipulation_mb: int,
                         custom_variable: str, duration_minutes: int, password: str,
                         compression: Optional[str] = None):
        """
        Encrypt all files in directory
        
        Args:
            directory_path: Path to directory
            algorithm: Encryption algorithm
            size_manipulation_mb: Size to increase in MB
            custom_variable: Custom variable X
            duration_minutes: Encryption duration in minutes
            password: Password for encryption
            compression: Compression algorithm (optional)
        """
        file_handler = FileHandler()
        files = file_handler.iter_files_in_directory(directory_path)
        scanned = 0
        encrypted = 0
        failed = 0
        skipped = 0
        skipped_reasons: Counter[str] = Counter()
        
        print(f"\n=== Directory Encrypt: {directory_path} ===")
        print("Traversing files recursively...")
        
        for file_path in files:
            scanned += 1
            print(f"\n[{scanned}] {file_path}")

            unsupported_reason = file_handler.get_unsupported_file_reason(file_path)
            if unsupported_reason:
                print(f"Skipped: {unsupported_reason}")
                skipped += 1
                skipped_reasons[unsupported_reason] += 1
                continue

            try:
                self.encrypt_file(
                    file_path, algorithm, size_manipulation_mb,
                    custom_variable, duration_minutes, password, compression
                )
                encrypted += 1
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                failed += 1
                continue
        
        print(
            f"\nDONE: scanned={scanned} encrypted={encrypted} "
            f"failed={failed} skipped={skipped}"
        )
        if skipped_reasons:
            print("Skip reasons:")
            for reason, count in skipped_reasons.items():
                print(f"  - {reason}: {count}")


def parse_custom_variable(custom_var: str) -> str:
    """Validate custom variable format: <int> or <int>-<int>."""
    if re.fullmatch(r"\d+", custom_var):
        return custom_var
    if re.fullmatch(r"\d+-\d+", custom_var):
        start, end = map(int, custom_var.split("-"))
        if start > end:
            raise argparse.ArgumentTypeError("custom_variable range must be start<=end")
        return custom_var
    raise argparse.ArgumentTypeError("custom_variable must be <int> or <int>-<int>")


def parse_non_negative_int(value: str) -> int:
    """Argparse type for non-negative integer."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        prog='encrypt-o-matic',
        description='Encrypt and decrypt files with optional compression and timer restore.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  encrypt-o-matic.exe C:\\path\\to\\sample.bin AES 10 0-100000 60 --compression zlib
  encrypt-o-matic.exe --decrypt C:\\path\\to\\sample.bin
  encrypt-o-matic.exe --decrypt --timer-only C:\\path\\to\\sample.bin
  encrypt-o-matic.exe --encrypt-dir C:\\path\\to\\dir AES 2 0-50000 15
        """
    )
    
    # Main commands
    parser.add_argument('target_app', nargs='?', help='Path to target data file or directory')
    parser.add_argument('encryption_algorithm', nargs='?', 
                       choices=['AES', 'ChaCha20', 'Twofish'],
                       help='Encryption algorithm (AES, ChaCha20, or Twofish)')
    parser.add_argument('size_manipulation', nargs='?', type=parse_non_negative_int,
                       help='File size manipulation number in MB')
    parser.add_argument('custom_variable', nargs='?', type=parse_custom_variable,
                       help='Custom variable X (e.g., 0-100000)')
    parser.add_argument('duration', nargs='?', type=parse_non_negative_int,
                       help='Encryption duration in minutes')
    
    # Additional options
    parser.add_argument('--decrypt', action='store_true',
                       help='Decrypt file')
    parser.add_argument('--status', action='store_true',
                       help='Show file status (encryption/timer/backup)')
    parser.add_argument('--force', action='store_true',
                       help='Bypass active timer for password-based decryption')
    parser.add_argument('--encrypt-dir', action='store_true',
                       help='Encrypt entire directory')
    parser.add_argument('--compression', choices=['zlib', 'bzip2'],
                       help='Compression algorithm before encryption (zlib or bzip2)')
    parser.add_argument('--timer-only', action='store_true',
                       help='Decrypt only if timer has expired (no password prompt)')
    
    args = parser.parse_args()

    if args.decrypt and args.encrypt_dir:
        parser.error("--decrypt and --encrypt-dir cannot be used together")

    if args.timer_only and not args.decrypt:
        parser.error("--timer-only requires --decrypt")

    if args.status and (args.decrypt or args.encrypt_dir):
        parser.error("--status cannot be combined with --decrypt/--encrypt-dir")
    
    app = Encryptomatic()

    if args.status:
        if not args.target_app:
            parser.error("File path is required for --status")
        app.show_status(args.target_app)
        return
    
    # Decryption mode
    if args.decrypt:
        if not args.target_app:
            parser.error("File path is required for decryption")

        if args.timer_only:
            if not app.decrypt_when_timer_expired(args.target_app):
                sys.exit(1)
        else:
            if app.timer_blocks_decryption(args.target_app) and not args.force:
                remaining = app.timer_manager.get_remaining_time(args.target_app)
                if remaining is not None:
                    print(f"❌ Decryption blocked by active timer. Remaining: {remaining}")
                else:
                    print("❌ Decryption blocked by active timer.")
                print("Use --timer-only after expiry, or --force to override with password.")
                sys.exit(1)
            try:
                password = app.password_manager.require_password()
                if not app.decrypt_file(args.target_app, password, args.force):
                    # If password-based decryption fails, only allow timer-based restore
                    # when the timer is already expired.
                    if not app.decrypt_when_timer_expired(args.target_app):
                        sys.exit(1)
            except ValueError as e:
                print(f"❌ {e}")
                if not app.decrypt_when_timer_expired(args.target_app):
                    sys.exit(1)
    
    # Directory encryption mode
    elif args.encrypt_dir:
        if not _has_encrypt_args(args):
            parser.error("All parameters are required for directory encryption")
        
        try:
            password = app.password_manager.require_password()
            app.encrypt_directory(
                args.target_app, args.encryption_algorithm, args.size_manipulation,
                args.custom_variable, args.duration, password, args.compression
            )
        except ValueError as e:
            print(f"❌ {e}")
            sys.exit(1)
    
    # File encryption mode
    else:
        if not _has_encrypt_args(args):
            parser.print_help()
            sys.exit(1)
        
        try:
            password = app.password_manager.require_password()
            app.encrypt_file(
                args.target_app, args.encryption_algorithm, args.size_manipulation,
                args.custom_variable, args.duration, password, args.compression
            )
        except ValueError as e:
            print(f"❌ {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Critical error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
