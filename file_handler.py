import os
import tempfile
import zlib
import bz2
from pathlib import Path
from typing import Iterator, List, Optional


class FileHandler:
    """File handler for encryption operations."""
    PADDING_MARKER = b"ENCRYPTOMATIC_PADDING_START"

    def __init__(self, size_manipulation_mb: int = 0, compression: Optional[str] = None):
        """
        Initialize file handler
        
        Args:
            size_manipulation_mb: Size to increase file by in MB
            compression: Compression algorithm (None, 'zlib', 'bzip2')
        """
        self.size_manipulation_mb = size_manipulation_mb
        self.compression = compression
    
    def read_file(self, file_path: str) -> bytes:
        """
        Read file
        
        Args:
            file_path: Path to file
            
        Returns:
            File contents
        """
        with open(file_path, "rb") as f:
            return f.read()

    def write_file(self, file_path: str, data: bytes):
        """
        Write file
        
        Args:
            file_path: Path to file
            data: Data to write
        """
        target_path = Path(file_path)
        temp_fd, temp_path = tempfile.mkstemp(
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            dir=str(target_path.parent),
        )
        try:
            with os.fdopen(temp_fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, str(target_path))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    def compress_data(self, data: bytes) -> bytes:
        """
        Compress data
        
        Args:
            data: Data to compress
            
        Returns:
            Compressed data
        """
        if self.compression == "zlib":
            return zlib.compress(data, level=9)
        if self.compression == "bzip2":
            return bz2.compress(data, compresslevel=9)
        return data
    
    def decompress_data(self, compressed_data: bytes) -> bytes:
        """
        Decompress data
        
        Args:
            compressed_data: Compressed data
            
        Returns:
            Decompressed data
        """
        if self.compression == "zlib":
            return zlib.decompress(compressed_data)
        if self.compression == "bzip2":
            return bz2.decompress(compressed_data)
        return compressed_data
    
    def increase_file_size(self, data: bytes) -> bytes:
        """
        Increase file size by specified amount in MB
        
        Args:
            data: Original data
            
        Returns:
            Data with increased size
        """
        if self.size_manipulation_mb <= 0:
            return data
        
        # Generate random data to increase size
        additional_size = self.size_manipulation_mb * 1024 * 1024  # MB to bytes
        padding = os.urandom(additional_size)
        
        # Add padding start marker for recovery
        return data + self.PADDING_MARKER + padding
    
    def decrease_file_size(self, data: bytes) -> bytes:
        """
        Decrease file size (remove added padding)
        
        Args:
            data: Data with padding
            
        Returns:
            Data without padding
        """
        marker_pos = data.rfind(self.PADDING_MARKER)
        
        if marker_pos != -1:
            return data[:marker_pos]
        return data
    
    def get_files_in_directory(self, directory_path: str) -> List[str]:
        """
        Get list of all files in directory (recursively)
        
        Args:
            directory_path: Path to directory
            
        Returns:
            List of file paths
        """
        files = []
        path = Path(directory_path)
        
        if path.is_file():
            return [str(path)]
        
        if not path.is_dir():
            raise ValueError(f"Path does not exist or is not a file/directory: {directory_path}")
        
        for file_path in path.rglob('*'):
            if file_path.is_file():
                files.append(str(file_path))
        
        return files

    def iter_files_in_directory(self, directory_path: str) -> Iterator[str]:
        """
        Iterate files in a directory recursively without loading all paths in memory.

        Args:
            directory_path: Path to file or directory

        Yields:
            File paths
        """
        path = Path(directory_path)

        if path.is_file():
            yield str(path)
            return

        if not path.is_dir():
            raise ValueError(f"Path does not exist or is not a file/directory: {directory_path}")

        stack = [str(path)]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                yield entry.path
                        except OSError:
                            continue
            except OSError:
                continue

    def get_unsupported_file_reason(self, file_path: str) -> Optional[str]:
        """
        Return unsupported reason for a file path, otherwise None.

        Args:
            file_path: Candidate path

        Returns:
            Reason string if unsupported, else None
        """
        path = Path(file_path)

        try:
            if path.is_symlink():
                return "symlink is not supported"
            if not path.is_file():
                return "not a regular file"
            if path.name.endswith(".encryptomatic_backup"):
                return "backup file is skipped"
            if not os.access(file_path, os.R_OK):
                return "read permission denied"
            if not os.access(path.parent, os.W_OK):
                return "directory is not writable"
        except OSError as exc:
            return f"file access error: {exc}"

        return None

    def is_directory(self, path: str) -> bool:
        """
        Check if path is a directory
        
        Args:
            path: Path to check
            
        Returns:
            True if it's a directory
        """
        return Path(path).is_dir()
    
    def get_backup_path(self, file_path: str) -> str:
        """
        Get backup file path
        
        Args:
            file_path: Path to original file
            
        Returns:
            Path to backup
        """
        return f"{file_path}.encryptomatic_backup"
    
    def create_backup(self, file_path: str):
        """
        Create backup of file
        
        Args:
            file_path: Path to file
        """
        backup_path = self.get_backup_path(file_path)
        if os.path.exists(file_path):
            data = self.read_file(file_path)
            self.write_file(backup_path, data)
    
    def restore_backup(self, file_path: str):
        """
        Restore file from backup
        
        Args:
            file_path: Path to file
        """
        backup_path = self.get_backup_path(file_path)
        if os.path.exists(backup_path):
            data = self.read_file(backup_path)
            self.write_file(file_path, data)
            os.remove(backup_path)
    
    def remove_backup(self, file_path: str):
        """
        Remove backup file
        
        Args:
            file_path: Path to file
        """
        backup_path = self.get_backup_path(file_path)
        if os.path.exists(backup_path):
            os.remove(backup_path)
