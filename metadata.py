import struct
import json
from typing import Optional, Dict, Any


class MetadataManager:
    """Manager for encrypted file metadata"""
    
    # Magic header for encrypted file identification
    MAGIC_HEADER = b"ENCRYPTOMATIC\x00\x00\x00"
    METADATA_VERSION = 1
    LENGTH_SIZE = 4
    
    @staticmethod
    def create_metadata(algorithm: str, compression: Optional[str] = None,
                       size_manipulation_mb: int = 0,
                       payload_version: int = 1) -> Dict[str, Any]:
        """
        Create metadata
        
        Args:
            algorithm: Encryption algorithm
            compression: Compression algorithm (if used)
            size_manipulation_mb: Size increase in MB
            payload_version: Encryption payload version
            
        Returns:
            Dictionary with metadata
        """
        return {
            "version": MetadataManager.METADATA_VERSION,
            "algorithm": algorithm.upper(),
            "compression": compression,
            "size_manipulation_mb": size_manipulation_mb,
            "payload_version": payload_version,
        }
    
    @staticmethod
    def pack_metadata(metadata: Dict[str, Any]) -> bytes:
        """
        Pack metadata into binary format
        
        Args:
            metadata: Dictionary with metadata
            
        Returns:
            Bytes with packed metadata
        """
        # Convert to JSON
        json_data = json.dumps(metadata).encode("utf-8")
        
        # Format: MAGIC_HEADER (16 bytes) + JSON length (4 bytes) + JSON
        header = MetadataManager.MAGIC_HEADER
        length = struct.pack(">I", len(json_data))  # Big-endian, 4 bytes
        
        return header + length + json_data
    
    @staticmethod
    def unpack_metadata(data: bytes) -> Optional[Dict[str, Any]]:
        """
        Unpack metadata from binary format
        
        Args:
            data: Bytes with metadata
            
        Returns:
            Dictionary with metadata or None if format is invalid
        """
        header_len = len(MetadataManager.MAGIC_HEADER)
        if len(data) < header_len + MetadataManager.LENGTH_SIZE:
            return None
        
        # Check magic header
        header = data[:header_len]
        if header != MetadataManager.MAGIC_HEADER:
            return None
        
        # Extract JSON length
        length_offset = header_len
        json_length = struct.unpack(">I", data[length_offset:length_offset + MetadataManager.LENGTH_SIZE])[0]
        
        # Extract JSON
        json_offset = length_offset + MetadataManager.LENGTH_SIZE
        if len(data) < json_offset + json_length:
            return None
        
        json_data = data[json_offset:json_offset + json_length]
        
        try:
            return json.loads(json_data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    
    @staticmethod
    def get_metadata_size(data: bytes) -> int:
        """
        Get metadata block size
        
        Args:
            data: Bytes with metadata at the beginning
            
        Returns:
            Metadata block size or 0 if format is invalid
        """
        header_len = len(MetadataManager.MAGIC_HEADER)
        if len(data) < header_len + MetadataManager.LENGTH_SIZE:
            return 0

        if data[:header_len] != MetadataManager.MAGIC_HEADER:
            return 0
        
        length_offset = header_len
        json_length = struct.unpack(">I", data[length_offset:length_offset + MetadataManager.LENGTH_SIZE])[0]
        
        return header_len + MetadataManager.LENGTH_SIZE + json_length
    
    @staticmethod
    def is_encrypted_file(data: bytes) -> bool:
        """
        Check if file is encrypted
        
        Args:
            data: File data
            
        Returns:
            True if file is encrypted
        """
        if len(data) < len(MetadataManager.MAGIC_HEADER):
            return False
        
        return data[:len(MetadataManager.MAGIC_HEADER)] == MetadataManager.MAGIC_HEADER
