import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional


class DecryptionTimer:
    """Manager for automatic decryption timer"""
    
    def __init__(self, timer_file: str = "encryptomatic_timers.json"):
        """
        Initialize timer manager
        
        Args:
            timer_file: Path to timer file
        """
        self.timer_path = Path(timer_file)
    
    def save_timer(self, file_path: str, duration_minutes: int):
        """
        Save timer for file
        
        Args:
            file_path: Path to encrypted file
            duration_minutes: Encryption duration in minutes
        """
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        timers = self.load_timers()
        timers[file_path] = {
            "end_time": end_time.isoformat(),
            "duration_minutes": duration_minutes
        }
        
        with open(self.timer_path, "w", encoding="utf-8") as f:
            json.dump(timers, f, indent=2)
    
    def load_timers(self) -> Dict[str, dict]:
        """
        Load all timers
        
        Returns:
            Dictionary with timers
        """
        if not self.timer_path.exists():
            return {}
        
        try:
            with open(self.timer_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def is_timer_expired(self, file_path: str) -> bool:
        """
        Check if timer has expired for file
        
        Args:
            file_path: Path to file
            
        Returns:
            True if timer expired or doesn't exist
        """
        timers = self.load_timers()
        if file_path not in timers:
            return True
        
        end_time_str = timers[file_path]["end_time"]
        end_time = datetime.fromisoformat(end_time_str)
        
        return datetime.now() >= end_time
    
    def get_remaining_time(self, file_path: str) -> Optional[timedelta]:
        """
        Get remaining time until decryption
        
        Args:
            file_path: Path to file
            
        Returns:
            Remaining time or None if timer doesn't exist
        """
        timers = self.load_timers()
        if file_path not in timers:
            return None
        
        end_time_str = timers[file_path]["end_time"]
        end_time = datetime.fromisoformat(end_time_str)
        remaining = end_time - datetime.now()
        
        return remaining if remaining.total_seconds() > 0 else timedelta(0)
    
    def remove_timer(self, file_path: str):
        """
        Remove timer for file
        
        Args:
            file_path: Path to file
        """
        timers = self.load_timers()
        if file_path in timers:
            del timers[file_path]
            with open(self.timer_path, "w", encoding="utf-8") as f:
                json.dump(timers, f, indent=2)
    
    def check_all_timers(self) -> List[str]:
        """
        Check all timers and return list of files with expired timers
        
        Returns:
            List of paths to files with expired timers
        """
        timers = self.load_timers()
        expired_files = []
        
        for file_path in timers:
            if self.is_timer_expired(file_path):
                expired_files.append(file_path)
        
        return expired_files
