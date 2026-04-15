import hashlib
import getpass
import json
import hmac
import secrets
from pathlib import Path


class PasswordManager:
    """Manager for master password handling"""
    
    def __init__(self, config_file: str = "encryptomatic_config.json"):
        """
        Initialize password manager
        
        Args:
            config_file: Path to configuration file
        """
        self.config_path = Path(config_file)
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using scrypt with random salt.
        
        Args:
            password: Password to hash
            
        Returns:
            JSON string with salt + hash parameters
        """
        password_bytes = password.encode("utf-8")
        salt = secrets.token_bytes(16)
        n = 2**14
        r = 8
        p = 1
        dklen = 32
        digest = hashlib.scrypt(password_bytes, salt=salt, n=n, r=r, p=p, dklen=dklen)
        value = {
            "algo": "scrypt",
            "salt": salt.hex(),
            "n": n,
            "r": r,
            "p": p,
            "dklen": dklen,
            "hash": digest.hex(),
        }
        return json.dumps(value, separators=(",", ":"))

    def _verify_password_hash(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored scrypt descriptor."""
        try:
            data = json.loads(stored_hash)
            if data.get("algo") != "scrypt":
                return False
            salt = bytes.fromhex(data["salt"])
            n = int(data["n"])
            r = int(data["r"])
            p = int(data["p"])
            dklen = int(data["dklen"])
            expected = bytes.fromhex(data["hash"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return False

        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
        )
        return hmac.compare_digest(candidate, expected)
    
    def prompt_password(self) -> str:
        """
        Secure password input (hides input)
        
        Returns:
            Entered password
        """
        return getpass.getpass("Enter master password: ")
    
    def save_password_hash(self, password: str):
        """
        Save password hash to configuration file
        
        Args:
            password: Password to save
        """
        password_hash = self.hash_password(password)
        config = {
            "password_hash": password_hash
        }
        
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config, f)
    
    def load_password_hash(self) -> str:
        """
        Load password hash from configuration file
        
        Returns:
            Password hash or empty string if file doesn't exist
        """
        if not self.config_path.exists():
            return ""
        
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                return config.get("password_hash", "")
        except (json.JSONDecodeError, KeyError):
            return ""
    
    def verify_password(self, password: str) -> bool:
        """
        Verify password
        
        Args:
            password: Password to verify
            
        Returns:
            True if password is correct, otherwise False
        """
        stored_hash = self.load_password_hash()
        if not stored_hash:
            return False

        return self._verify_password_hash(password, stored_hash)
    
    def set_password(self) -> str:
        """
        Set new password with confirmation
        
        Returns:
            Set password
        """
        while True:
            password = getpass.getpass("Enter new master password: ")
            confirm = getpass.getpass("Confirm password: ")
            
            if password == confirm:
                if len(password) < 8:
                    print("Password must contain at least 8 characters!")
                    continue
                self.save_password_hash(password)
                print("Password successfully set!")
                return password
            else:
                print("Passwords do not match! Try again.")
    
    def require_password(self) -> str:
        """
        Require password input with verification
        
        Returns:
            Correct password
            
        Raises:
            ValueError: If password is incorrect
        """
        stored_hash = self.load_password_hash()
        if not stored_hash:
            print("Password is not set yet. Set a new password.")
            return self.set_password()
        
        max_attempts = 3
        for attempt in range(max_attempts):
            password = self.prompt_password()
            if self.verify_password(password):
                return password
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    print(f"Invalid password! Attempts remaining: {remaining}")
                else:
                    raise ValueError("Maximum number of attempts exceeded. Access denied.")
