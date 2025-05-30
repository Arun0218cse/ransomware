import smtplib
import os
import ctypes
import winsound
import platform
import socket
import psutil
from email.message import EmailMessage
from win10toast import ToastNotifier
from typing import Dict, Any, Optional

# Load email credentials securely with fallback
EMAIL_ADDRESS = os.getenv("ALERT_EMAIL", "your_email@example.com")
EMAIL_PASSWORD = os.getenv("ALERT_PASSWORD", "your_password")

def send_email_alert(subject: str, message: str, recipient: str = "admin@example.com") -> bool:
    """
    Sends an email alert in case of ransomware detection
    
    Args:
        subject: Email subject line
        message: Email body content
        recipient: Recipient email address
        
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("❌ Email credentials missing! Set ALERT_EMAIL and ALERT_PASSWORD.")
        return False

    try:
        email_msg = EmailMessage()
        email_msg.set_content(message)
        email_msg["Subject"] = subject
        email_msg["From"] = EMAIL_ADDRESS
        email_msg["To"] = recipient

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(email_msg)

        print("📧 Email alert sent successfully.")
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

def show_notification(title: str, message: str, duration: int = 10) -> None:
    """
    Displays a Windows Toast Notification
    
    Args:
        title: Notification title
        message: Notification message
        duration: How long to show the notification (seconds)
    """
    try:
        toaster = ToastNotifier()
        toaster.show_toast(title, message, duration=duration)
    except Exception as e:
        print(f"❌ Notification error: {e}")

def play_alert_sound(sound_type: str = "system") -> None:
    """
    Plays an alert sound
    
    Args:
        sound_type: Type of sound to play ('system', 'beep', or 'custom')
    """
    try:
        if platform.system() == "Windows":
            if sound_type == "system":
                winsound.PlaySound("SystemHand", winsound.SND_ASYNC)
            elif sound_type == "beep":
                winsound.Beep(1000, 500)  # Frequency, Duration
        else:
            # Mac/Linux alternative
            if sound_type == "beep":
                os.system('play -nq -t alsa synth 0.5 sine 1000')
            else:
                os.system('play -nq -t alsa synth 1 sine 800 vol 0.5')
    except Exception as e:
        print(f"❌ Could not play alert sound: {e}")

def is_admin() -> bool:
    """Check if the program is running with admin privileges"""
    try:
        return os.getuid() == 0  # Unix/Linux
    except AttributeError:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows
        except:
            return False

def get_system_info() -> Dict[str, Any]:
    """Gather basic system information"""
    try:
        info = {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_cores": os.cpu_count(),
            "memory": psutil.virtual_memory().total if hasattr(psutil, 'virtual_memory') else None,
            "disk_usage": {d.mountpoint: psutil.disk_usage(d.mountpoint).percent 
                          for d in psutil.disk_partitions()} if hasattr(psutil, 'disk_partitions') else {}
        }
        return info
    except Exception as e:
        print(f"❌ Could not gather system info: {e}")
        return {}

def check_internet_connection(timeout: float = 5.0) -> bool:
    """
    Check if there's an active internet connection
    
    Args:
        timeout: Timeout in seconds
        
    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        host = "8.8.8.8"  # Google DNS
        port = 53  # DNS port
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except (socket.gaierror, socket.timeout, ConnectionError):
        return False
    except Exception as e:
        print(f"❌ Internet check error: {e}")
        return False

def secure_delete(filepath: str, passes: int = 3) -> bool:
    """
    Securely delete a file by overwriting it before deletion
    
    Args:
        filepath: Path to file to delete
        passes: Number of overwrite passes
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not os.path.exists(filepath):
            return False
            
        length = os.path.getsize(filepath)
        with open(filepath, "ba+") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
        os.remove(filepath)
        return True
    except Exception as e:
        print(f"❌ Secure delete failed: {e}")
        return False