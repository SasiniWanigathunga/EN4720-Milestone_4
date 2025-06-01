import json
import time
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, Any, Optional
from dataclasses import dataclass
import threading
import logging

@dataclass
class DetectionEvent:
    """Data class for storing detection events"""
    timestamp: datetime
    event_name: str
    user_role: str
    user_id: str
    source_id: str
    context: Dict[str, Any]
    threat_level: str
    description: str

class AttackDetector:
    """
    Smart Building Cyber-Attack Detection System
    
    This system implements rule-based anomaly detection for smart building systems
    to identify potential cyber-attacks and differentiate them from authorized requests.
    """
    
    def __init__(self):
        # Configuration Constants
        self.MAX_FAILED_LOGINS = 5
        self.LOGIN_WINDOW_MINUTES = 1
        self.MAX_TOGGLE_COMMANDS = 10
        self.TOGGLE_WINDOW_SECONDS = 30
        self.POWER_SPIKE_THRESHOLD = 1.5  # 150% of average
        self.BUSINESS_HOURS_START = 8
        self.BUSINESS_HOURS_END = 18
        self.SUSPICIOUS_COMMAND_THRESHOLD = 5
        self.COMMAND_WINDOW_MINUTES = 5
        self.API_WINDOW_MINUTES = 1
        self.SESSION_TIMEOUT_MINUTES = 30  # Session timeout for hijacking detection
        
        # Data Structures for Tracking
        self.failed_logins = defaultdict(list)
        self.toggle_events = defaultdict(list)
        self.power_readings = defaultdict(list)
        self.active_sessions = defaultdict(set)
        self.command_events = defaultdict(list)
        self.session_tracking = {}  # New: Session hijacking tracking
        
        # Historical averages for power consumption (simulated)
        self.historical_power_averages = {
            "device_001": 100.0,
            "device_002": 75.0,
            "device_003": 120.0,
            "hvac_001": 200.0,
            "lighting_001": 50.0,
            "security_cam_001": 15.0,
            "door_lock_001": 5.0
        }
        
        # Detected threats log
        self.detected_threats = []
        self.lock = threading.Lock()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def instrument(self, event_name: str, user_role: str, user_id: str, 
                  source_id: str, timestamp: Optional[datetime] = None, 
                  context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Main instrumentation function - the entry point for all event monitoring
        
        Args:
            event_name: Type of event (e.g., "login_attempt", "toggle_device")
            user_role: User role ("ADMIN", "MANAGER", "USER")
            user_id: Unique user identifier
            source_id: IP address or device ID
            timestamp: Event timestamp (defaults to now)
            context: Additional context data
            
        Returns:
            bool: True if threat detected, False otherwise
        """
        if timestamp is None:
            timestamp = datetime.now()
        if context is None:
            context = {}
            
        threat_detected = False
        
        with self.lock:
            # Run all detection algorithms
            detections = [
                self._detect_failed_login_attacks(event_name, user_role, user_id, source_id, timestamp, context),
                self._detect_toggle_spam_attacks(event_name, user_role, user_id, source_id, timestamp, context),
                self._detect_power_anomalies(event_name, user_role, user_id, source_id, timestamp, context),
                self._detect_suspicious_command_patterns(event_name, user_role, user_id, source_id, timestamp, context),
                self._detect_session_hijacking(event_name, user_role, user_id, source_id, timestamp, context)
            ]
            
            # Check if any detection triggered
            for detection in detections:
                if detection:
                    threat_detected = True
                    self._log_threat(detection)
        
        return threat_detected
    
    def _detect_failed_login_attacks(self, event_name: str, user_role:str, user_id: str, source_id: str, 
                                   timestamp: datetime, context: Dict[str, Any]) -> Optional[DetectionEvent]:
        """Detect brute force login attacks"""
        if event_name != "login_attempt":
            return None
        
        # check ADMIN or MANAGER roles during business hours
        if self._is_business_hours_admin_activity(timestamp, user_role):
            return None
            
        success = context.get("success", True)
        if not success:
            # Add failed login attempt
            self.failed_logins[source_id].append(timestamp)
            
            # Clean old entries
            cutoff_time = timestamp - timedelta(minutes=self.LOGIN_WINDOW_MINUTES)
            self.failed_logins[source_id] = [
                t for t in self.failed_logins[source_id] if t > cutoff_time
            ]
            
            # Check if threshold exceeded
            if len(self.failed_logins[source_id]) > self.MAX_FAILED_LOGINS:
                return DetectionEvent(
                    timestamp=timestamp,
                    event_name=event_name,
                    user_role="",
                    user_id=user_id,
                    source_id=source_id,
                    context=context,
                    threat_level="HIGH",
                    description=f"Brute force attack detected: {len(self.failed_logins[source_id])} failed logins from {source_id} in {self.LOGIN_WINDOW_MINUTES} minutes"
                )
        
        return None
    
    def _detect_toggle_spam_attacks(self, event_name: str, user_role:str, user_id: str, source_id: str, 
                                  timestamp: datetime, context: Dict[str, Any]) -> Optional[DetectionEvent]:
        """Detect device toggle spam attacks"""
        if event_name not in ["toggle_device", "device_control"]:
            return None
        
        # check ADMIN or MANAGER roles during business hours
        if self._is_business_hours_admin_activity(timestamp, user_role):
            return None
            
        device_id = context.get("device_id", "unknown")
        key = f"{user_id}_{device_id}"
        
        self.toggle_events[key].append(timestamp)
        
        # Clean old entries
        cutoff_time = timestamp - timedelta(seconds=self.TOGGLE_WINDOW_SECONDS)
        self.toggle_events[key] = [
            t for t in self.toggle_events[key] if t > cutoff_time
        ]
        
        # Check if threshold exceeded
        if len(self.toggle_events[key]) > self.MAX_TOGGLE_COMMANDS:
            return DetectionEvent(
                timestamp=timestamp,
                event_name=event_name,
                user_role="",
                user_id=user_id,
                source_id=source_id,
                context=context,
                threat_level="MEDIUM",
                description=f"Device toggle spam detected: {len(self.toggle_events[key])} commands in {self.TOGGLE_WINDOW_SECONDS} seconds for device {device_id}"
            )
        
        return None
    
    def _detect_power_anomalies(self, event_name: str, user_role:str, user_id: str, source_id: str, 
                              timestamp: datetime, context: Dict[str, Any]) -> Optional[DetectionEvent]:
        """Detect abnormal power consumption values"""
        if event_name != "power_reading":
            return None
        
        # check ADMIN or MANAGER roles during business hours
        if self._is_business_hours_admin_activity(timestamp, user_role):
            return None
            
        device_id = context.get("device_id", "unknown")
        power_value = context.get("value", 0)
        
        # Check for invalid values
        if power_value <= 0:
            return DetectionEvent(
                timestamp=timestamp,
                event_name=event_name,
                user_role=user_role,
                user_id=user_id,
                source_id=source_id,
                context=context,
                threat_level="HIGH",
                description=f"Invalid negative or zero power reading: {power_value} for device {device_id}"
            )
        
        # Check against historical average
        historical_avg = self.historical_power_averages.get(device_id, 100.0)
        if power_value > historical_avg * self.POWER_SPIKE_THRESHOLD:
            return DetectionEvent(
                timestamp=timestamp,
                event_name=event_name,
                user_role=user_role,
                user_id=user_id,
                source_id=source_id,
                context=context,
                threat_level="MEDIUM",
                description=f"Power spike detected: {power_value} vs historical average {historical_avg} for device {device_id}"
            )
        
        return None
    
    
    def _detect_suspicious_command_patterns(self, event_name: str, user_role: str, user_id: str, source_id: str, 
                                          timestamp: datetime, context: Dict[str, Any]) -> Optional[DetectionEvent]:
        """Detect suspicious command patterns"""
        if event_name not in ["command_execute", "system_command", "admin_command", "execute_command"]:
            return None
        
        # check ADMIN or MANAGER roles during business hours
        if self._is_business_hours_admin_activity(timestamp, user_role):
            return None
            
        command = context.get("command", "").lower()
        
        # List of suspicious commands read from "suspicious_patterns.json"
        suspicious_patterns_file = "suspicious_patterns.json"
        try:
            with open(suspicious_patterns_file, "r") as f:
                suspicious_patterns = json.load(f).get("suspicious_patterns", [])
        except FileNotFoundError:
            self.logger.error(f"Could not find suspicious patterns file: {suspicious_patterns_file}")
            suspicious_patterns = [
            "rm -rf", "del /s", "format", "shutdown", "reboot", "halt",
            "dd if=", "mkfs", "fdisk", "killall", "pkill",
            "wget", "curl", "nc ", "netcat", "telnet",
            "chmod 777", "chown", "passwd", "useradd", "userdel"
        ]
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern in command:
                return DetectionEvent(
                    timestamp=timestamp,
                    event_name=event_name,
                    user_role=user_role,
                    user_id=user_id,
                    source_id=source_id,
                    context=context,
                    threat_level="CRITICAL",
                    description=f"Suspicious command detected: '{command}' contains pattern '{pattern}'"
                )
        
        # Track command frequency
        key = f"{user_id}_{source_id}"
        self.command_events[key].append(timestamp)
        
        # Clean old entries
        cutoff_time = timestamp - timedelta(minutes=self.COMMAND_WINDOW_MINUTES)
        self.command_events[key] = [
            t for t in self.command_events[key] if t > cutoff_time
        ]
        
        # Check for excessive command execution
        if len(self.command_events[key]) > self.SUSPICIOUS_COMMAND_THRESHOLD:
            return DetectionEvent(
                timestamp=timestamp,
                event_name=event_name,
                user_role=user_role,
                user_id=user_id,
                source_id=source_id,
                context=context,
                threat_level="MEDIUM",
                description=f"Excessive command execution: {len(self.command_events[key])} commands in {self.COMMAND_WINDOW_MINUTES} minutes"
            )
        
        return None
    
    def _detect_session_hijacking(self, event_name: str, user_role: str, user_id: str, source_id: str, 
                                timestamp: datetime, context: Dict[str, Any]) -> Optional[DetectionEvent]:
        """
        Detect potential session hijacking attempts
        
        Session hijacking detection works by tracking:
        1. Session tokens and their associated source IPs
        2. User-Agent strings (browser/client identification)
        3. Timing patterns of session usage
        
        User-Agent examples:
        - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" (Chrome browser)
        - "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)" (iPhone Safari)
        - "curl/7.68.0" (Command line tool - potentially suspicious)
        - "Python-requests/2.25.1" (Python script - potentially suspicious)
        
        Detection triggers when:
        - Same session token used from different IP addresses within timeout window
        - User-Agent string changes unexpectedly (e.g., browser to curl)
        - Rapid location changes (impossible travel time)
        """
        # Only monitor events that use session tokens
        if event_name not in ["login_attempt", "api_call", "api_request", "device_action", 
                              "toggle_device"]:
            return None
        
        # check ADMIN or MANAGER roles during business hours
        if self._is_business_hours_admin_activity(timestamp, user_role):
            return None
        
        session_token = context.get('session_token')
        # User-Agent identifies the client software (browser, app, script, etc.)
        # Examples: "Mozilla/5.0 (Windows...)", "curl/7.68.0", "Python-requests/2.25.1"
        user_agent = context.get('user_agent', 'unknown')

        if not session_token:
            return None
            
        # Track user sessions by session token
        session_key = f"{user_id}_{session_token}"
        
        if session_key not in self.session_tracking:
            # First time seeing this session token - record it
            self.session_tracking[session_key] = {
                'original_source_id': source_id,
                'current_source_id': source_id,
                'user_agent': user_agent,
                'last_activity': timestamp,
                'source_changes': 0,
                'first_seen': timestamp
            }
        else:
            session_info = self.session_tracking[session_key]
            
            # Check if session is being used from a different source
            if session_info['current_source_id'] != source_id:
                # Check if previous session activity was recent (within timeout)
                time_diff = (timestamp - session_info['last_activity']).total_seconds() / 60
                
                if time_diff < self.SESSION_TIMEOUT_MINUTES:
                    # Session is still active but from different source - potential hijacking
                    session_info['source_changes'] += 1
                    
                    # Multiple source changes increase suspicion
                    threat_level = "HIGH" if session_info['source_changes'] > 1 else "MEDIUM"
                    
                    # Additional suspicious indicators
                    user_agent_changed = user_agent != session_info['user_agent']
                    rapid_change = time_diff < 1  # Less than 1 minute since last activity
                    
                    if user_agent_changed or rapid_change:
                        threat_level = "CRITICAL"
                    
                    description = (f"Session hijacking detected: Session token for user {user_id} "
                                 f"used from {session_info['current_source_id']} now being used from {source_id}. "
                                 f"Source changes: {session_info['source_changes']}, "
                                 f"Time since last activity: {time_diff:.1f} minutes")
                    
                    if user_agent_changed:
                        description += f", User-Agent changed from '{session_info['user_agent']}' to '{user_agent}'"
                    
                    # Update tracking info
                    session_info['current_source_id'] = source_id
                    session_info['last_activity'] = timestamp
                    if user_agent_changed:
                        session_info['user_agent'] = user_agent
                    
                    return DetectionEvent(
                        timestamp=timestamp,
                        event_name=event_name,
                        user_role="",
                        user_id=user_id,
                        source_id=source_id,
                        context=context,
                        threat_level=threat_level,
                        description=description
                    )
                else:
                    # Session timeout - legitimate user might have moved to different device
                    session_info['current_source_id'] = source_id
                    session_info['last_activity'] = timestamp
                    session_info['source_changes'] = 0  # Reset counter
                    if user_agent != session_info['user_agent']:
                        session_info['user_agent'] = user_agent
            else:
                # Same source - just update last activity
                session_info['last_activity'] = timestamp
        
        return None
    
    def _is_business_hours_admin_activity(self, timestamp: datetime, user_role: str) -> bool:
        """Check if activity is from admin/manager during business hours"""
        if user_role not in ["ADMIN", "MANAGER"]:
            return False
            
        hour = timestamp.hour
        return self.BUSINESS_HOURS_START <= hour < self.BUSINESS_HOURS_END
    
    def _log_threat(self, detection: DetectionEvent):
        """Log detected threat"""
        self.detected_threats.append(detection)
        self.logger.warning(f"THREAT DETECTED: {detection.description}")
        
        # Also write to file
        try:
            with open("security_alerts.json", "a") as f:
                alert_data = {
                    "timestamp": detection.timestamp.isoformat(),
                    "event_name": detection.event_name,
                    "user_role": detection.user_role,
                    "user_id": detection.user_id,
                    "source_id": detection.source_id,
                    "context": detection.context,
                    "threat_level": detection.threat_level,
                    "description": detection.description
                }
                f.write(json.dumps(alert_data) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write alert to file: {e}")
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats"""
        threat_levels = defaultdict(int)
        threat_types = defaultdict(int)
        
        for threat in self.detected_threats:
            threat_levels[threat.threat_level] += 1
            threat_types[threat.event_name] += 1
        
        return {
            "total_threats": len(self.detected_threats),
            "threat_levels": dict(threat_levels),
            "threat_types": dict(threat_types),
            "recent_threats": [
                {
                    "timestamp": t.timestamp.isoformat(),
                    "description": t.description,
                    "threat_level": t.threat_level
                }
                for t in self.detected_threats[-10:]  # Last 10 threats
            ]
        }