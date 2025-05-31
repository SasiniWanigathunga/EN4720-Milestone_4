import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import threading

class UserRole(Enum):
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    USER = "USER"

class AlertLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class SecurityEvent:
    timestamp: str
    event_name: str
    user_role: str
    user_id: str
    source_id: str
    context: Dict[str, Any]
    alert_level: Optional[str] = None
    attack_type: Optional[str] = None
    flagged: bool = False

class AttackDetector:
    def __init__(self):
        # Time-based tracking for rate limiting
        self.login_attempts = defaultdict(deque)  # source_id -> timestamps
        self.command_history = defaultdict(deque)  # source_id -> timestamps
        self.power_readings = defaultdict(list)   # source_id -> readings
        self.session_tracking = defaultdict(dict) # user_id -> session info
        self.geolocation_history = defaultdict(deque)  # user_id -> locations
        
        # Configuration thresholds
        self.config = {
            'failed_login_threshold': 5,
            'failed_login_window': 60,  # seconds
            'command_spam_threshold': 10,
            'command_spam_window': 30,  # seconds
            'power_spike_multiplier': 1.5,  # 150% of average
            'suspicious_location_threshold': 3,  # different locations
            'session_timeout': 1800,  # 30 minutes
            'business_hours': (9, 17),  # 9 AM to 5 PM
        }
        
        # Historical data for anomaly detection
        self.power_baselines = defaultdict(list)  # device_id -> historical readings
        self.user_patterns = defaultdict(dict)    # user_id -> behavioral patterns
        
        # Alert storage
        self.security_events = []
        self.active_alerts = defaultdict(list)
        
        # Thread lock for concurrent access
        self.lock = threading.Lock()
        
    def instrument(self, event_name: str, user_role: str, user_id: str, 
                  source_id: str, timestamp: datetime, context: Dict[str, Any]):
        """
        Main instrumentation function - called at hot spots in the smart building system
        """
        with self.lock:
            # Create security event
            event = SecurityEvent(
                timestamp=timestamp.isoformat(),
                event_name=event_name,
                user_role=user_role,
                user_id=user_id,
                source_id=source_id,
                context=context
            )
            
            # Run detection algorithms
            self._detect_failed_login_attacks(event, timestamp)
            self._detect_command_spam_attacks(event, timestamp)
            self._detect_power_anomalies(event, timestamp)
            self._detect_session_hijacking(event, timestamp)
            self._detect_geolocation_anomalies(event, timestamp)
            
            # Log the event
            self._log_event(event)
            
            return event.flagged
    
    def _detect_failed_login_attacks(self, event: SecurityEvent, timestamp: datetime):
        """Detect multiple failed login attempts from same source"""
        if event.event_name != "login_attempt":
            return
            
        source_id = event.source_id
        success = event.context.get('success', True)
        
        # Track failed attempts
        if not success:
            self.login_attempts[source_id].append(timestamp)
            
            # Clean old attempts outside window
            cutoff = timestamp - timedelta(seconds=self.config['failed_login_window'])
            while (self.login_attempts[source_id] and 
                   self.login_attempts[source_id][0] < cutoff):
                self.login_attempts[source_id].popleft()
            
            # Check threshold
            if len(self.login_attempts[source_id]) >= self.config['failed_login_threshold']:
                self._flag_attack(event, "BRUTE_FORCE_LOGIN", AlertLevel.HIGH)
        else:
            # Clear failed attempts on successful login
            if source_id in self.login_attempts:
                self.login_attempts[source_id].clear()
    
    def _detect_command_spam_attacks(self, event: SecurityEvent, timestamp: datetime):
        """Detect abnormal frequency of control commands"""
        if event.event_name not in ["toggle_device", "control_command", "device_action"]:
            return
            
        source_id = event.source_id
        user_role = UserRole(event.user_role)
        
        # Skip if admin/manager during business hours
        if (user_role in [UserRole.ADMIN, UserRole.MANAGER] and 
            self._is_business_hours(timestamp)):
            return
            
        self.command_history[source_id].append(timestamp)
        
        # Clean old commands outside window
        cutoff = timestamp - timedelta(seconds=self.config['command_spam_window'])
        while (self.command_history[source_id] and 
               self.command_history[source_id][0] < cutoff):
            self.command_history[source_id].popleft()
        
        # Check threshold
        if len(self.command_history[source_id]) >= self.config['command_spam_threshold']:
            self._flag_attack(event, "COMMAND_SPAM", AlertLevel.MEDIUM)
    
    def _detect_power_anomalies(self, event: SecurityEvent, timestamp: datetime):
        """Detect abnormal power consumption values"""
        if event.event_name != "power_reading":
            return
            
        device_id = event.context.get('device_id', event.source_id)
        power_value = event.context.get('value', 0)
        
        # Check for invalid values
        if power_value < 0:
            self._flag_attack(event, "INVALID_POWER_READING", AlertLevel.HIGH)
            return
        
        if power_value == 0 and event.context.get('device_type') not in ['switch', 'sensor']:
            self._flag_attack(event, "SUSPICIOUS_ZERO_POWER", AlertLevel.MEDIUM)
            return
            
        # Track historical readings
        self.power_baselines[device_id].append(power_value)
        
        # Keep only last 100 readings for baseline
        if len(self.power_baselines[device_id]) > 100:
            self.power_baselines[device_id] = self.power_baselines[device_id][-100:]
        
        # Check for power spikes (need at least 10 readings for baseline)
        if len(self.power_baselines[device_id]) >= 10:
            avg_power = statistics.mean(self.power_baselines[device_id][:-1])  # Exclude current reading
            if avg_power > 0 and power_value > avg_power * self.config['power_spike_multiplier']:
                self._flag_attack(event, "POWER_SPIKE_ANOMALY", AlertLevel.MEDIUM)
    
    def _detect_session_hijacking(self, event: SecurityEvent, timestamp: datetime):
        """Detect potential session hijacking attempts"""
        if event.event_name not in ["login_attempt", "api_request", "device_action"]:
            return
            
        user_id = event.user_id
        source_id = event.source_id
        session_token = event.context.get('session_token')
        
        if not session_token:
            return
            
        # Track user sessions
        if user_id not in self.session_tracking:
            self.session_tracking[user_id] = {
                'source_id': source_id,
                'session_token': session_token,
                'last_activity': timestamp
            }
        else:
            session_info = self.session_tracking[user_id]
            
            # Check for session from different source
            if (session_info['session_token'] == session_token and 
                session_info['source_id'] != source_id):
                
                # Check if previous session is still active
                time_diff = (timestamp - session_info['last_activity']).total_seconds()
                if time_diff < self.config['session_timeout']:
                    self._flag_attack(event, "SESSION_HIJACKING", AlertLevel.CRITICAL)
            
            # Update session info
            session_info['source_id'] = source_id
            session_info['last_activity'] = timestamp
    
    def _detect_geolocation_anomalies(self, event: SecurityEvent, timestamp: datetime):
        """Detect impossible travel or suspicious location changes"""
        if event.event_name != "login_attempt" or not event.context.get('success', False):
            return
            
        user_id = event.user_id
        location = event.context.get('location')  # Expected format: {"lat": x, "lon": y}
        
        if not location:
            return
            
        self.geolocation_history[user_id].append({
            'timestamp': timestamp,
            'location': location,
            'source_id': event.source_id
        })
        
        # Keep only last 10 locations
        if len(self.geolocation_history[user_id]) > 10:
            self.geolocation_history[user_id].popleft()
        
        # Check for multiple locations in short time
        recent_locations = []
        cutoff = timestamp - timedelta(hours=1)
        
        for entry in self.geolocation_history[user_id]:
            if entry['timestamp'] > cutoff:
                loc_key = f"{entry['location']['lat']:.2f},{entry['location']['lon']:.2f}"
                if loc_key not in recent_locations:
                    recent_locations.append(loc_key)
        
        if len(recent_locations) >= self.config['suspicious_location_threshold']:
            self._flag_attack(event, "GEOLOCATION_ANOMALY", AlertLevel.HIGH)
    
    def _is_business_hours(self, timestamp: datetime) -> bool:
        """Check if timestamp falls within business hours"""
        hour = timestamp.hour
        return self.config['business_hours'][0] <= hour <= self.config['business_hours'][1]
    
    def _flag_attack(self, event: SecurityEvent, attack_type: str, alert_level: AlertLevel):
        """Flag an event as a potential attack"""
        event.flagged = True
        event.attack_type = attack_type
        event.alert_level = alert_level.value
        
        # Add to active alerts
        self.active_alerts[attack_type].append({
            'timestamp': event.timestamp,
            'user_id': event.user_id,
            'source_id': event.source_id,
            'alert_level': alert_level.value
        })
        
        print(f"🚨 ATTACK DETECTED: {attack_type} - Level: {alert_level.value}")
        print(f"   User: {event.user_id}, Source: {event.source_id}")
        print(f"   Event: {event.event_name}, Time: {event.timestamp}")
    
    def _log_event(self, event: SecurityEvent):
        """Log security event to storage"""
        self.security_events.append(event)
        
        # Also write to JSON file for persistence
        log_entry = asdict(event)
        try:
            with open('security_log.json', 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')
        except Exception as e:
            print(f"Failed to write to log file: {e}")
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get summary of security events and alerts"""
        total_events = len(self.security_events)
        flagged_events = sum(1 for event in self.security_events if event.flagged)
        
        attack_types = defaultdict(int)
        for event in self.security_events:
            if event.flagged and event.attack_type:
                attack_types[event.attack_type] += 1
        
        return {
            'total_events': total_events,
            'flagged_events': flagged_events,
            'attack_types': dict(attack_types),
            'active_alerts': len(self.active_alerts)
        }


# Test Harness and Demonstration
def run_comprehensive_tests():
    """Comprehensive test suite demonstrating attack detection"""
    detector = AttackDetector()
    print("🏠 Smart Home Cyber-Attack Detection System - Test Suite")
    print("=" * 60)
    
    current_time = datetime.now()
    
    # Test 1: Normal Operations (should NOT trigger alerts)
    print("\n📋 Test 1: Normal Operations")
    print("-" * 30)
    
    # Normal user login
    detector.instrument("login_attempt", "USER", "user123", "192.168.1.100", 
                       current_time, {"success": True, "location": {"lat": 40.7128, "lon": -74.0060}})
    
    # Normal device toggles
    for i in range(3):
        detector.instrument("toggle_device", "USER", "user123", "192.168.1.100",
                           current_time + timedelta(seconds=i*10), 
                           {"device_id": "light_01", "action": "toggle"})
    
    # Normal power readings
    for reading in [45.2, 47.1, 46.8, 48.0]:
        detector.instrument("power_reading", "ADMIN", "admin001", "192.168.1.50",
                           current_time + timedelta(minutes=1), 
                           {"device_id": "hvac_01", "value": reading, "device_type": "hvac"})
    
    print("✅ Normal operations completed - No alerts expected")
    
    # Test 2: Brute Force Login Attack
    print("\n📋 Test 2: Brute Force Login Attack")
    print("-" * 30)
    
    # Simulate 6 failed login attempts within 1 minute
    attacker_ip = "10.0.0.999"
    for i in range(6):
        detector.instrument("login_attempt", "USER", "unknown", attacker_ip,
                           current_time + timedelta(seconds=i*8), 
                           {"success": False, "reason": "invalid_password"})
    
    # Test 3: Command Spam Attack
    print("\n📋 Test 3: Command Spam Attack")
    print("-" * 30)
    
    # Simulate 12 rapid device toggles in 25 seconds
    spam_time = current_time + timedelta(minutes=2)
    for i in range(12):
        detector.instrument("toggle_device", "USER", "user456", "192.168.1.200",
                           spam_time + timedelta(seconds=i*2), 
                           {"device_id": "light_02", "action": "toggle"})
    
    # Test 4: Power Anomaly Detection
    print("\n📋 Test 4: Power Anomaly Detection")
    print("-" * 30)
    
    # Establish baseline first
    baseline_readings = [50.0, 52.1, 49.8, 51.2, 50.5, 51.8, 49.9, 52.0, 50.3, 51.1]
    for i, reading in enumerate(baseline_readings):
        detector.instrument("power_reading", "SYSTEM", "sensor", "192.168.1.10",
                           current_time + timedelta(minutes=3, seconds=i*5), 
                           {"device_id": "main_meter", "value": reading, "device_type": "meter"})
    
    # Now send anomalous readings
    # Power spike (>150% of average ~50.8)
    detector.instrument("power_reading", "SYSTEM", "sensor", "192.168.1.10",
                       current_time + timedelta(minutes=4), 
                       {"device_id": "main_meter", "value": 85.0, "device_type": "meter"})
    
    # Invalid negative reading
    detector.instrument("power_reading", "SYSTEM", "sensor", "192.168.1.10",
                       current_time + timedelta(minutes=4, seconds=10), 
                       {"device_id": "main_meter", "value": -10.0, "device_type": "meter"})
    
    # Test 5: Session Hijacking Detection
    print("\n📋 Test 5: Session Hijacking Detection")
    print("-" * 30)
    
    session_token = "abc123xyz789"
    base_time = current_time + timedelta(minutes=5)
    
    # User logs in from first location
    detector.instrument("login_attempt", "USER", "user789", "192.168.1.150",
                       base_time, 
                       {"success": True, "session_token": session_token})
    
    # Same session used from different IP shortly after
    detector.instrument("api_request", "USER", "user789", "203.0.113.5",
                       base_time + timedelta(seconds=30), 
                       {"session_token": session_token, "action": "get_devices"})
    
    # Test 6: Geolocation Anomaly Detection
    print("\n📋 Test 6: Geolocation Anomaly Detection")  
    print("-" * 30)
    
    # User logging in from multiple distant locations rapidly
    locations = [
        {"lat": 40.7128, "lon": -74.0060},  # New York
        {"lat": 34.0522, "lon": -118.2437}, # Los Angeles  
        {"lat": 41.8781, "lon": -87.6298},  # Chicago
        {"lat": 29.7604, "lon": -95.3698}   # Houston
    ]
    
    geo_time = current_time + timedelta(minutes=6)
    for i, location in enumerate(locations):
        detector.instrument("login_attempt", "USER", "user999", f"IP_{i}",
                           geo_time + timedelta(minutes=i*5), 
                           {"success": True, "location": location})
    
    # Test 7: Admin Bypass (should NOT trigger during business hours)
    print("\n📋 Test 7: Admin Bypass Test")
    print("-" * 30)
    
    # Simulate business hours (assume current time is business hours)
    business_time = current_time.replace(hour=14)  # 2 PM
    
    # Admin rapid commands should not trigger alert
    for i in range(12):
        detector.instrument("toggle_device", "ADMIN", "admin001", "192.168.1.5",
                           business_time + timedelta(seconds=i), 
                           {"device_id": "emergency_lights", "action": "toggle"})
    
    print("✅ Admin commands during business hours - Should not trigger alerts")
    
    # Generate Summary Report
    print("\n📊 SECURITY SUMMARY REPORT")
    print("=" * 60)
    
    summary = detector.get_security_summary()
    print(f"Total Events Processed: {summary['total_events']}")
    print(f"Flagged as Suspicious: {summary['flagged_events']}")
    print(f"Active Alert Categories: {summary['active_alerts']}")
    
    if summary['attack_types']:
        print("\nDetected Attack Types:")
        for attack_type, count in summary['attack_types'].items():
            print(f"  • {attack_type}: {count} incidents")
    
    print(f"\n📝 Detailed logs written to: security_log.json")
    
    # Show some recent flagged events
    print("\n🚨 Recent Security Incidents:")
    flagged_events = [e for e in detector.security_events if e.flagged][-5:]
    for event in flagged_events:
        print(f"  • {event.attack_type} - {event.user_id} from {event.source_id}")
        print(f"    Time: {event.timestamp}, Level: {event.alert_level}")

if __name__ == "__main__":
    run_comprehensive_tests()