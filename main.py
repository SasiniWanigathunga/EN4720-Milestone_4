import json
from datetime import datetime, timedelta
from collections import defaultdict

class AttackDetector:
    def __init__(self):
        # Track events by source IP
        self.failed_logins = defaultdict(list)  # IP -> [timestamps]
        self.commands = defaultdict(list)       # IP -> [timestamps]
        self.power_readings = defaultdict(list) # device -> [values]
        self.alerts = []
        
    def instrument(self, event_name, user_role, user_id, source_ip, timestamp, context):
        """Main function called from smart home system"""
        
        # Check for attacks
        if event_name == "login_attempt":
            self._check_login_attack(source_ip, timestamp, context)
            
        elif event_name == "toggle_device":
            self._check_command_spam(source_ip, user_role, timestamp)
            
        elif event_name == "power_reading":
            self._check_power_anomaly(context, timestamp)
            
        # Log all events
        self._log_event(event_name, user_role, user_id, source_ip, timestamp, context)
    
    def _check_login_attack(self, source_ip, timestamp, context):
        """Detect too many failed logins"""
        if not context.get('success', True):  # Failed login
            self.failed_logins[source_ip].append(timestamp)
            
            # Remove old attempts (older than 1 minute)
            cutoff = timestamp - timedelta(minutes=1)
            self.failed_logins[source_ip] = [t for t in self.failed_logins[source_ip] if t > cutoff]
            
            # Check if too many failures
            if len(self.failed_logins[source_ip]) >= 5:
                self._create_alert("BRUTE_FORCE_LOGIN", source_ip, timestamp)
    
    def _check_command_spam(self, source_ip, user_role, timestamp):
        """Detect too many device commands"""
        # Skip check for admins during business hours (9 AM - 5 PM)
        if user_role == "ADMIN" and 9 <= timestamp.hour <= 17:
            return
            
        self.commands[source_ip].append(timestamp)
        
        # Remove old commands (older than 30 seconds)
        cutoff = timestamp - timedelta(seconds=30)
        self.commands[source_ip] = [t for t in self.commands[source_ip] if t > cutoff]
        
        # Check if too many commands
        if len(self.commands[source_ip]) >= 10:
            self._create_alert("COMMAND_SPAM", source_ip, timestamp)
    
    def _check_power_anomaly(self, context, timestamp):
        """Detect abnormal power readings"""
        device_id = context.get('device_id', 'unknown')
        power_value = context.get('value', 0)
        
        # Check for invalid values
        if power_value < 0:
            self._create_alert("NEGATIVE_POWER", device_id, timestamp)
            return
            
        # Track power readings for this device
        self.power_readings[device_id].append(power_value)
        
        # Need at least 10 readings to detect spikes
        if len(self.power_readings[device_id]) >= 10:
            # Calculate average of previous readings
            previous_readings = self.power_readings[device_id][:-1]
            average = sum(previous_readings) / len(previous_readings)
            
            # Check if current reading is 150% higher than average
            if average > 0 and power_value > average * 1.5:
                self._create_alert("POWER_SPIKE", device_id, timestamp)
    
    def _create_alert(self, attack_type, source, timestamp):
        """Create and log security alert"""
        alert = {
            'attack_type': attack_type,
            'source': source,
            'timestamp': timestamp.isoformat(),
            'message': f"Attack detected: {attack_type} from {source}"
        }
        self.alerts.append(alert)
        print(f"🚨 ALERT: {alert['message']}")
    
    def _log_event(self, event_name, user_role, user_id, source_ip, timestamp, context):
        """Log all events to file"""
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'event': event_name,
            'user_role': user_role,
            'user_id': user_id,
            'source_ip': source_ip,
            'context': context
        }
        
        # Write to log file
        with open('security_log.json', 'a') as f:
            json.dump(log_entry, f)
            f.write('\n')
    
    def get_alerts(self):
        """Return all alerts"""
        return self.alerts
    
    def get_summary(self):
        """Get summary of attacks detected"""
        attack_counts = defaultdict(int)
        for alert in self.alerts:
            attack_counts[alert['attack_type']] += 1
        return dict(attack_counts)


# Test the attack detector
def test_attack_detector():
    detector = AttackDetector()
    print("Testing Smart Home Attack Detector")
    print("=" * 40)
    
    now = datetime.now()
    
    # Test 1: Normal activity (no alerts)
    print("\n1. Testing normal activity...")
    detector.instrument("login_attempt", "USER", "john", "192.168.1.100", now, {"success": True})
    detector.instrument("toggle_device", "USER", "john", "192.168.1.100", now, {"device": "light1"})
    detector.instrument("power_reading", "SYSTEM", "meter", "192.168.1.50", now, 
                       {"device_id": "meter1", "value": 45.2})
    print("✅ Normal activity - no alerts")
    
    # Test 2: Failed login attack
    print("\n2. Testing brute force login...")
    bad_ip = "10.0.0.999"
    for i in range(6):  # 6 failed attempts
        detector.instrument("login_attempt", "USER", "hacker", bad_ip, 
                           now + timedelta(seconds=i*5), {"success": False})
    
    # Test 3: Command spam attack
    print("\n3. Testing command spam...")
    spam_ip = "192.168.1.200"
    for i in range(12):  # 12 rapid commands
        detector.instrument("toggle_device", "USER", "spammer", spam_ip,
                           now + timedelta(seconds=i*2), {"device": "light2"})
    
    # Test 4: Power anomaly
    print("\n4. Testing power anomaly...")
    # First establish normal readings
    for i, reading in enumerate([50, 52, 48, 51, 49, 53, 47, 52, 50, 51]):
        detector.instrument("power_reading", "SYSTEM", "sensor", "192.168.1.10",
                           now + timedelta(minutes=1, seconds=i*5),
                           {"device_id": "hvac1", "value": reading})
    
    # Then send spike
    detector.instrument("power_reading", "SYSTEM", "sensor", "192.168.1.10",
                       now + timedelta(minutes=2),
                       {"device_id": "hvac1", "value": 120})  # Much higher than ~50 average
    
    # Test negative power
    detector.instrument("power_reading", "SYSTEM", "sensor", "192.168.1.10",
                       now + timedelta(minutes=3),
                       {"device_id": "hvac1", "value": -10})
    
    # Test 5: Admin bypass (should not alert)
    print("\n5. Testing admin bypass...")
    admin_time = now.replace(hour=14)  # 2 PM (business hours)
    for i in range(12):
        detector.instrument("toggle_device", "ADMIN", "admin", "192.168.1.5",
                           admin_time + timedelta(seconds=i), {"device": "emergency"})
    print("✅ Admin commands during business hours - no alerts expected")
    
    # Show results
    print("\n" + "=" * 40)
    print("DETECTION RESULTS:")
    print("=" * 40)
    
    alerts = detector.get_alerts()
    if alerts:
        for alert in alerts:
            print(f"• {alert['attack_type']}: {alert['source']} at {alert['timestamp']}")
    else:
        print("No attacks detected")
    
    print(f"\nTotal alerts: {len(alerts)}")
    
    summary = detector.get_summary()
    if summary:
        print("\nAttack types detected:")
        for attack_type, count in summary.items():
            print(f"  {attack_type}: {count} times")
    
    print(f"\nLogs saved to: security_log.json")

if __name__ == "__main__":
    test_attack_detector()