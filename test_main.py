import unittest
from unittest.mock import patch, mock_open
from datetime import datetime, timedelta
import os
import json
import builtins

from main import AttackDetector, DetectionEvent


class TestAttackDetector(unittest.TestCase):

    def setUp(self):
        """Set up for test methods."""
        self.detector = AttackDetector()
        self.detector.detected_threats = []

        self.suspicious_patterns_path = "suspicious_patterns.json"
        self.backup_suspicious_patterns_path = self.suspicious_patterns_path + ".unittest_bak"
        self.original_patterns_file_backed_up = False

        if os.path.exists(self.suspicious_patterns_path):
            os.rename(self.suspicious_patterns_path,
                      self.backup_suspicious_patterns_path)
            self.original_patterns_file_backed_up = True

        with open(self.suspicious_patterns_path, "w") as f:
            json.dump({"suspicious_patterns": ["test_suspicious_cmd"]}, f)

    def tearDown(self):
        """Clean up after test methods."""
        if os.path.exists("security_alerts.json"):
            os.remove("security_alerts.json")

        if os.path.exists(self.suspicious_patterns_path):
            os.remove(self.suspicious_patterns_path)

        if self.original_patterns_file_backed_up:
            if os.path.exists(self.backup_suspicious_patterns_path):
                os.rename(self.backup_suspicious_patterns_path,
                          self.suspicious_patterns_path)
            self.original_patterns_file_backed_up = False

    def test_instrument_with_none_context(self):
        """Test instrument method when context is None."""
        threat_detected = self.detector.instrument(
            event_name="some_event",
            user_role="USER",
            user_id="test_user_ctx",
            source_id="source_ctx",
            context=None
        )
        self.assertFalse(threat_detected)

    def test_failed_login_attacks_brute_force(self):
        """Test brute force login attack detection."""
        source_id = "192.168.1.100"
        user_id = "test_user"
        for i in range(self.detector.MAX_FAILED_LOGINS + 1):
            self.detector.instrument(
                event_name="login_attempt",
                user_role="USER",
                user_id=user_id,
                source_id=source_id,
                context={"success": False}
            )
        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "HIGH")
        self.assertIn("Brute force attack detected",
                      self.detector.detected_threats[0].description)

    def test_failed_login_attacks_no_brute_force(self):
        """Test no brute force when logins are spaced out."""
        source_id = "192.168.1.101"
        user_id = "test_user_2"
        for i in range(self.detector.MAX_FAILED_LOGINS):
            self.detector.instrument(
                event_name="login_attempt",
                user_role="USER",
                user_id=user_id,
                source_id=source_id,
                timestamp=datetime.now() - timedelta(minutes=(self.detector.LOGIN_WINDOW_MINUTES + 1) * i),
                context={"success": False}
            )
        self.assertEqual(len(self.detector.detected_threats), 0)

    def test_failed_login_attacks_admin_business_hours(self):
        """Test admin failed logins during business hours (should not trigger)."""
        source_id = "192.168.1.102"
        user_id = "admin_user"
        business_hour_time = datetime.now().replace(
            hour=self.detector.BUSINESS_HOURS_START + 1)
        for i in range(self.detector.MAX_FAILED_LOGINS + 1):
            self.detector.instrument(
                event_name="login_attempt",
                user_role="ADMIN",
                user_id=user_id,
                source_id=source_id,
                timestamp=business_hour_time,
                context={"success": False}
            )
        self.assertEqual(len(self.detector.detected_threats), 0)

    def test_toggle_spam_attacks(self):
        """Test device toggle spam attack detection."""
        user_id = "spammer"
        device_id = "light_001"
        for i in range(self.detector.MAX_TOGGLE_COMMANDS + 1):
            self.detector.instrument(
                event_name="toggle_device",
                user_role="USER",
                user_id=user_id,
                source_id="10.0.0.1",
                context={"device_id": device_id}
            )
        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "MEDIUM")
        self.assertIn("Device toggle spam detected",
                      self.detector.detected_threats[0].description)

    def test_toggle_spam_attacks_admin_business_hours(self):
        """Test admin toggle spam during business hours (should not trigger)."""
        user_id = "admin_spammer"
        device_id = "light_002"
        business_hour_time = datetime.now().replace(
            hour=self.detector.BUSINESS_HOURS_START + 1)
        for i in range(self.detector.MAX_TOGGLE_COMMANDS + 1):
            self.detector.instrument(
                event_name="toggle_device",
                user_role="ADMIN",
                user_id=user_id,
                source_id="10.0.0.2",
                timestamp=business_hour_time,
                context={"device_id": device_id}
            )
        self.assertEqual(len(self.detector.detected_threats), 0)

    def test_power_anomalies_spike(self):
        """Test power spike anomaly detection."""
        device_id = "device_001"
        historical_avg = self.detector.historical_power_averages[device_id]
        spike_value = historical_avg * \
            (self.detector.POWER_SPIKE_THRESHOLD + 0.1)

        self.detector.instrument(
            event_name="power_reading",
            user_role="SYSTEM",
            user_id="sensor_monitor",
            source_id="sensor_cluster_A",
            context={"device_id": device_id, "value": spike_value}
        )
        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "MEDIUM")
        self.assertIn("Power spike detected",
                      self.detector.detected_threats[0].description)

    def test_power_anomalies_invalid_value(self):
        """Test invalid (negative) power reading."""
        device_id = "device_002"
        self.detector.instrument(
            event_name="power_reading",
            user_role="SYSTEM",
            user_id="sensor_monitor",
            source_id="sensor_cluster_B",
            context={"device_id": device_id, "value": -100}
        )
        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "HIGH")
        self.assertIn("Invalid negative or zero power reading",
                      self.detector.detected_threats[0].description)

    def test_power_anomalies_admin_business_hours(self):
        """Test power anomaly by admin during business hours (should not trigger)."""
        device_id = "device_003"
        historical_avg = self.detector.historical_power_averages[device_id]
        spike_value = historical_avg * \
            (self.detector.POWER_SPIKE_THRESHOLD + 0.1)
        business_hour_time = datetime.now().replace(
            hour=self.detector.BUSINESS_HOURS_START + 1)

        self.detector.instrument(
            event_name="power_reading",
            user_role="ADMIN",
            user_id="admin_sensor_check",
            source_id="admin_console",
            timestamp=business_hour_time,
            context={"device_id": device_id, "value": spike_value}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

    def test_normal_power_reading(self):
        """Test normal power reading (should not trigger any threat)."""
        device_id = "device_003"
        historical_avg = self.detector.historical_power_averages[device_id]
        normal_value = historical_avg * 0.9
        self.detector.instrument(
            event_name="power_reading",
            user_role="SYSTEM",
            user_id="sensor_monitor_normal",
            source_id="sensor_cluster_C",
            context={"device_id": device_id, "value": normal_value}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

    def test_suspicious_command_patterns_direct_hit(self):
        """Test detection of a known suspicious command."""
        suspicious_command_str = "some_user_command test_suspicious_cmd --option"
        expected_pattern = "test_suspicious_cmd"

        self.detector.instrument(
            event_name="command_execute",
            user_role="USER",
            user_id="hacker_user",
            source_id="compromised_server",
            context={"command": suspicious_command_str}
        )
        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "CRITICAL")
        self.assertIn(
            f"Suspicious command detected: '{suspicious_command_str}' contains pattern '{expected_pattern}'", self.detector.detected_threats[0].description)

    def test_suspicious_command_patterns_file_not_found(self):
        """Test suspicious command detection when patterns file is missing."""
        original_builtin_open = builtins.open

        def mock_open_for_patterns_file(file_path, mode='r', *args, **kwargs):
            if file_path == self.suspicious_patterns_path and mode == 'r':
                raise FileNotFoundError(
                    f"Mocked FileNotFoundError for {file_path}")
            return original_builtin_open(file_path, mode, *args, **kwargs)

        with patch('builtins.open', side_effect=mock_open_for_patterns_file):
            with patch.object(self.detector.logger, 'error') as mock_logger_error:
                self.detector.instrument(
                    event_name="command_execute",
                    user_role="USER",
                    user_id="hacker_user_default",
                    source_id="compromised_server_default",
                    context={"command": "rm -rf /"}
                )

            expected_missing_file_path_in_main = "suspicious_patterns.json"
            mock_logger_error.assert_called_with(
                f"Could not find suspicious patterns file: {expected_missing_file_path_in_main}")

        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "CRITICAL")
        self.assertIn(
            "rm -rf /", self.detector.detected_threats[0].description)

    @patch('json.load')
    def test_suspicious_command_patterns_excessive_commands(self, mock_json_load):
        """Test detection of excessive command execution."""
        mock_json_load.return_value = {"suspicious_patterns": []}
        with patch('builtins.open', mock_open()) as mocked_file_open:
            user_id = "script_kiddie"
            source_id = "bot_ip"
            for i in range(self.detector.SUSPICIOUS_COMMAND_THRESHOLD + 1):
                self.detector.instrument(
                    event_name="execute_command",
                    user_role="USER",
                    user_id=user_id,
                    source_id=source_id,
                    context={"command": f"normal_command_{i}"}
                )
            mocked_file_open.assert_any_call("suspicious_patterns.json", "r")

        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "MEDIUM")
        self.assertIn("Excessive command execution",
                      self.detector.detected_threats[0].description)

    def test_suspicious_command_patterns_admin_business_hours(self):
        """Test suspicious command by admin during business hours (should not trigger)."""
        suspicious_command = "do_something test_suspicious_cmd important_file"
        business_hour_time = datetime.now().replace(
            hour=self.detector.BUSINESS_HOURS_START + 1)
        self.detector.instrument(
            event_name="admin_command",
            user_role="ADMIN",
            user_id="admin_ops",
            source_id="admin_workstation",
            timestamp=business_hour_time,
            context={"command": suspicious_command}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

    def test_session_hijacking_different_ip(self):
        """Test session hijacking with different IP."""
        user_id = "victim_user"
        session_token = "SESSION_TOKEN_ABC123"
        original_ip = "1.1.1.1"
        hijacker_ip = "2.2.2.2"
        ua = "Chrome/90.0"

        ts1 = datetime(2023, 1, 1, 12, 0, 0)
        self.detector.instrument(
            event_name="api_call", user_role="USER", user_id=user_id, source_id=original_ip,
            timestamp=ts1, context={
                "session_token": session_token, "user_agent": ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

        ts2 = ts1 + timedelta(seconds=30)
        self.detector.instrument(
            event_name="api_call", user_role="USER", user_id=user_id, source_id=hijacker_ip,
            timestamp=ts2, context={
                "session_token": session_token, "user_agent": ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "CRITICAL")
        self.assertIn("Session hijacking detected",
                      self.detector.detected_threats[0].description)
        self.assertIn(f"used from {original_ip} now being used from {hijacker_ip}",
                      self.detector.detected_threats[0].description)

    def test_session_hijacking_different_user_agent(self):
        """Test session hijacking with different User-Agent."""
        user_id = "victim_user_ua"
        session_token = "SESSION_TOKEN_DEF456"
        original_ip = "3.3.3.3"
        original_ua = "Mozilla/5.0 (Windows NT 10.0)"
        hijacker_ua = "curl/7.68.0"

        ts_init = datetime(2023, 1, 1, 13, 0, 0)
        self.detector.instrument(
            event_name="device_action", user_role="USER", user_id=user_id, source_id=original_ip,
            timestamp=ts_init, context={
                "session_token": session_token, "user_agent": original_ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

        ts_ua_change_same_ip = ts_init + timedelta(seconds=30)
        self.detector.instrument(
            event_name="device_action", user_role="USER", user_id=user_id, source_id=original_ip,
            timestamp=ts_ua_change_same_ip, context={
                "session_token": session_token, "user_agent": hijacker_ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 0,
                         "Threat should not be detected for UA change on same IP")

        self.detector.detected_threats = []
        self.detector.session_tracking = {}

        ts_reinit = datetime(2023, 1, 1, 14, 0, 0)
        self.detector.instrument(
            event_name="device_action", user_role="USER", user_id=user_id, source_id=original_ip,
            timestamp=ts_reinit, context={
                "session_token": session_token, "user_agent": original_ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

        hijacker_ip = "4.4.4.4"
        ts_hijack = ts_reinit + timedelta(seconds=30)
        self.detector.instrument(
            event_name="device_action", user_role="USER", user_id=user_id, source_id=hijacker_ip,
            timestamp=ts_hijack, context={
                "session_token": session_token, "user_agent": hijacker_ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 1)
        self.assertEqual(
            self.detector.detected_threats[0].threat_level, "CRITICAL")
        self.assertIn("User-Agent changed",
                      self.detector.detected_threats[0].description)
        self.assertIn(f"used from {original_ip} now being used from {hijacker_ip}",
                      self.detector.detected_threats[0].description)

    def test_session_hijacking_timeout_legitimate_move_ua_change(self):
        """Test session timeout allowing legitimate move to new IP and new User-Agent."""
        user_id = "mobile_user_ua_change"
        session_token = "SESSION_TOKEN_JKL012"
        original_ip = "9.9.9.9"
        new_ip = "10.10.10.10"
        original_ua = "AndroidApp/1.0"
        new_ua = "AndroidApp/2.0"

        ts1 = datetime.now() - timedelta(minutes=self.detector.SESSION_TIMEOUT_MINUTES + 5)
        self.detector.instrument(
            event_name="api_request", user_role="USER", user_id=user_id, source_id=original_ip,
            timestamp=ts1,
            context={"session_token": session_token, "user_agent": original_ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)
        session_key = f"{user_id}_{session_token}"
        self.assertEqual(
            self.detector.session_tracking[session_key]['user_agent'], original_ua)

        ts2 = datetime.now()
        self.detector.instrument(
            event_name="api_request", user_role="USER", user_id=user_id, source_id=new_ip,
            timestamp=ts2,
            context={"session_token": session_token, "user_agent": new_ua}
        )
        self.assertEqual(len(self.detector.detected_threats), 0,
                         "Threat should not be detected after session timeout")
        self.assertEqual(
            self.detector.session_tracking[session_key]['user_agent'], new_ua, "User agent should be updated")
        self.assertEqual(
            self.detector.session_tracking[session_key]['current_source_id'], new_ip)
        self.assertEqual(
            self.detector.session_tracking[session_key]['source_changes'], 0)

    def test_session_hijacking_timeout_legitimate_move(self):
        """Test session timeout allowing legitimate move to new IP."""
        user_id = "mobile_user"
        session_token = "SESSION_TOKEN_GHI789"
        original_ip = "5.5.5.5"
        new_ip = "6.6.6.6"

        ts1 = datetime.now() - timedelta(minutes=self.detector.SESSION_TIMEOUT_MINUTES + 5)
        self.detector.instrument(
            event_name="api_request", user_role="USER", user_id=user_id, source_id=original_ip,
            timestamp=ts1,
            context={"session_token": session_token,
                     "user_agent": "AndroidApp/1.0"}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

        ts2 = datetime.now()
        self.detector.instrument(
            event_name="api_request", user_role="USER", user_id=user_id, source_id=new_ip,
            timestamp=ts2,
            context={"session_token": session_token,
                     "user_agent": "AndroidApp/1.0"}
        )
        self.assertEqual(len(self.detector.detected_threats), 0,
                         "Threat should not be detected after session timeout")

    def test_session_hijacking_admin_business_hours(self):
        """Test session hijacking attempt for admin during business hours (should not trigger)."""
        user_id = "admin_victim"
        session_token = "SESSION_ADMIN_XYZ"
        original_ip = "7.7.7.7"
        hijacker_ip = "8.8.8.8"
        business_hour_time = datetime.now().replace(
            hour=self.detector.BUSINESS_HOURS_START + 2)

        self.detector.instrument(
            event_name="api_call", user_role="ADMIN", user_id=user_id, source_id=original_ip,
            timestamp=business_hour_time - timedelta(seconds=10),
            context={"session_token": session_token,
                     "user_agent": "AdminTool/1.0"}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

        self.detector.instrument(
            event_name="api_call", user_role="ADMIN", user_id=user_id, source_id=hijacker_ip,
            timestamp=business_hour_time,
            context={"session_token": session_token,
                     "user_agent": "AdminTool/1.0"}
        )
        self.assertEqual(len(self.detector.detected_threats), 0)

    def test_is_business_hours_admin_activity(self):
        """Test the _is_business_hours_admin_activity helper."""
        ts_business_admin = datetime.now().replace(hour=10)
        self.assertTrue(self.detector._is_business_hours_admin_activity(
            ts_business_admin, "ADMIN"))
        self.assertTrue(self.detector._is_business_hours_admin_activity(
            ts_business_admin, "MANAGER"))

        ts_off_hours_admin = datetime.now().replace(hour=20)
        self.assertFalse(self.detector._is_business_hours_admin_activity(
            ts_off_hours_admin, "ADMIN"))

        self.assertFalse(self.detector._is_business_hours_admin_activity(
            ts_business_admin, "USER"))

        self.assertFalse(self.detector._is_business_hours_admin_activity(
            ts_off_hours_admin, "USER"))

    def test_log_threat_file_creation(self):
        """Test that _log_threat creates and writes to security_alerts.json."""
        self.assertFalse(os.path.exists("security_alerts.json"))

        event = DetectionEvent(
            timestamp=datetime.now(),
            event_name="test_event",
            user_role="TEST_ROLE",
            user_id="test_user",
            source_id="test_source",
            context={"data": "test_data"},
            threat_level="TEST_LEVEL",
            description="This is a test threat."
        )
        self.detector._log_threat(event)

        self.assertTrue(os.path.exists("security_alerts.json"))
        with open("security_alerts.json", "r") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            log_entry = json.loads(lines[0])
            self.assertEqual(log_entry["description"],
                             "This is a test threat.")
            self.assertEqual(log_entry["threat_level"], "TEST_LEVEL")

    def test_log_threat_file_write_exception(self):
        """Test _log_threat when writing to file fails."""
        event = DetectionEvent(
            timestamp=datetime.now(), event_name="test_event_fail", user_role="TEST_ROLE",
            user_id="test_user_fail", source_id="test_source_fail", context={},
            threat_level="TEST_LEVEL_FAIL", description="This is a test threat for file write failure."
        )

        with patch('builtins.open', mock_open()) as mocked_open:
            mocked_open.side_effect = IOError("Simulated file write error")
            with patch.object(self.detector.logger, 'error') as mock_logger_error:
                self.detector._log_threat(event)

        mock_logger_error.assert_called_once()
        self.assertIn("Failed to write alert to file",
                      mock_logger_error.call_args[0][0])
        self.assertIn(event, self.detector.detected_threats)

    def test_get_threat_summary(self):
        """Test the get_threat_summary method."""
        summary_before = self.detector.get_threat_summary()
        self.assertEqual(summary_before["total_threats"], 0)

        ts = datetime.now()
        self.detector._log_threat(DetectionEvent(
            ts, "login_attempt", "", "u1", "s1", {}, "HIGH", "d1"))
        self.detector._log_threat(DetectionEvent(
            ts, "toggle_device", "", "u2", "s2", {}, "MEDIUM", "d2"))
        self.detector._log_threat(DetectionEvent(
            ts, "login_attempt", "", "u3", "s3", {}, "HIGH", "d3"))

        summary_after = self.detector.get_threat_summary()
        self.assertEqual(summary_after["total_threats"], 3)
        self.assertEqual(summary_after["threat_levels"]["HIGH"], 2)
        self.assertEqual(summary_after["threat_levels"]["MEDIUM"], 1)
        self.assertEqual(summary_after["threat_types"]["login_attempt"], 2)
        self.assertEqual(summary_after["threat_types"]["toggle_device"], 1)
        self.assertEqual(len(summary_after["recent_threats"]), 3)


if __name__ == '__main__':
    unittest.main()
