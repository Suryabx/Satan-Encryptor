"""
Logger Module
Handles application logging and activity tracking
"""

import json
import os
from datetime import datetime
from pathlib import Path

class Logger:
    """Application logger for tracking activities"""
    
    def __init__(self, log_file="satan_encryptor.log", max_logs=1000):
        self.log_file = log_file
        self.max_logs = max_logs
        self.logs = []
        self.load_logs()
        
    def log(self, action, details, level="info"):
        """Add a log entry"""
        log_entry = {
            'timestamp': datetime.now(),
            'action': action,
            'details': details,
            'level': level
        }
        
        self.logs.insert(0, log_entry)  # Add to beginning
        
        # Keep only max_logs entries
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[:self.max_logs]
            
        self.save_logs()
        
    def get_logs(self):
        """Get all logs"""
        return self.logs
        
    def get_recent_logs(self, count=10):
        """Get recent logs"""
        return self.logs[:count]
        
    def clear_logs(self):
        """Clear all logs"""
        self.logs = []
        self.save_logs()
        
    def save_logs(self):
        """Save logs to file"""
        try:
            # Convert datetime objects to strings for JSON serialization
            serializable_logs = []
            for log in self.logs:
                serializable_log = log.copy()
                serializable_log['timestamp'] = log['timestamp'].isoformat()
                serializable_logs.append(serializable_log)
                
            with open(self.log_file, 'w') as f:
                json.dump(serializable_logs, f, indent=2)
        except Exception as e:
            print(f"Failed to save logs: {str(e)}")
            
    def load_logs(self):
        """Load logs from file"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    serializable_logs = json.load(f)
                    
                # Convert timestamp strings back to datetime objects
                self.logs = []
                for log in serializable_logs:
                    log['timestamp'] = datetime.fromisoformat(log['timestamp'])
                    self.logs.append(log)
        except Exception as e:
            print(f"Failed to load logs: {str(e)}")
            self.logs = []
            
    def export_logs(self, export_path):
        """Export logs to a file"""
        try:
            # Create a formatted log export
            with open(export_path, 'w') as f:
                f.write("Satan Encryptor Suite - Activity Log Export\n")
                f.write("=" * 50 + "\n\n")
                
                for log in self.logs:
                    timestamp = log['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"[{timestamp}] {log['level'].upper()}\n")
                    f.write(f"Action: {log['action']}\n")
                    f.write(f"Details: {log['details']}\n")
                    f.write("-" * 30 + "\n\n")
                    
            return True
        except Exception as e:
            print(f"Failed to export logs: {str(e)}")
            return False
            
    def search_logs(self, query, field='action'):
        """Search logs by field"""
        results = []
        query = query.lower()
        
        for log in self.logs:
            if field in log and query in log[field].lower():
                results.append(log)
                
        return results
        
    def get_logs_by_level(self, level):
        """Get logs by level (info, warning, error)"""
        return [log for log in self.logs if log['level'] == level]
        
    def get_logs_by_date(self, date):
        """Get logs by date"""
        target_date = date.date() if hasattr(date, 'date') else date
        return [log for log in self.logs if log['timestamp'].date() == target_date]
        
    def get_log_statistics(self):
        """Get log statistics"""
        total_logs = len(self.logs)
        if total_logs == 0:
            return {'total': 0}
            
        levels = {}
        actions = {}
        
        for log in self.logs:
            # Count by level
            level = log['level']
            levels[level] = levels.get(level, 0) + 1
            
            # Count by action
            action = log['action']
            actions[action] = actions.get(action, 0) + 1
            
        return {
            'total': total_logs,
            'by_level': levels,
            'by_action': actions,
            'oldest': self.logs[-1]['timestamp'] if self.logs else None,
            'newest': self.logs[0]['timestamp'] if self.logs else None
        }