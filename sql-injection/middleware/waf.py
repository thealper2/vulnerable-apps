import re
from typing import Any, Dict, Optional

from flask import jsonify, request


class WebApplicationFirewall:
    """Simple WAF to detect and block SQL injection attempts"""
    
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 
        'UNION', 'OR', 'AND', '--', ';', '/*', '*/', 'EXEC'
    ]
    
    @classmethod
    def detect_sql_injection(cls, input_str: str) -> bool:
        """Check if input contains potential SQL injection patterns"""
        if not isinstance(input_str, str):
            return False
            
        input_upper = input_str.upper()
        for keyword in cls.SQL_KEYWORDS:
            if keyword in input_upper:
                # Simple pattern matching - could be enhanced
                return True
                
        # Check for common injection patterns
        patterns = [
            r".*'.*--.*",    # Single quote followed by comment
            r".*;.*",        # Statement termination
            r".*/\*.*\*/.*"  # Block comments
        ]
        
        for pattern in patterns:
            if re.match(pattern, input_upper):
                return True
                
        return False
    
    @classmethod
    def check_request(cls) -> Optional[Dict[str, Any]]:
        """Check incoming request for SQL injection attempts"""
        # Check query parameters
        for _, value in request.args.items():
            if cls.detect_sql_injection(value):
                return {"status": "error", "message": "Potential SQL injection detected"}
        
        # Check form data
        if request.form:
            for _, value in request.form.items():
                if cls.detect_sql_injection(value):
                    return {"status": "error", "message": "Potential SQL injection detected"}
        
        # Check JSON body
        if request.is_json:
            data = request.get_json(silent=True) or {}
            for _, value in data.items():
                if isinstance(value, str) and cls.detect_sql_injection(value):
                    return {"status": "error", "message": "Potential SQL injection detected"}
        
        return None