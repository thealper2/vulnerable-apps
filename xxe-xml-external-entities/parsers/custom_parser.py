import re
from typing import Dict, Optional

from models.data_models import UserProfile


class SimpleXMLParser:
    """A simple custom XML parser with limited functionality"""

    @staticmethod
    def extract_user_profile(xml_str: str) -> Optional[UserProfile]:
        """
        Extracts user profile data from XML using regex
        Only allows specific tags and doesn't process entities
        """
        try:
            username = re.search(r"<username>(.*?)</username>", xml_str)
            email = re.search(r"<email>(.*?)</email>", xml_str)
            age = re.search(r"<age>(.*?)</age>", xml_str)

            if not username:
                return None

            return UserProfile(
                username=username.group(1),
                email=email.group(1) if email else None,
                age=int(age.group(1)) if age and age.group(1).isdigit() else None,
            )

        except Exception:
            return None
