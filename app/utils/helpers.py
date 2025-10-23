from fastapi import Request
from typing import Optional, Dict, Any
import httpx
import re
from user_agents import parse


def get_client_info(request: Request) -> Dict[str, any]:
    """Extract client information from request."""
    # Get IP address
    ip_address = request.client.host if request.client else None

    # Check for forwarded IP (behind proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        ip_address = real_ip

    # Get user agent
    user_agent_string = request.headers.get("User-Agent", "")
    
    # Parse device info from user agent
    device_info_str, device_details = parse_user_agent(user_agent_string)
    
    # Get accept language
    accept_language = request.headers.get("Accept-Language", "")
    
    # Get referer
    referer = request.headers.get("Referer", "")
    
    return {
        "ip_address": ip_address,
        "user_agent": user_agent_string,
        "device_info": device_info_str,
        "device_details": device_details,
        "accept_language": accept_language,
        "referer": referer
    }


def parse_user_agent(user_agent_string: str) -> tuple[str, Dict[str, any]]:
    """Parse user agent string to extract device information.
    
    Returns:
        tuple: (human_readable_string, detailed_device_info_dict)
    """
    device_details = {
        "browser_name": "Unknown",
        "browser_version": "Unknown",
        "os_name": "Unknown",
        "os_version": "Unknown",
        "device_type": "Unknown",
        "device_brand": "Unknown",
        "device_model": "Unknown"
    }
    
    if not user_agent_string:
        return "Unknown Device", device_details
    
    try:
        user_agent = parse(user_agent_string)
        
        # Browser info
        browser_name = user_agent.browser.family
        browser_version = user_agent.browser.version_string
        
        # OS info
        os_name = user_agent.os.family
        os_version = user_agent.os.version_string
        
        # Device info
        device_type = "Desktop"
        if user_agent.is_mobile:
            device_type = "Mobile"
        elif user_agent.is_tablet:
            device_type = "Tablet"
        elif user_agent.is_bot:
            device_type = "Bot"
        
        device_brand = user_agent.device.brand or "Unknown"
        device_model = user_agent.device.model or "Unknown"
        
        # Update device details dictionary
        device_details.update({
            "browser_name": browser_name,
            "browser_version": browser_version,
            "os_name": os_name,
            "os_version": os_version,
            "device_type": device_type,
            "device_brand": device_brand,
            "device_model": device_model
        })
        
        # Create human-readable string
        human_readable = f"{browser_name} {browser_version} on {os_name} {os_version} ({device_type})"
        if device_brand != "Unknown" and device_model != "Unknown":
            human_readable += f" - {device_brand} {device_model}"
        
        return human_readable, device_details
    
    except Exception:
        # Fallback to basic parsing
        if "Mobile" in user_agent_string or "Android" in user_agent_string:
            device_details["device_type"] = "Mobile"
            return "Mobile Device", device_details
        elif "iPad" in user_agent_string or "Tablet" in user_agent_string:
            device_details["device_type"] = "Tablet"
            return "Tablet", device_details
        else:
            device_details["device_type"] = "Desktop"
            return "Desktop", device_details


async def get_location_from_ip(ip_address: Optional[str]) -> tuple[Optional[str], Dict[str, Any]]:
    """Get approximate location from IP address.
    
    Returns:
        tuple: (formatted_location_string, detailed_location_data)
    """
    location_data = {
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "zip": None,
        "latitude": None,
        "longitude": None,
        "timezone": None,
        "isp": None,
        "org": None
    }
    
    if not ip_address or ip_address in ["127.0.0.1", "localhost", "::1"]:
        return "Local", location_data
    
    # Skip private IP ranges
    if is_private_ip(ip_address):
        return "Private Network", location_data
    
    try:
        # For development/testing, return mock data to avoid API rate limits
        # In production, you would use the actual API call
        print(f"Getting location for IP: {ip_address}")
        
        # Mock data for testing
        mock_data = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "region": "CA",
            "regionName": "California",
            "city": "San Francisco",
            "zip": "94105",
            "lat": 37.7749,
            "lon": -122.4194,
            "timezone": "America/Los_Angeles",
            "isp": "Example ISP",
            "org": "Example Organization"
        }
        
        # Update location data dictionary with mock data
        location_data.update({
            "country": mock_data.get("country"),
            "country_code": mock_data.get("countryCode"),
            "region": mock_data.get("regionName"),
            "city": mock_data.get("city"),
            "zip": mock_data.get("zip"),
            "latitude": mock_data.get("lat"),
            "longitude": mock_data.get("lon"),
            "timezone": mock_data.get("timezone"),
            "isp": mock_data.get("isp"),
            "org": mock_data.get("org")
        })
        
        # Create formatted location string
        city = mock_data.get("city", "")
        country = mock_data.get("country", "")
        if city and country:
            return f"{city}, {country}", location_data
        elif country:
            return country, location_data
            
        # Uncomment this for production use with actual API
        """
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,query")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    # Update location data dictionary
                    location_data.update({
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org")
                    })
                    
                    # Create formatted location string
                    city = data.get("city", "")
                    country = data.get("country", "")
                    if city and country:
                        return f"{city}, {country}", location_data
                    elif country:
                        return country, location_data
        """
    except Exception as e:
        print(f"Error getting location from IP: {str(e)}")
    
    return "Unknown Location", location_data


def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range."""
    private_ranges = [
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\.",
        r"^127\.",
        r"^169\.254\.",
        r"^::1$",
        r"^fc00:",
        r"^fe80:"
    ]
    
    for pattern in private_ranges:
        if re.match(pattern, ip):
            return True
    return False


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password_strength(password: str) -> Dict[str, bool]:
    """Validate password strength."""
    checks = {
        "min_length": len(password) >= 8,
        "has_uppercase": bool(re.search(r'[A-Z]', password)),
        "has_lowercase": bool(re.search(r'[a-z]', password)),
        "has_digit": bool(re.search(r'\d', password)),
        "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }
    
    return checks


def is_strong_password(password: str) -> bool:
    """Check if password meets strength requirements."""
    checks = validate_password_strength(password)
    return all(checks.values())


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage."""
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:255-len(ext)-1] + '.' + ext if ext else name[:255]
    
    return filename or 'unnamed_file'


def generate_session_id() -> str:
    """Generate a unique session ID."""
    import uuid
    return str(uuid.uuid4())


def mask_email(email: str) -> str:
    """Mask email for privacy (e.g., j***@example.com)."""
    if '@' not in email:
        return email
    
    local, domain = email.split('@', 1)
    if len(local) <= 2:
        masked_local = local[0] + '*'
    else:
        masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
    
    return f"{masked_local}@{domain}"


def format_datetime(dt) -> str:
    """Format datetime for display."""
    if not dt:
        return "Never"
    
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return str(dt)