import re
import time
import requests
import sys
import warnings
from typing import Optional, Dict
from dataclasses import dataclass
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings if you are using self-signed certs
warnings.simplefilter('ignore', InsecureRequestWarning)

print("="*60)
print("  ORBIT MISSION DISPATCHER (API MODE)")
print("="*60)

@dataclass
class Mission:
    mission_id: str
    mission_name: str
    robot_nickname: Optional[str] = None
    
class OrbitMissionDispatcher:
    def __init__(self, orbit_hostname: str, orbit_verify_cert: bool = True):
        # Normalize hostname to full URL
        if not orbit_hostname.startswith("http"):
            self.orbit_url = f"https://{orbit_hostname}"
        else:
            self.orbit_url = orbit_hostname
            
        self.orbit_verify_cert = orbit_verify_cert
        
        # Use a Session for connection pooling and persistent headers
        self.session = requests.Session()
        self.session.verify = orbit_verify_cert
        
        self.available_missions = {}
        self.available_robots = {}

    def authenticate_with_token(self, api_token: str) -> bool:
        """
        Authenticates by setting the standard Authorization header.
        This is the native way to use API tokens.
        """
        print(f"🔐 Authenticating with API Token...")
        
        # 1. Set the header for all future requests
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        })
        
        # 2. Validate the token by hitting a lightweight endpoint
        try:
            # We try to fetch the version or robots to verify access
            response = self.session.get(f"{self.orbit_url}/api/v0/robots", timeout=5)
            
            if response.status_code == 200:
                print("✓ API Token accepted by Orbit!")
                return True
            elif response.status_code in [401, 403]:
                print(f"✗ Authentication failed: Access Denied ({response.status_code})")
                return False
            else:
                print(f"✗ Connection validation failed: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Could not connect to Orbit: {e}")
            return False

    def get_available_robots(self) -> Dict[str, str]:
        print("⧗ Fetching robots via API...")
        try:
            response = self.session.get(f"{self.orbit_url}/api/v0/robots")
            
            if response.status_code != 200:
                print(f"✗ API Error: {response.status_code} - {response.text}")
                return {}

            data = response.json()
            # Handle different Orbit API response structures (list vs dict)
            robots_list = data if isinstance(data, list) else data.get('robots', [])
            
            self.available_robots = {}
            for r in robots_list:
                if 'nickname' not in r: continue
                
                nick = r['nickname']
                self.available_robots[nick.lower()] = {
                    'id': r.get('hostname', r.get('id', 'N/A')),
                    'nickname': nick,
                    'status': 'paired' if r.get('paired') else 'unpaired'
                }
                print(f"  • {nick} (Status: {self.available_robots[nick.lower()]['status']})")
                
            return self.available_robots
            
        except Exception as e:
            print(f"✗ Error parsing robots: {e}")
            return {}

    def get_available_missions(self) -> Dict[str, Mission]:
        print("⧗ Fetching missions via API...")
        try:
            response = self.session.get(f"{self.orbit_url}/api/v0/site_walks")
            
            if response.status_code != 200:
                print(f"✗ API Error: {response.status_code} - {response.text}")
                return {}

            data = response.json()
            missions_list = data if isinstance(data, list) else data.get('missions', [])
            
            self.available_missions = {}
            for m in missions_list:
                m_obj = Mission(
                    mission_id=m['uuid'],
                    mission_name=m['name'],
                    robot_nickname=m.get('robot_nickname')
                )
                self.available_missions[m['name'].lower()] = m_obj
                
                robot_str = f" -> {m_obj.robot_nickname}" if m_obj.robot_nickname else ""
                print(f"  • {m_obj.mission_name}{robot_str}")
                
            return self.available_missions
            
        except Exception as e:
            print(f"✗ Error parsing missions: {e}")
            return {}

    def dispatch_mission(self, mission_name: str, robot_nickname: str) -> bool:
        # 1. Resolve Mission
        m_key = mission_name.lower()
        if m_key not in self.available_missions:
            print(f"✗ Mission '{mission_name}' not found.")
            return False
        mission = self.available_missions[m_key]

        # 2. Resolve Robot
        r_target = robot_nickname.lower() if robot_nickname else (mission.robot_nickname.lower() if mission.robot_nickname else None)
        
        if not r_target or r_target not in self.available_robots:
            print(f"✗ Robot '{robot_nickname}' not found.")
            return False
            
        robot_hostname = self.available_robots[r_target]['id']

        # 3. Execute "Run" API Call
        print(f"🚀 Dispatching '{mission.mission_name}' to '{robot_hostname}'...")
        
        # API Endpoint: Create a Run (This is the standard way to 'dispatch')
        url = f"{self.orbit_url}/api/v0/site_walks/{mission.mission_id}/runs"
        
        # Payload: Orbit expects start_time in ms to schedule immediately
        current_time_ms = int(time.time() * 1000)
        payload = {
            "robot_hostname": robot_hostname,
            "start_time": current_time_ms
        }
        
        try:
            response = self.session.post(url, json=payload)
            
            if response.status_code in [200, 201]:
                print(f"✓ Mission successfully dispatched! (Run ID: {response.json().get('id', 'Unknown')})")
                return True
            else:
                print(f"✗ Dispatch Failed: {response.status_code}")
                print(f"  Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"✗ API Connection Failed: {e}")
            return False

# --- Chat Interface ---
class MissionChatBot:
    def __init__(self, dispatcher: OrbitMissionDispatcher):
        self.dispatcher = dispatcher
        # Simple regex patterns for commands
        self.patterns = [
            (r"(?:start|run|dispatch)\s+(.+?)\s+(?:on|to)\s+(.+)", self._dispatch),
            (r"(?:list|show)\s+missions?", self._list_missions),
            (r"(?:list|show)\s+robots?", self._list_robots),
        ]

    def process(self, text):
        for pattern, func in self.patterns:
            match = re.match(pattern, text.strip(), re.IGNORECASE)
            if match:
                return func(match)
        print("❓ Command not recognized.")

    def _dispatch(self, match):
        return self.dispatcher.dispatch_mission(match.group(1).strip(), match.group(2).strip())

    def _list_missions(self, _):
        self.dispatcher.get_available_missions()

    def _list_robots(self, _):
        self.dispatcher.get_available_robots()

if __name__ == "__main__":
    # CONFIGURATION
    HOST = "10.129.31.6"  # Your Host IP
    
    # 1. Setup
    dispatcher = OrbitMissionDispatcher(orbit_hostname=HOST, orbit_verify_cert=False)
    
    # 2. Auth
    token = input("Orbit API Token: ").strip()
    if not dispatcher.authenticate_with_token(token):
        sys.exit(1)
        
    # 3. Load Data
    dispatcher.get_available_robots()
    dispatcher.get_available_missions()
    
    # 4. Loop
    bot = MissionChatBot(dispatcher)
    print("\n🤖 Ready! (Type 'run <mission> on <robot>', 'list missions', or 'q')")
    
    while True:
        try:
            cmd = input("You: ")
            if cmd.lower() in ['q', 'quit']: break
            if cmd: bot.process(cmd)
        except KeyboardInterrupt:
            break