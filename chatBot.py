import re
import json
import time
import requests
import sys
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from datetime import datetime

ORBIT_HOSTNAME = "10.129.31.6"

# --- SDK Import Handling ---
try:
    import bosdyn.client
    from bosdyn.client import create_standard_sdk, ResponseError, RpcError
    # Note: bosdyn.orbit.client is hypothetical here unless you have a specific wrapper.
    # We will keep the import for structure but ensure safety.
    try:
        from bosdyn.orbit.client import Client as OrbitClient
    except ImportError:
        OrbitClient = None
    SPOT_SDK_AVAILABLE = True
except ImportError:
    print("⚠️  Orbit SDK not found. Install via: pip install bosdyn-orbit")
    SPOT_SDK_AVAILABLE = False
    OrbitClient = None
    print("Warning: Spot SDK not installed. Run: pip install bosdyn-client")

@dataclass
class Mission:
    mission_id: str
    mission_name: str
    robot_nickname: Optional[str] = None
    created_at: Optional[str] = None
    mission_type: Optional[str] = None

class OrbitMissionDispatcher:
    def __init__(self, orbit_hostname: str, orbit_verify_cert: bool = True):
        self.orbit_hostname = orbit_hostname
        # Ensure URL has protocol
        if orbit_hostname.startswith("http"):
            self.orbit_url = orbit_hostname
        else:
            self.orbit_url = f"https://{orbit_hostname}"
            
        self.orbit_verify_cert = orbit_verify_cert
        
        self.orbit_client = None
        self.access_token = None
        
        self.available_missions: Dict[str, Mission] = {}
        self.available_robots: Dict[str, Any] = {}
        
    def authenticate_orbit(self, username: str, password: str) -> bool:
        print(f"🔐 Authenticating with Orbit at {self.orbit_hostname}...")
        try:
            if SPOT_SDK_AVAILABLE and OrbitClient:
                self.orbit_client = OrbitClient(self.orbit_hostname, verify=self.orbit_verify_cert)
                self.orbit_client.authenticate(username, password)
                print("✓ Orbit authentication successful (SDK)!")
                return True
            else:
                auth_url = f"{self.orbit_url}/api/v1/auth/token"
                response = requests.post(
                    auth_url, 
                    json={"username": username, "password": password}, 
                    verify=self.orbit_verify_cert
                )
                
                if response.status_code == 200:
                    self.access_token = response.json().get("access_token")
                    print("✓ Orbit authentication successful (REST)!")
                    return True
                else:
                    print(f"✗ Authentication failed: {response.status_code}")
                    print(f"   {response.text}")
                    return False
        except Exception as e:
            print(f"✗ Unexpected error during authentication: {e}")
            return False
        
    def authenticate_orbit_with_api_token(self, api_token: str):
        try:
            print(f"🔐 Authenticating with Orbit using API token...")

            self.access_token = api_token
            
            if SPOT_SDK_AVAILABLE and OrbitClient:
                self.orbit_client = OrbitClient(hostname=self.orbit_hostname, verify=self.orbit_verify_cert)
                self.orbit_client.authenticate_with_token(api_token)
                print("✓ Orbit authentication successful!")
                return True
            else:
                print("✓ API token set!")
                return True
                
        except Exception as e:
            print(f"✗ API token authentication error: {e}")
            return False
        
    def get_available_robots(self) -> Dict[str, Any]:
        try:
            print("⧗ Fetching available robots from Orbit...")
            self.available_robots = {}

            if self.orbit_client:
                robots = self.orbit_client.get_robots()
                for robot in robots:
                    self.available_robots[robot.nickname.lower()] = {
                        'id': robot.robot_id, 
                        'nickname': robot.nickname,
                        'serial_number': robot.serial_number,
                        'status': getattr(robot, 'status', 'unknown')
                    }
                    print(f"  • {robot.nickname} (S/N: {robot.serial_number})")
                
            else:
                headers = {'Authorization': f'Bearer {self.access_token}'}
                response = requests.get(f"{self.orbit_url}/api/v1/robots", 
                                        headers=headers, 
                                        verify=self.orbit_verify_cert)
                
            if response.status_code == 200:
                data = response.json()
                # print(f"DEBUG: API Response type: {type(data)}")
                # print(f"DEBUG: API Response: {data}")

                robots = data if isinstance(data, list) else data.get('robots', [])
                self.available_robots = {}
                for robot in robots:
                    
                    #If no nickname, skip
                    if 'nickname' not in robot:
                        continue

                    nickname = robot['nickname']

                    s_online = "🟢 ONLINE" if robot.get('isOnline') else "🔴 OFFLINE"
                    lease = "Unknown"
                    if 'lease' in robot:
                        print(lease = robot['lease'].get('holder', 'None'))

                    self.available_robots[nickname.lower()] = {
                        'id': robot.get('hostname', robot.get('robotIndex', 'N/A')),
                        'nickname': nickname,
                        'serial_number': robot.get('hostname', 'N/A'),
                        'status': 'paired' if robot.get('paired', False) else 'unpaired',
                        'ip' : robot.get('ipEthernet', 'N/A')
                        }
                    print(f"  • {nickname} ({robot.get('ipEthernet', 'N/A')})")
        
            print(f"  ✓ Found {len(self.available_robots)} robot(s)")
            return self.available_robots
        
        except Exception as e:
            print(f"✗ Error fetching robots: {e}")
            return {}      
        
    def get_available_missions(self) -> Dict[str, Mission]:
        self.available_missions = {}
        try:
            print("⧗ Fetching available missions from Orbit...")
            self.available_missions = {}
            
            if self.orbit_client:
                missions = self.orbit_client.get_missions()
                for mission in missions:

                    raw_name = mission.get('name')
                    m_name = raw_name if raw_name else "Unnamed Mission"

                    mission_obj = Mission(
                        mission_id=mission.id,
                        mission_name=mission.name,
                        robot_nickname=getattr(mission, 'robot_nickname', None),
                        created_at=getattr(mission, 'created_at', None),
                        mission_type=getattr(mission, 'mission_type', None)
                    )
                    self.available_missions[mission.name.lower()] = mission_obj
                    robot_info = f" (Robot: {mission_obj.robot_nickname})" if mission_obj.robot_nickname else ""
                    print(f"  • {m_name}{robot_info}")
            else:       
                headers = {'Authorization': f'Bearer {self.access_token}'}
                response = requests.get(f"{self.orbit_url}/api/v1/missions", 
                                        headers=headers, 
                                        verify=self.orbit_verify_cert)
                
                if response.status_code == 200:
                    missions = response.json().get('missions', [])
                    for mission in missions:
                        mission_obj = Mission(
                            mission_id=mission.get('id'),
                            mission_name=mission.get('name'),
                            robot_nickname=mission.get('robot_nickname'),
                            created_at=mission.get('created_at'),
                            mission_type=mission.get('mission_type', None)
                        )

                        self.available_missions[m_name.lower()] = mission_obj
                        robot_info = f" (Robot: {mission_obj.robot_nickname})" if mission_obj.robot_nickname else ""
                        print(f"  • {m_name}{robot_info}")

            if not self.available_missions:
                print("  ⚠️  No missions found in Orbit!")
            else:
                print(f"  ✓ Loaded {len(self.available_missions)} mission(s)")
            
            return self.available_missions
            
        except Exception as e:
            print(f"✗ Failed to fetch missions: {e}")
            import traceback
            traceback.print_exc()  # This helps debug
            return {}
        
    def mission_dispatcher(self, robot_nickname: Optional[str], mission_name: str) -> bool:
        if not mission_name:
            return False
            
        mission_key = mission_name.lower()
        if robot_nickname:
            robot_nickname = robot_nickname.lower()
        
        print(f"⧗ Dispatching mission '{mission_name}'...")
        
        if mission_key not in self.available_missions:
            print(f"✗ Mission '{mission_name}' not found.")
            return False

        mission = self.available_missions[mission_key]
        target_robot = robot_nickname or mission.robot_nickname
        
        if not target_robot:
             print("✗ No robot specified for this mission.")
             return False

        if target_robot.lower() not in self.available_robots:
            print(f"✗ Robot '{target_robot}' not found in Orbit list.")
            return False

        try:
            print(f"🚀 Dispatching mission: {mission.mission_name}")
            print(f"   Target robot: {target_robot}")
            
            if self.orbit_client:
                self.orbit_client.start_mission(
                    mission_id=mission.mission_id,
                    robot_nickname=target_robot
                )
            else:
                headers = {'Authorization': f'Bearer {self.access_token}'}
                dispatch_url = f"{self.orbit_url}/api/v0/missions/{mission.mission_id}/dispatch"
                payload = {'robot_nickname': target_robot}
                
                response = requests.post(
                    dispatch_url,
                    json=payload,
                    headers=headers,
                    verify=self.orbit_verify_cert
                )
                
                if response.status_code not in [200, 201, 202]:
                    print(f"✗ Dispatch failed: {response.status_code}")
                    print(f"   {response.text}")
                    return False
            
            print(f"✓ Mission dispatched successfully!")
            return True
            
            except Exception as e:
                print(f"✗ Failed to dispatch mission: {e}")
                return False
    
    def get_mission_status(self, mission_name: str) -> Optional[Dict]:
        try:
            mission_key = mission_name.lower()
            if mission_key not in self.available_missions:
                return None
            
            mission = self.available_missions[mission_key]
            
            # Note: Logic assumes checking runs for specific mission
            # This logic needs to be adapted based on exact API response structure
            if self.orbit_client:
                 # Pseudo-call: fetching runs via SDK
                 runs = self.orbit_client.get_mission_runs(mission.mission_id)
                 if not runs: return None
                 latest_run = runs[0]
                 return {
                    'mission' : mission.mission_name,
                    'status' : getattr(latest_run, 'status', 'unknown'),
                    'started_at' : getattr(latest_run, 'started_at', None),
                    'robot' : getattr(latest_run, 'robot_nickname', None)
                }
            else:
                headers = {"Authorization": f'Bearer {self.access_token}'}
                response = requests.get(
                    f"{self.orbit_url}/api/v0/site_walks/{mission.mission_id}/runs",
                    headers=headers,
                    verify=self.orbit_verify_cert
                )
                
                if response.status_code == 200:
                    runs = response.json().get('runs', [])
                    if not runs:
                        return None
                    
                    latest_run = runs[0]
                    return {
                        'mission' : mission.mission_name,
                        'status' : latest_run.get('status', 'unknown'),
                        'started_at' : latest_run.get('started_at', None),
                        'robot' : latest_run.get('robot_nickname', None)
                    }
                    
            return None
        
        except Exception as e:
            print(f"✗ Error fetching mission status: {e}")
            return None

    def start_up(self, auth_method: str, **auth_kwargs) -> bool:
        success = False
        if auth_method == 'password':
            success = self.authenticate_orbit(auth_kwargs.get('username'), auth_kwargs.get('password'))
        elif auth_method == 'api_token':
            success = self.authenticate_orbit_with_api_token(auth_kwargs.get('api_token'))
        else:
            print("✗ Invalid authentication method.")
            return False
            
        if success:
            self.get_available_robots()
            self.get_available_missions()
            return True
        return False

# --- Chatbot Interface ---
class MissionChatbot:
    def __init__(self, dispatcher: OrbitMissionDispatcher):
        self.dispatcher = dispatcher
        
        self.patterns = [
            # Dispatch: "start Inspection on Spot-1"
            (r"(?:start|run|execute|dispatch|send)\s+(.+?)\s+(?:on|to)\s+(.+)", self._handle_dispatch_to_robot),
            # Dispatch: "start Inspection"
            (r"(?:start|run|execute|dispatch)\s+(.+)", self._handle_dispatch),
            # Status: "status of Inspection"
            (r"status(?:\s+of)?\s+(.+)", self._handle_mission_status),
            # General Status
            (r"(?:what'?s|check)\s+(?:the\s+)?status", self._handle_general_status),
            # Listings
            (r"(?:list|show)\s+missions?", self._handle_list_missions),
            (r"(?:list|show)\s+robots?", self._handle_list_robots),
        ]
                 
    def parse_command(self, user_input: str) -> bool:
        user_input = user_input.strip()
        for pattern, handler in self.patterns:
            match = re.match(pattern, user_input, re.IGNORECASE)
            if match:
                return handler(match, user_input)
        return False
        
    def _handle_dispatch_to_robot(self, match, raw_cmd) -> bool:
        mission_name = match.group(1).strip()
        robot_nickname = match.group(2).strip()
        return self.dispatcher.mission_dispatcher(robot_nickname, mission_name)
    
    def _handle_dispatch(self, match, raw_cmd) -> bool:
        mission_name = match.group(1).strip()
        return self.dispatcher.mission_dispatcher(None, mission_name)
    
    def _handle_mission_status(self, match, raw_cmd) -> bool:
        mission_name = match.group(1).strip()
        status = self.dispatcher.get_mission_status(mission_name)
        if status:
            print(f"\n📊 Mission Status: {status['mission']}")
            print(f"   Status: {status['status']}")
            print(f"   Robot: {status['robot']}")
            print(f"   Started: {status['started_at']}\n")
        else:
            print(f"✗ No status available for '{mission_name}'\n")
        return True
    
    def _handle_general_status(self, match, raw_cmd) -> bool:
        print("\n📊 Orbit System Status:")
        print(f"   Robots: {len(self.dispatcher.available_robots)}")
        print(f"   Missions: {len(self.dispatcher.available_missions)}\n")
        return True
    
    def _handle_list_missions(self, match, raw_cmd) -> bool:
        missions = self.dispatcher.available_missions
        if missions:
            print(f"\n📋 Available Missions ({len(missions)}):")
            for mission in missions.values():
                robot_info = f" → {mission.robot_nickname}" if mission.robot_nickname else ""
                print(f"   • {mission.mission_name}{robot_info}")
                print(f"   • {mission.mission_name}{robot_info}")
        else:
            print("\n📋 No missions in Orbit")
        print()
        return True
    
    def _handle_list_robots(self, match, raw_cmd) -> bool:
        robots = self.dispatcher.available_robots
        if robots:
            print(f"\n🤖 Available Robots ({len(robots)}):")
            for robot in robots.values():
                print(f"   • {robot['nickname']} (Status: {robot['status']})")
        else:
            print("\n🤖 No robots registered")
        print()
        return True
    
    def get_help(self) -> str:
        return """
╔════════════════════════════════════════════════════════════╗
║         Orbit Mission Dispatcher - Commands                ║
╠════════════════════════════════════════════════════════════╣
║ DISPATCH MISSIONS:                                         ║
║   • "start warehouse patrol"                               ║
║   • "run inspection on Spot-1"                             ║
║                                                            ║
║ STATUS & INFO:                                             ║
║   • "status of warehouse patrol"                           ║
║   • "list missions"                                        ║
║   • "list robots"                                          ║
╚════════════════════════════════════════════════════════════╝
"""

if __name__ == "__main__":
    print("╔════════════════════════════════════════════════════════════╗")
    print("║         Orbit Mission Dispatcher - Chatbot Interface       ║")
    print("╚════════════════════════════════════════════════════════════╝\n")
    
    try:
        # Get Credentials
        ORBIT_HOSTNAME = input(f"Orbit hostname [{ORBIT_HOSTNAME}]: ") or ORBIT_HOSTNAME
        
        dispatcher = OrbitMissionDispatcher(
            orbit_hostname=ORBIT_HOSTNAME,
            orbit_verify_cert=False # Often False for internal testing
        )
        
        print("\nAuthentication Method:")
        print("1. API Token (Recommended)")
        print("2. Username/Password")
        choice = input("Select (1/2): ").strip()
        
        success = False
        if choice == '1':
            token = input("Enter API Token: ").strip()
            success = dispatcher.start_up('api_token', api_token=token)
        else:
            user = input("Username: ").strip()
            pwd = input("Password: ").strip()
            success = dispatcher.start_up('password', username=user, password=pwd)
            
        if not success:
            print("Failed to start up. Exiting.")
            sys.exit(1)
            
        # Start Chatbot
        chatbot = MissionChatbot(dispatcher)
        print(chatbot.get_help())
        
        while True:
            try:
                user_input = input("🤖 You: ").strip()
                if user_input.lower() in ['quit', 'exit', 'q']: break
                if not user_input: continue
                if user_input.lower() == 'help': 
                    print(chatbot.get_help())
                    continue
                    
                if not chatbot.parse_command(user_input):
                    print("❓ Command not recognized.")
            except KeyboardInterrupt:
                break
                
    except Exception as e:
        print(f"\nCritical Error: {e}")
    
    print("\n👋 Goodbye!\n")