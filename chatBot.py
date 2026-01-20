import re
import json
import time
import requests
from typing import Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime

try:
    import bosdyn.client
    from bosdyn.client import create_standard_sdk, ResponseError, RpcError
    from bosdyn.client.lease import LeaseClient, LeaseKeepAlive
    from bosdyn.client.estop import EstopClient, EstopEndpoint, EstopKeepAlive
    from bosdyn.client.robot_state import RobotStateClient
    from bosdyn.orbit.client import Client as OrbitClient
    SPOT_SDK_AVAILABLE = True
except ImportError:
    SPOT_SDK_AVAILABLE = False
    print("Warning: Spot SDK not installed. Run: pip install bosdyn-client bosdyn-mission")

@dataclass
class Mission:
    mission_id: str
    mission_name: str
    robot_nickname: Optional[str] = None
    created_at: Optional[str] = None
    mission_type: Optional[str] = None

class OrbitMissionDispatcher:
    def __init__(self, orbit_hostname: str, orbit_verify_cert: bool = True):
        
        if not SPOT_SDK_AVAILABLE:
            raise ImportError("Spot SDK not installed. Run: pip install bosdyn-client bosdyn-mission")
        
        self.orbit_hostname = orbit_hostname
        self.orbit_url = f"https://{orbit_hostname}"
        self.orbit_verify_cert = orbit_verify_cert
        
        self.orbit_client = None
        self.access_token = None
        
        self.available_missions = {}
        self.available_robots = {}
        
    def authenticate(self, username: str, password: str) -> bool:
        try:
            print(f"🔐 Authenticating with Orbit at {self.orbit_hostname}...")
            
            if SPOT_SDK_AVAILABLE:
                self.orbit_client = OrbitClient(self.orbit_hostname, verify=self.orbit_verify_cert)
                self.orbit_client.authenticate(username, password)
                print("✓ Orbit authentication successful (SDK)!")
                return True
            
            else:
                auth_url = f"{self.orbit_url}/api/v1/auth/token"
                response = requests.post(auth_url, json={"username": username, "password": password}, verify=self.orbit_verify_cert)
            
                if response.status_code == 200:
                    self.access_token = response.json()["access_token"]
                    print("✓ Orbit authentication successful (REST)!")
                    return True
                else:
                    print(f"✗ Authentication failed: {response.status_code}")
                    print(f"   {response.text}")
                    return False
        except Exception as e:
            print(f"✗ Unexpected error during authentication: {e}")
            return False
        
    def authenticate_orbit_with_api_token(self, api_token: str) -> bool:
        try:
            print(f"🔐 Authenticating with Orbit using API token...")
            
            if SPOT_SDK_AVAILABLE:
                self.orbit_client = OrbitClient(hostname=self.orbit_hostname, verify=self.verify_cert)
                self.orbit_client.authenticate_with_token(api_token)
                print("✓ Orbit authentication successful!")
                return True
            else:
                self.access_token = api_token
                print("✓ API token set!")
                return True
                
        except Exception as e:
            print(f"✗ API token authentication error: {e}")
            return False
        
    def get_available_robots (self) -> Dict[str, str]:
        try:
            print("⧗ Fetching available robots from Orbit...")
            
            if self.orbit_client:
                robots = self.orbit_client.get_robots()
                for robot in robots:
                    self.available_robots[robot.nickname.lower()] = {
                        'id': robot.robot_id, 
                        'nickname': robot.nickname,
                        'serial_number': robot.serial_number,
                        'state': getattr(robot, 'status', 'unknown')
                    }

                print(f"  • {robot.nickname} (S/N: {robot.serial_number})")
                
            else:
                headers = {'Authorization': f'Bearer {self.access_token}'}
                response = requests.get(f"{self.orbit_url}/api/v1/robots", 
                                        headers=headers, 
                                        verify=self.orbit_verify_cert)
                
                if response.status_code == 200:
                    robots = response.json().get('robots', [])
                    self.available_robots = {}
                    for robot in robots:
                        nickname = robot['nickname']
                        self.available_robots[nickname.lower()] = {
                            'id': robot['id'],
                            'nickname': nickname,
                            'serial_number': robot.get('serial_number', 'N/A'),
                            'status': robot.get('status', 'unknown')
                        }
                        print(f"  • {nickname}")
        
            print(f"  ✓ Found {len(self.available_robots)} robot(s)")
            return self.available_robots
        
        except Exception as e:
            print(f"✗ Error fetching robots: {e}")
            return {}      
        
    def get_available_missions(self) -> Dict[str, Mission]:
        try:
            print("⧗ Fetching available missions from Orbit...")
            
            if self.orbit_client:
                missions = self.orbit_client.get_missions()
                self.available_missions = {}
                for mission in missions:
                    mission_obj = Mission(
                        mission_id= mission.id,
                        mission_name= mission.name,
                        robot_nickname= getattr(mission, 'robot_nickname', None),
                        created_at= getattr(mission, 'created_at', None),
                        mission_type= getattr(mission, 'mission_type', None)
                    )
                    
                    self.available_missions[mission.name.lower()] = mission_obj
                    
                    robot_info = f" (Robot: {mission_obj.robot_nickname})" if mission_obj.robot_nickname else ""
                    print(f"  • {mission.name}{robot_info}")
                    
            else:
                headers = {'Authorization': f'Bearer {self.access_token}'}
                response = requests.get(f"{self.orbit_url}/api/v1/missions", 
                                        headers=headers, 
                                        verify=self.orbit_verify_cert
                                        )
                
                if response.status_code == 200:
                    missions = response.json().get('missions', [])
                    self.available_missions = {}
                    for mission in missions:
                        mission_obj = Mission(
                            mission_id= mission['id'],
                            mission_name= mission['name'],
                            robot_nickname= mission.get('robot_nickname'),
                            created_at= mission.get('created_at'),
                            mission_type= mission.get('mission_type', None)
                        )
                        
                        self.available_missions[mission['name'].lower()] = mission_obj
                        robot_info = f" (Robot: {mission_obj.robot_nickname})" if mission_obj.robot_nickname else ""
                        print(f"  • {mission['name']}{robot_info}")
            
            if not self.available_missions:
                print("  ⚠️  No missions found in Orbit!")
                print("  💡 Create missions in Orbit:")
                print("     1. Log into Orbit web interface")
                print("     2. Go to Missions → Create New")
                print("     3. Configure your mission")
                print("     4. Save and it will appear here")
            else:
                print(f"  ✓ Loaded {len(self.available_missions)} mission(s)")
            
            return self.available_missions
            
        except Exception as e:
            print(f"✗ Failed to fetch missions: {e}")
            return {}
        
    def mission_dispatcher(self, robot_nickname: str, mission_name: Optional[str] = None) -> bool:
            mission_key = mission_name.lower()
            robot_nickname = robot_nickname.lower()
            print(f"⧗ Dispatching mission '{mission_name}' to robot '{robot_nickname}'...")
            
            
            if mission_key not in self.available_missions:
                print(f"✗ Mission '{mission_name}' not found in Orbit.")
                print(f"\n📋 Available missions:")
                for mission in self.available_missions.values():
                    print(f"   • {mission.name}")
                return False

            mission = self.available_missions[mission_key]

            target_robot = robot_nickname or mission.robot_nickname
            
            if not target_robot or target_robot not in self.available_robots:
                print(f"✗ Robot '{target_robot}' not found in Orbit.")
                print(f"\nAvailable robots:")
                for robot in self.available_robots.values():
                    print(f"   • {robot.nickname}")
                return False

            try:
                print(f"🚀 Dispatching mission: {mission.name}")
                print(f"   Target robot: {target_robot}")
                print(f"   Mission ID: {mission.mission_id}")
                
                if self.orbit_client:
                    # Using Orbit SDK to dispatch
                    self.orbit_client.start_mission(
                        mission_id=mission.mission_id,
                        robot_nickname=target_robot
                    )
                else:
                    # Using REST API to dispatch
                    headers = {'Authorization': f'Bearer {self.access_token}'}
                    dispatch_url = f"{self.orbit_url}/api/v0/missions/{mission.mission_id}/dispatch"
                
                    payload = {
                    'robot_nickname': target_robot
                    }
                
                    response = requests.post(
                        dispatch_url,
                        json=payload,
                        headers=headers,
                        verify=self.verify_cert
                        )
                
                    if response.status_code not in [200, 201, 202]:
                        print(f"✗ Dispatch failed: {response.status_code}")
                        print(f"   {response.text}")
                        return False
            
                    print(f"✓ Mission dispatched successfully!")
                    print(f"💡 Monitor progress in Orbit web interface")
                    return True
            
            except Exception as e:
                print(f"✗ Failed to dispatch mission: {e}")
                return False
    
    def get_mission_status(self, mission_id: str) -> Optional[str]:
        try:
            mission_key = mission_id.lower()
            if mission_key not in self.available_missions:
                return None
            
            mission = self.available_missions[mission_key]
            
            if self.orbit_client:
                return {
                    'mission' : mission.name,
                    'status' : getattr(latest_run, 'status', 'unknown'),
                    'started_at' : getattr(latest_run, 'started_at', None),
                    'robot' : getattr(latest_run, 'robot_nickname', None)
                }
            else:
                headers = {"Authorization": f'Bearer {self.access_token}'}
                response = requests.get(
                    f"{self.orbit_url}/api/v1/missions/{mission.mission_id}/runs",
                    headers=headers,
                    verify=self.orbit_verify_cert
                )
                
                if response.status_code == 200:
                    runs = response.json().get('runs', [])
                    if not runs:
                        return None
                    
                    latest_run = runs[0]
                    return {
                        'mission' : mission.name,
                        'status' : latest_run.get('status', 'unknown'),
                        'started_at' : latest_run.get('started_at', None),
                        'robot' : latest_run.get('robot_nickname', None)
                    }
                    
            return None
        
        except Exception as e:
            print(f"✗ Error fetching mission status: {e}")
            return None

    def startup(self, auth_method: str, **auth_kwargs) -> bool:
        if auth_method == 'password':
            if not self.authenticate_orbit(auth_kwargs.get('username'), auth_kwargs.get('password')):
                return False
        elif auth_method == 'api_token':
            if not self.authenticate_orbit_with_api_token(auth_kwargs.get('api_token')):
                return False
        else:
            print("✗ Invalid authentication method specified.")
            return False
        
        self.get_available_robots()
        self.get_available_missions()
        return True
    
class MissionChatBot:
    def __init__(self, dispatcher: OrbitMissionDispatcher):
        self.dispatcher = dispatcher
        
        self.patterns = [
            # Mission dispatch
            (r"(?:start|run|execute|dispatch|send)\s+(.+?)\s+(?:on|to)\s+(.+)", self._handle_dispatch_to_robot),
            (r"(?:start|run|execute|dispatch)\s+(.+)", self._handle_dispatch),
            
            # Status
            (r"status(?:\s+of)?\s+(.+)", self._handle_mission_status),
            (r"(?:what'?s|check)\s+(?:the\s+)?status", self._handle_general_status),
            
            # Listing
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
        
    def handle_dispatch_to_robot(self, mission_name: str, robot_nickname: str) -> bool:
        mission_name = match.group(1).strip()
        robot_nickname = match.group(2).strip()
        return self.dispatcher.mission_dispatcher(robot_nickname, mission_name)
    
    def handle_dispatch(self, mission_name: str) -> bool:
        mission_name = match.group(1).strip()
        return self.dispatcher.mission_dispatcher("", mission_name)
    
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
                print(f"   • {mission.name}{robot_info}")
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
║   • "dispatch perimeter check to Spot-2"                   ║
║                                                            ║
║ STATUS & INFO:                                             ║
║   • "status of warehouse patrol"                           ║
║   • "list missions"                                        ║
║   • "list robots"                                          ║
╚════════════════════════════════════════════════════════════╝
"""


if __name__ == "__main__":
    import sys
    
    print("╔════════════════════════════════════════════════════════════╗")
    print("║         Orbit Mission Dispatcher - Chatbot Interface       ║")
    print("╚════════════════════════════════════════════════════════════╝\n")
    
    # Configuration
    ORBIT_HOSTNAME = "orbit.example.com"  # Change to your Orbit server
    USE_API_TOKEN = True  # Recommended for automation
    
    # Get Orbit credentials
    print("Orbit Configuration:")
    ORBIT_HOSTNAME = input(f"Orbit hostname [{ORBIT_HOSTNAME}]: ") or ORBIT_HOSTNAME
    
    # Initialize dispatcher
    dispatcher = OrbitMissionDispatcher(
        orbit_hostname=ORBIT_HOSTNAME,
        orbit_verify_cert=True  # Set to False for self-signed certs
    )
    
    try:
        # Authenticate
        if USE_API_TOKEN:
            api_token = input("Orbit API token: ")
            if not dispatcher.startup('token', api_token=api_token):
                sys.exit(1)
        else:
            username = input("Orbit username: ")
            password = input("Orbit password: ")
            if not dispatcher.startup('password', username=username, password=password):
                sys.exit(1)
        
        # Initialize chatbot
        chatbot = MissionChatbot(dispatcher)
        print(chatbot.get_help())
        print("Type 'help' for commands, 'quit' to exit\n")
        
        # Command loop
        while True:
            try:
                user_input = input("🤖 You: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    break
                
                if user_input.lower() == 'help':
                    print(chatbot.get_help())
                    continue
                
                if not user_input:
                    continue
                
                if not chatbot.parse_command(user_input):
                    print("❓ Command not recognized. Type 'help' for examples.\n")
                
            except EOFError:
                break
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    
    finally:
        print("\n👋 Goodbye!\n")


# def chatbot_loop():
#     if authorize_robot(ip, "username", "password") is None:
#         print("Error: Robot authentication failed.")
#         return
#     while True:
#         text = input(">> ").strip()
#         if text.lower() in ['exit', 'quit']:
#             print("Exiting chatbot. Goodbye!")
#             break
        
#         command = process_command(text)
#         if command:
#             print("✔ Parsed command:", command)

#         else:
#             print("✘ Unrecognized command. Please try again.")

# def classify_intent(text):
#     if any(w in text for w in ['power on', 'turn on']):
#         return 'power_on'
#     if any(w in text for w in ['power off', 'shut down']):
#         return 'power_off'
#     if 'stand' in text:
#         return 'stand'
#     if 'sit' in text:
#         return 'sit'
#     if 'self right' in text or 'self-right' in text:
#         return 'selfright'
#     if any(w in text for w in ["walk", "move"]):
#         return "walk"
#     if any(w in text for w in ['start', 'begin', 'initiate','execute','start mission']):
#         return 'start_mission'
#     if any(w in text for w in ['stop', 'halt', 'end', 'terminate', 'stop mission']):
#         return 'stop_mission'
#     if any(w in text for w in ['status', 'state', 'condition']):
#         return 'check_status'
    
#     return None
        
