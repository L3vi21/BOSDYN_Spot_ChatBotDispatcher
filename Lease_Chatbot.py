import re
import json
import time
import uuid
import requests
import sys
from typing import Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime
import cv2
import logging
import numpy as np

try:
    from bosdyn.orbit.client import Client as OrbitClient
    SPOT_SDK_AVAILABLE = True
    from bosdyn.client.lease import LeaseClient, LeaseKeepAlive 
    from bosdyn.client.robot import Robot
except ImportError:
    print("⚠️  Orbit SDK not found. Install via: pip install bosdyn-orbit")
    SPOT_SDK_AVAILABLE = False

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
            print("⚠️  Spot SDK not installed - using REST API only")
            print("   (Optional: pip install bosdyn-client bosdyn-mission)")
        
        self.orbit_hostname = orbit_hostname
        self.orbit_url = f"https://{orbit_hostname}"
        self.orbit_verify_cert = orbit_verify_cert
        
        self.orbit_client = None
        self.access_token = None

        self.lease_client = None
        self.lease_keepalive = None
        
        self.available_missions = {}
        self.available_robots = {}

    def probe_robot(self, robot_ip: str, robot_name: str):
        print(f"\n🔍 DIAGNOSTIC: Probing {robot_name} at {robot_ip}...")
 
        try:
            response = requests.get(f"https://{robot_ip}/", verify=False, timeout=3)
            
            if response.status_code == 200:
                print(f"   ✅ PC ➔ ROBOT: SUCCESS! Robot web server is active.")
                print(f"      (This proves your network connection is good)")
            else:
                print(f"   ⚠️ PC ➔ ROBOT: Connected, but got code {response.status_code}")
                
        except requests.exceptions.ConnectTimeout:
            print(f"   ❌ PC ➔ ROBOT: FAILED (Timed Out)")
            print(f"      -> Your computer cannot see {robot_ip}. Check your WiFi!")
            return
        except Exception as e:
            print(f"   ❌ PC ➔ ROBOT: FAILED ({e})")
            return
        
        robot_data = self.available_robots.get(robot_name.lower())
        if robot_data:
            orbit_sees_it = robot_data.get('status')
            if "ONLINE" in orbit_sees_it:
                print(f"   ✅ ORBIT ➔ ROBOT: SUCCESS! Orbit is connected.")
            else:
                print(f"   ❌ ORBIT ➔ ROBOT: FAILED! Orbit says '{orbit_sees_it}'")
                print(f"      -> FIX: Go to Orbit Settings > Robots > Edit > Re-enter Password")
        
    def authenticate(self, username: str, password: str) -> bool:
        try:
            print(f"🔐 Authenticating with Orbit at {self.orbit_hostname}...")
            
            if SPOT_SDK_AVAILABLE:
                self.orbit_client = OrbitClient(self.orbit_hostname, verify=self.orbit_verify_cert)
                self.orbit_client.authenticate(username, password)
                print("✓ Orbit authentication successful (SDK)!")
                return True
            
            else:
                auth_url = f"{self.orbit_url}/api/v0/auth/token"
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
        
    def authenticate_orbit_with_api_token(self, api_token: str):
        try:
            print(f"🔐 Authenticating with Orbit using API token...")

            self.access_token = api_token
            
            if SPOT_SDK_AVAILABLE:
                temp_client = OrbitClient(
                    hostname=self.orbit_hostname,
                    verify=self.orbit_verify_cert,
                    )

                temp_client.token = api_token
                temp_client._session.headers.update(
                    {'Authorization': f'Bearer {api_token}'}
                )
                try:
                    print("   Verifying SDK connection...")
                    # get_system_time is usually a fast, safe check
                    temp_client.get_system_time() 
                    print("✓ SDK Validation Passed!")
                    self.orbit_client = temp_client
                    return True
                except Exception as e:
                    print(f"⚠️ SDK Validation Failed: {e}")
                    print("   (The SDK refused the token, so we will disable the SDK client)")
                    # Kill the client so 'if self.orbit_client' returns False later
                    self.orbit_client = None
                    return True # We still return True because REST mode works
            else:
                print("✓ API token set!")
                return True
                
        except Exception as e:
            print(f"✗ API token authentication error: {e}")
            return False
    def acquire_control(self, robot_nickname: str) -> bool:
        """
        Forcefully takes the lease so the script can work without user logout.
        The user remains in the Orbit Environment but loses robot control.
        """
        if not self.orbit_client:
            print("⚠️ SDK client not initialized. Cannot take lease via REST.")
            return False

        try:
            print(f"⧗ Attempting to acquire sub-lease for {robot_nickname}...")
            
            # 1. Retrieve the robot object from Orbit
            robot_obj = self.orbit_client.get_robot(robot_nickname)
            
            # 2. Initialize the Lease Client for this specific robot
            self.lease_client = robot_obj.ensure_client(LeaseClient.default_service_name)
            
            # 3. 'take' forcefully acquires the lease from any current user/tablet
            self.lease_client.take_lease()
            
            # 4. Background thread to keep the lease active (heartbeat)
            # return_at_exit=True ensures the lease goes back to Orbit when script ends
            self.lease_keepalive = LeaseKeepAlive(self.lease_client, must_acquire=True, return_at_exit=True)
            
            print(f"✅ Control acquired. The user in Orbit has been shifted to 'View Only'.")
            return True
            
        except Exception as e:
            print(f"❌ Sub-lease acquisition failed: {e}")
            return False
        
    def get_available_robots (self) -> Dict[str, str]:
        try:
            print("⧗ Fetching available robots from Orbit...")

            headers = {'Authorization': f'Bearer {self.access_token}'}
            response = requests.get(f"{self.orbit_url}/api/v0/robots", 
                                    headers=headers, 
                                    verify=self.orbit_verify_cert
                                    )
                
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
                    ip_address = robot.get('wifiIpAddress', 'N/A')
                    lease = "Unknown"
                    if 'lease' in robot:
                        lease = robot['lease'].get('holder', 'None')

                    self.available_robots[nickname.lower()] = {
                        'id': robot.get('hostname', robot.get('robotIndex', 'N/A')),
                        'nickname': nickname,
                        'serial_number': robot.get('hostname', 'N/A'),
                        'status': 'paired' if robot.get('paired', False) else 'unpaired',
                        'ip' : ip_address
                        }
                    print(f"  • {nickname} ({robot.get('ipEthernet', 'N/A')})")
                    print(f"  • {nickname} ({ip_address}) | Lease: {lease}")
                
                    # --- NEW: Run the Probe ---
                    if ip_address and ip_address != 'N/A':
                        self.probe_robot(ip_address, nickname)
                    
        
            print(f"  ✓ Found {len(self.available_robots)} robot(s)")
            return self.available_robots
        
        except Exception as e:
            print(f"✗ Error fetching robots: {e}")
            return {}      
        
    def get_available_missions(self) -> Dict[str, Mission]:
        self.available_missions = {}
        try:
            print("⧗ Fetching available missions from Orbit...")

            if self.orbit_client:
                missions = self.orbit_client.get_site_walks()

                for mission in missions:

                    raw_name = mission.get('name')
                    m_name = raw_name if raw_name else "Unnamed Mission"

                    mission_obj = Mission(
                        mission_id=mission.id,
                        mission_name=m_name,
                        robot_nickname=mission.robot_nickname,
                        created_at=mission.created_at,
                        mission_type=mission.mission_type
                    )
                        
                    self.available_missions[m_name.lower()] = mission_obj
                    robot_info = f" (Robot: {mission_obj.robot_nickname})" if mission_obj.robot_nickname else ""
                    print(f"  • {m_name}{robot_info}")
            else:       
                headers = {'Authorization': f'Bearer {self.access_token}'}
                response = requests.get(
                    f"{self.orbit_url}/api/v0/site_walks", 
                    headers=headers, 
                    verify=self.orbit_verify_cert,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # print(f"DEBUG: API Response type: {type(data)}")
                    # print(f"DEBUG: API Response: {data}")

                    missions = data if isinstance(data, list) else data.get('missions', [])
                    self.available_missions = {}
                    for mission in missions:

                        raw_name = mission.get('name')
                        m_name = raw_name if raw_name else "Unnamed Mission"

                        # print(f"DEBUG: Processing mission: {mission}")
                        mission_obj = Mission(  # ← Fixed indentation
                            mission_id=mission['uuid'],
                            mission_name=m_name,
                            robot_nickname=mission.get('robot_nickname'),
                            created_at=mission.get('created_at'),
                            mission_type=mission.get('mission_type', None)
                        )

                        self.available_missions[m_name.lower()] = mission_obj
                        robot_info = f" (Robot: {mission_obj.robot_nickname})" if mission_obj.robot_nickname else ""
                        print(f"  • {m_name}{robot_info}")

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
            import traceback
            traceback.print_exc()  # This helps debug
            return {}
        
    def mission_dispatcher(self, robot_nickname: str, mission_name: Optional[str] = None) -> bool:
            mission_key = mission_name.lower()
            robot_nickname = robot_nickname.lower()
            print(f"⧗ Dispatching mission '{mission_name}' to robot '{robot_nickname}'...")
            
            
            if mission_key not in self.available_missions:
                print(f"✗ Mission '{mission_name}' not found in Orbit.")
                print(f"\n📋 Available missions:")
                for mission in self.available_missions.values():
                    print(f"   • {mission}")
                return False

            mission = self.available_missions[mission_key]
            target_robot = robot_nickname or mission.robot_nickname
            
            if not target_robot or target_robot not in self.available_robots:
                print(f"✗ Robot '{target_robot}' not found in Orbit.")
                print(f"\nAvailable robots:")

            robot_hostname = self.available_robots[target_robot]['id']

            unique_request_id = str(uuid.uuid4())
            current_time_ms = int(time.time() * 1000)
            request_name = f"Run-{mission.mission_name}-{current_time_ms}-{unique_request_id}"

            driver_id = unique_request_id
            dispatch_url = f"{self.orbit_url}/api/v0/calendar/mission/dispatch/{target_robot}?currentDriverId={driver_id}"

            payload = {
                "agent": {
                    "nickname": target_robot,
                },
                "schedule" : {
                    "timeMs" : {
                        "low" : 1,
                        "high" : 0,
                        "unsigned" : False
                    },
                    "repeatMs" : {
                        "low" : 0,
                        "high" : 0,
                        "unsigned" : False
                    } 
                },
                "task" : {
                    "dispatchTarget" : {
                        "missionId" : mission.mission_id
                    },
                    "forceAcquireEstop" : True,
                    "forceAcquireLease" : True,
                    "skipInitialization": False,
                    "requireDocked": False
                },
                "eventMetadata": {
                    "name": f"Manual Dispatch ({driver_id})"
                }
            }
            
            print(f" ⧗ Sending Calendar Dispatch to: {dispatch_url}")

            try:
                # Using REST API to dispatch
                headers = {'Authorization': f'Bearer {self.access_token}'}
                
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
            if not self.authenticate(auth_kwargs.get('username'), auth_kwargs.get('password')):
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
            (r"(?:take|acquire)\s+control\s+(?:of\s+)?(.+)", self._handle_take_control),
        ]
                 
    def parse_command(self, user_input: str) -> bool:
        user_input = user_input.strip()
        
        for pattern, handler in self.patterns:
            match = re.match(pattern, user_input, re.IGNORECASE)
            if match:
                return handler(match, user_input)
        return False
        
    def _handle_dispatch_to_robot(self, match, raw_cmd):
        mission_name = match.group(1).strip()
        robot_nickname = match.group(2).strip()
        return self.dispatcher.mission_dispatcher(robot_nickname, mission_name)
    
    def _handle_dispatch(self, match, raw_cmd):
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
    def _handle_take_control(self, match, raw_cmd) -> bool:
        """
        Handler for the 'take control of [robot]' command.
        Triggers the sub-lease acquisition in the dispatcher.
        """
        robot_nickname = match.group(1).strip()
        success = self.dispatcher.acquire_control(robot_nickname)
        
        if success:
            print(f"🛠️ System: Control of '{robot_nickname}' is now held by this script.")
        else:
            print(f"❌ System: Could not acquire control of '{robot_nickname}'.")
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
        orbit_verify_cert=False  # Set to False for self-signed certs
    )
    
    try:
        # Authenticate
        if USE_API_TOKEN:
            api_token = input("Orbit API token: ")
            if not dispatcher.startup('api_token', api_token=api_token):
                sys.exit(1)
        else:
            username = input("Orbit username: ")
            password = input("Orbit password: ")
            if not dispatcher.startup('password', username=username, password=password):
                sys.exit(1)
        
        # Initialize chatbot
        chatbot = MissionChatBot(dispatcher)
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
