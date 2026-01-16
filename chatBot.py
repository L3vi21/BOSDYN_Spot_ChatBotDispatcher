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
                self.available_robots[robot_nickname.lower()] = {
                    'id': robot.robot_id, 
                    'nickname': robot.nickname,
                    'serial_number': robot.serial_number,
                    'state': getattr(robot, 'status', 'unknown')}
                
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
        
    def mission_dispatcher(self, robot_nickname: str, mission_name: str) -> bool:
        try:
            
            mission_name = mission_name.lower()
            robot_nickname = robot_nickname.lower()
            print(f"⧗ Dispatching mission '{mission_name}' to robot '{robot_nickname}'...")
            
            if mission_key not in self.available_missions:
            print(f"✗ Mission '{mission_name}' not found in Orbit.")
            print(f"\n📋 Available missions:")
            for mission in self.available_missions.values():
                print(f"   • {mission.name}")
            return False
            
            mission = self.available_missions[mission_name]
            
            target_roobot = robot_nickname or mission.robot_nickname
            
            if not target_robot or target_robot not in self.available_robots:
                

            
                    

    
    def connect(self):
        try:
            self.sdk = create_standard_sdk('SpotMissionDispatcher')
            self.robot = self.sdk.create_robot(self.hostname)
            
            self.robot.authenticate(self.username, self.password)
            self.robot.sync_with_directory()
            self.robot.time_sync.wait_for_sync()
        
            robot_id = self.robot.get_id()
            print(f"✓ Connected to: {robot_id.nickname} (Serial: {robot_id.serial_number})")
        
            self.is_connected = True
            return True
        
        except RpcError as e:
            print(f"✗ Connection failed: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
        
    def setup_mission_clients(self):
        if not self.is_connected:
            print("✗ Cannot setup mission clients: Not connected to robot.")
            return False
        try:
            self.lease_client = self.robot.ensure_client(LeaseClient.default_service_name)
            self.estop_client = self.robot.ensure_client(EstopClient.default_service_name)
            self.robot_state_client = self.robot.ensure_client(RobotStateClient.default_service_name)
            
            self.autowalk_client = self.robot.ensure_client(AutowalkClient.default_service_name)
            self.graph_nav_client = self.robot.ensure_client(GraphNavClient.default_service_name)
            self.mission_client = self.robot.ensure_client(MissionClient.default_service_name)
            
        print("✓ Mission clients initialized successfully.")
        return True

    except Exception as e:
            print(f"✗ Unexpected error during client setup: {e}")
            return False
        
    def acquire_control(self):
        try:
            #Setup Lease
            self.lease = self.lease_client.acquire()
            self.lease_keepalive = LeaseKeepAlive(self.lease_client)
            print("✓ Lease acquired successfully.")
            
            #Setup Estop
            estop_endpoint = EstopEndpoint(self.estop_client, 'SpotMissionDispatcherEstop', 9.0)
            estop_endpoint.force_simple_setup()
            self.estop_keepalive = EstopKeepAlive(estop_endpoint)
            
            print("⧗ Acquiring lease...")
            return True
        
        except bosdyn.client.lease.ResourceAlreadyClaimedError:
            print("✗ Another client has control of the robot.")
            print("  Use the tablet or admin console to release the lease.")
            return False
        except Exception as e:
            print(f"✗ Unexpected error during lease acquisition: {e}")
            return None
    
    def setup_estop(self):
        if not self.estop_client:
            print("✗ Cannot setup estop: Estop client not initialized.")
            return False
        
        try:
            estop_endpoint = bosdyn.client.estop.EstopEndpoint(self.estop_client, 'SpotChatbotEstop', 9.0)
            estop_endpoint.force_simple_setup()
            
            self.estop_keepalive = bosdyn.client.estop.EstopKeepAlive(estop_endpoint)
            print("✓ Estop endpoint set up successfully.")
            return True
        
        except Exception as e:
            print(f"✗ Unexpected error during estop setup: {e}")
            return False
        
    def power_on(self):
        if not self.power_client:
            print("✗ Cannot power on: Power client not initialized.")
            return False
        
        try:
            print("⧗ Powering on robot...")
            self.power_client.power_on(timeout_sec=20)
            self.is_powered_on = True
            print("✓ Robot powered on successfully.")
            return True
        
        except Exception as e:
            print(f"✗ Unexpected error during power on: {e}")
            return False
        
    def power_off(self):
        if not self.power_client:
            print("✗ Cannot power off: Power client not initialized.")
            return False
        
        try:
            print("⧗ Powering off robot...")
            self.power_client.power_off(cut_immediately=False,timeout_sec=20)
            self.is_powered_on = False
            print("✓ Robot powered off successfully.")
            return True
        
        except Exception as e:
            print(f"✗ Unexpected error during power off: {e}")
            return False
        
    def get_robot_state(self):
        if not self.robot_state_client:
            print("✗ Cannot get robot state: Robot state client not initialized.")
            return None
        
        try:
            state = self.robot_state_client.get_robot_state()
            return state
        
        except Exception as e:
            print(f"✗ Unexpected error getting robot state: {e}")
            return None
        
    def full_startup(self):
        if not self.connect():
            return False
        if not self.setup_clients():
            return False
        if not self.acquire_lease():
            return False
        if not self.setup_estop():
            return False
        return True
    
    def shutdown(self):
        if self.is_powered_on:
            self.power_off()
        
        if self.lease_keepalive:
            self.lease_keepalive.shutdown()
        
        if self.lease_client and self.lease:
            self.lease_client.return_lease(self.lease)
            print("✓ Lease returned")
        
        if self.estop_keepalive:
            self.estop_keepalive.shutdown()
            
        print("✓ Shutdown complete")
        
    def __enter__(self):
        self.full_startup()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
        
class missionDispatcher:
    def __innit__(self, robot):
        self.mission_client = robot.ensure_client(MissionClient.default_service_name)
        self.active_mission = None
        
        """
        Initialize Spot Mission Dispatcher
        
        Args:
            hostname: IP address of Spot (e.g., "192.168.80.3")
            username: Username for authentication
            password: Password for authentication
        """
        
        if not SPOT_SDK_AVAILABLE:
            raise ImportError("Spot SDK is not available. Please install the bosdyn-client package.")
        
        self.hostname = hostname
        self.username = username
        self.password = password
        
        
        
class spotChatBot():
    def __init__(self, robot):
        self.patterns = {
            
        }
    

    

def authorize_robot(ip, username, password):
    
    robot = spot_Connection(ip, username, password).create_robot(ip)
    
    if robot is None:
        return None


    authenticate(robot, username, password)
    return robot

def chatbot_loop():
    if authorize_robot(ip, "username", "password") is None:
        print("Error: Robot authentication failed.")
        return
    while True:
        text = input(">> ").strip()
        if text.lower() in ['exit', 'quit']:
            print("Exiting chatbot. Goodbye!")
            break
        
        command = process_command(text)
        if command:
            print("✔ Parsed command:", command)

        else:
            print("✘ Unrecognized command. Please try again.")

def normalize_text(text):
    return text.lower().strip()

def classify_intent(text):
    if any(w in text for w in ['power on', 'turn on']):
        return 'power_on'
    if any(w in text for w in ['power off', 'shut down']):
        return 'power_off'
    if 'stand' in text:
        return 'stand'
    if 'sit' in text:
        return 'sit'
    if 'self right' in text or 'self-right' in text:
        return 'selfright'
    if any(w in text for w in ["walk", "move"]):
        return "walk"
    if any(w in text for w in ['start', 'begin', 'initiate','execute','start mission']):
        return 'start_mission'
    if any(w in text for w in ['stop', 'halt', 'end', 'terminate', 'stop mission']):
        return 'stop_mission'
    if any(w in text for w in ['status', 'state', 'condition']):
        return 'check_status'
    
    return None

#robot_command(command, end_time_secs=None, timesync_endpoint=None, lease=None, **kwargs)
#play_mission(pause_time_secs, leases=[], settings=None, **kwargs)
def build_spot_command(intent, text):
    command = {'intent': intent}
    
    if intent == 'stand':
        return {
            "category": "mobility",
            "rpc": "stand",
            "builder": RobotCommandBuilder.stand_command
        }
        
    if intent == 'sit':
        return {
            "category": "mobility",
            "rpc": "sit",
            "builder": RobotCommandBuilder.sit_command
        }
        
    if intent == 'selfright':
        return {
            "category": "mobility",
            "rpc": "selfright",
            "builder": RobotCommandBuilder.selfright_command
        }

    if intent == 'power_on':
        return {
            "category": "power",
            "rpc": "power_on",
            "builder": RobotCommandBuilder.power_on_command
        }

    if intent == 'power_off':
        return {
            "category": "power",
            "rpc": "power_off",
            "builder": RobotCommandBuilder.power_off_command
        }
            
            
class ChatBot:
    def __init__(self):
        self.commands = {
            'action' : 'start_mission',
            'Status'  : 'check_status',
            'Help'    : 'show_help'
            'robot' : 'robot_info'
            
        }