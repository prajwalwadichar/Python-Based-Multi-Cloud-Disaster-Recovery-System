
import datetime
import hashlib
import logging
import os
import shutil
import sys
import json
import schedule
import time
import threading
import cryptography.fernet
from azure.storage.blob import BlobServiceClient
from google.cloud import storage
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Configure enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler('disaster_recovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CloudProvider(Enum):
    AWS = 'aws'
    AZURE = 'azure'
    GCP = 'gcp'

@dataclass
class RecoveryPoint:
    id: str
    timestamp: datetime.datetime
    size: int
    description: str = ""
    tags: Dict[str, str] = None

class DisasterRecoverySystem:
    def __init__(self, config_path: str = 'config.json'):
        """
        Initialize the enhanced disaster recovery system
        """
        self.config = self.load_config(config_path)
        self.encryption_key = self.setup_encryption()
        self.backup_providers = {
            CloudProvider.AWS: self.backup_to_aws,
            CloudProvider.AZURE: self.backup_to_azure,
            CloudProvider.GCP: self.backup_to_gcp
        }
        self.recovery_providers = {
            CloudProvider.AWS: self.recover_from_aws,
            CloudProvider.AZURE: self.recover_from_azure,
            CloudProvider.GCP: self.recover_from_gcp
        }
        self.validate_config()
        self.scheduler_thread = None
        self.running = False
        
    def load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(config_path) as f:
                config = json.load(f)
            
            # Convert provider string to enum
            config['backup_provider'] = CloudProvider(config['backup_provider'].lower())
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
            raise

    def setup_encryption(self) -> Optional[cryptography.fernet.Fernet]:
        """Setup encryption if enabled in config"""
        if self.config.get('encryption_enabled', False):
            key = self.config.get('encryption_key')
            if not key:
                key = cryptography.fernet.Fernet.generate_key()
                logger.warning("No encryption key provided. Generated a new one. "
                              "Store this securely for recovery: " + key.decode())
            return cryptography.fernet.Fernet(key)
        return None

    def validate_config(self):
        """Validate configuration parameters"""
        required_params = ['backup_provider', 'backup_paths', 'retention_days']
        for param in required_params:
            if param not in self.config:
                raise ValueError(f"Missing required configuration parameter: {param}")

    def encrypt_file(self, file_path: str) -> str:
        """Encrypt a file if encryption is enabled"""
        if not self.encryption_key:
            return file_path
            
        encrypted_path = file_path + '.enc'
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = self.encryption_key.encrypt(data)
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            os.remove(file_path)
            logger.info(f"Encrypted backup file: {encrypted_path}")
            return encrypted_path
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise

    def decrypt_file(self, file_path: str) -> str:
        """Decrypt a file if encryption is enabled"""
        if not self.encryption_key:
            return file_path
            
        decrypted_path = file_path.replace('.enc', '')
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.encryption_key.decrypt(encrypted_data)
            
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"Decrypted backup file: {decrypted_path}")
            return decrypted_path
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise

    def create_backup(self) -> Optional[str]:
        """Create an encrypted backup of configured files/directories"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = f"backup_{timestamp}"
            os.makedirs(backup_dir, exist_ok=True)
            
            # Backup each path
            for path in self.config['backup_paths']:
                dest = os.path.join(backup_dir, os.path.basename(path))
                if os.path.isfile(path):
                    shutil.copy2(path, dest)
                elif os.path.isdir(path):
                    shutil.copytree(path, dest)
            
            # Create metadata file
            metadata = {
                'timestamp': timestamp,
                'system': os.uname()._asdict(),
                'files': [os.path.basename(p) for p in self.config['backup_paths']],
                'config_hash': hashlib.sha256(json.dumps(self.config).encode()).hexdigest()
            }
            with open(os.path.join(backup_dir, 'metadata.json'), 'w') as f:
                json.dump(metadata, f)
            
            # Compress the backup
            backup_archive = f"{backup_dir}.zip"
            shutil.make_archive(backup_dir, 'zip', backup_dir)
            
            # Clean up temporary directory
            shutil.rmtree(backup_dir)
            
            # Encrypt if enabled
            if self.encryption_key:
                backup_archive = self.encrypt_file(backup_archive)
            
            logger.info(f"Created backup archive: {backup_archive}")
            return backup_archive
            
        except Exception as e:
            logger.error(f"Backup creation failed: {str(e)}")
            return None

    def backup_to_cloud(self, backup_file: str) -> bool:
        """Upload encrypted backup to configured cloud provider"""
        try:
            provider = self.config['backup_provider']
            if provider not in self.backup_providers:
                raise ValueError(f"Unsupported cloud provider: {provider}")
            
            return self.backup_providers[provider](backup_file)
        except Exception as e:
            logger.error(f"Cloud backup failed: {str(e)}")
            return False

    def backup_to_aws(self, backup_file: str) -> bool:
        """Upload backup to AWS S3 with enhanced features"""
        try:
            s3 = boto3.client(
                's3',
                aws_access_key_id=self.config['aws_access_key'],
                aws_secret_access_key=self.config['aws_secret_key']
            )
            
            bucket_name = self.config.get('aws_bucket', 'disaster-recovery-backups')
            object_name = os.path.basename(backup_file)
            
            # Upload with metadata and storage class
            extra_args = {
                'Metadata': {
                    'backup-system': 'python-dr',
                    'encrypted': str(bool(self.encryption_key))
                },
                'StorageClass': 'STANDARD_IA'  # Lower cost for infrequent access
            }
            
            s3.upload_file(
                backup_file,
                bucket_name,
                object_name,
                ExtraArgs=extra_args
            )
            
            logger.info(f"Backup uploaded to AWS S3: {bucket_name}/{object_name}")
            return True
        except Exception as e:
            logger.error(f"AWS backup failed: {str(e)}")
            return False

    def backup_to_azure(self, backup_file: str) -> bool:
        """Upload backup to Azure Blob Storage with enhanced features"""
        try:
            blob_service = BlobServiceClient.from_connection_string(
                self.config['azure_connection_string'])
            container_name = self.config.get('azure_container', 'disaster-recovery')
            blob_name = os.path.basename(backup_file)
            
            # Create container if not exists
            container_client = blob_service.get_container_client(container_name)
            if not container_client.exists():
                container_client.create_container()
                logger.info(f"Created Azure container: {container_name}")
            
            # Upload blob with metadata
            blob_client = container_client.get_blob_client(blob_name)
            metadata = {
                'backup-system': 'python-dr',
                'encrypted': str(bool(self.encryption_key))
            }
            
            with open(backup_file, "rb") as data:
                blob_client.upload_blob(data, metadata=metadata)
            
            logger.info(f"Backup uploaded to Azure: {container_name}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"Azure backup failed: {str(e)}")
            return False

    def backup_to_gcp(self, backup_file: str) -> bool:
        """Upload backup to Google Cloud Storage with enhanced features"""
        try:
            storage_client = storage.Client.from_service_account_json(
                self.config['gcp_credentials'])
            bucket_name = self.config.get('gcp_bucket', 'disaster-recovery-backups')
            blob_name = os.path.basename(backup_file)
            
            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(blob_name)
            
            # Set metadata
            blob.metadata = {
                'backup-system': 'python-dr',
                'encrypted': str(bool(self.encryption_key))
            }
            
            # Use nearline storage class for cost savings
            blob.storage_class = 'NEARLINE'
            
            blob.upload_from_filename(backup_file)
            
            logger.info(f"Backup uploaded to GCP: {bucket_name}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"GCP backup failed: {str(e)}")
            return False

    def list_recovery_points(self) -> List[RecoveryPoint]:
        """List available recovery points from cloud storage"""
        provider = self.config['backup_provider']
        if provider not in self.recovery_providers:
            raise ValueError(f"Unsupported cloud provider: {provider}")
        
        return self.recovery_providers[provider](list_only=True)

    def recover_from_backup(self, recovery_point_id: str, destination: str = None) -> bool:
        """Recover from a specific backup point"""
        provider = self.config['backup_provider']
        if provider not in self.recovery_providers:
            raise ValueError(f"Unsupported cloud provider: {provider}")
        
        return self.recovery_providers[provider](
            recovery_point_id=recovery_point_id,
            destination=destination
        )

    def recover_from_aws(self, recovery_point_id: str = None, 
                        destination: str = None, list_only: bool = False):
        """Recovery implementation for AWS"""
        s3 = boto3.client(
            's3',
            aws_access_key_id=self.config['aws_access_key'],
            aws_secret_access_key=self.config['aws_secret_key']
        )
        bucket_name = self.config.get('aws_bucket', 'disaster-recovery-backups')
        
        if list_only:
            # List all recovery points
            response = s3.list_objects_v2(Bucket=bucket_name)
            recovery_points = []
            
            for obj in response.get('Contents', []):
                if obj['Key'].startswith('backup_'):
                    recovery_points.append(RecoveryPoint(
                        id=obj['Key'],
                        timestamp=obj['LastModified'],
                        size=obj['Size'],
                        tags={'storage_class': obj.get('StorageClass', 'STANDARD')}
                    ))
            
            return recovery_points
        
        # Actual recovery
        if not recovery_point_id:
            raise ValueError("Recovery point ID must be specified")
        
        local_path = destination or recovery_point_id
        s3.download_file(bucket_name, recovery_point_id, local_path)
        
        # Decrypt if needed
        if local_path.endswith('.enc'):
            local_path = self.decrypt_file(local_path)
        
        # Extract the backup
        shutil.unpack_archive(local_path, os.path.splitext(local_path)[0])
        logger.info(f"Recovered files to: {os.path.splitext(local_path)[0]}")
        return True

    # Similar implementations for Azure and GCP would go here
    # (omitted for brevity but would follow the same pattern)

    def start_scheduled_backups(self):
        """Start the scheduled backup job based on configuration"""
        if not self.config.get('schedule'):
            logger.warning("No backup schedule configured")
            return
        
        schedule_config = self.config['schedule']
        
        if schedule_config.get('daily'):
            schedule.every().day.at(schedule_config['daily']).do(self.run_backup_job)
        elif schedule_config.get('hourly'):
            schedule.every().hour.do(self.run_backup_job)
        elif schedule_config.get('weekly'):
            schedule.every().week.do(self.run_backup_job)
        
        logger.info("Starting backup scheduler")
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler)
        self.scheduler_thread.start()

    def _run_scheduler(self):
        """Internal method to run the scheduler"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

    def stop_scheduled_backups(self):
        """Stop the scheduled backup job"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        logger.info("Backup scheduler stopped")

    def run_backup_job(self):
        """Run a complete backup job with notification"""
        logger.info("Starting scheduled backup job")
        try:
            backup_file = self.create_backup()
            if backup_file and self.backup_to_cloud(backup_file):
                self.cleanup_old_backups()
                self.send_notification("Backup completed successfully")
                return True
        except Exception as e:
            logger.error(f"Backup job failed: {str(e)}")
            self.send_notification(f"Backup failed: {str(e)}", error=True)
        return False

    def send_notification(self, message: str, error: bool = False):
        """Send notification about backup status"""
        if not self.config.get('notifications'):
            return
        
        # TODO: Implement email/SMS/webhook notifications
        # This would use the configured notification methods
        
        level = "ERROR" if error else "INFO"
        logger.info(f"Notification ({level}): {message}")

    def cleanup_old_backups(self):
        """Clean up old backups based on retention policy"""
        retention_days = self.config['retention_days']
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
        
        # Clean local backups
        for file in os.listdir('.'):
            if file.startswith('backup_') and (file.endswith('.zip') or file.endswith('.enc')):
                file_date_str = file[7:].split('.')[0]  # Extract timestamp
                try:
                    file_date = datetime.datetime.strptime(file_date_str, "%Y%m%d_%H%M%S")
                    if file_date < cutoff_date:
                        os.remove(file)
                        logger.info(f"Removed old local backup: {file}")
                except ValueError:
                    continue
        
        # TODO: Implement cloud backup cleanup
        # This would require provider-specific implementations

    def monitor_system(self):
        """Monitor system health and resources"""
        # TODO: Implement comprehensive monitoring
        # This could check disk space, memory, network connectivity, etc.
        pass

class DisasterRecoveryCLI:
    """Command Line Interface for the Disaster Recovery System"""
    
    def __init__(self, dr_system: DisasterRecoverySystem):
        self.dr_system = dr_system
        self.commands = {
            'backup': self.run_backup,
            'list': self.list_recovery_points,
            'recover': self.run_recovery,
            'schedule': self.manage_schedule,
            'monitor': self.run_monitoring,
            'help': self.show_help,
            'exit': None
        }
    
    def run(self):
        """Run the CLI interface"""
        print("Disaster Recovery System - Command Line Interface")
        self.show_help()
        
        while True:
            try:
                command = input("\nDR> ").strip().lower()
                if command == 'exit':
                    break
                
                if command in self.commands:
                    self.commands[command]()
                else:
                    print("Invalid command. Type 'help' for available commands.")
            except Exception as e:
                print(f"Error: {str(e)}")
    
    def run_backup(self):
        """Execute backup command"""
        print("Starting backup process...")
        if self.dr_system.run_backup_job():
            print("Backup completed successfully!")
        else:
            print("Backup failed. Check logs for details.")
    
    def list_recovery_points(self):
        """List available recovery points"""
        print("Fetching recovery points...")
        points = self.dr_system.list_recovery_points()
        
        if not points:
            print("No recovery points found")
            return
        
        print("\nAvailable Recovery Points:")
        for i, point in enumerate(points, 1):
            print(f"{i}. {point.id} ({point.timestamp}) - {point.size/1024:.2f} KB")
    
    def run_recovery(self):
        """Execute recovery command"""
        self.list_recovery_points()
        points = self.dr_system.list_recovery_points()
        
        if not points:
            return
        
        try:
            choice = int(input("Select recovery point (number): "))
            if 1 <= choice <= len(points):
                destination = input("Recovery destination path (optional): ").strip()
                if not destination:
                    destination = None
                
                print(f"Recovering {points[choice-1].id}...")
                if self.dr_system.recover_from_backup(points[choice-1].id, destination):
                    print("Recovery completed successfully!")
                else:
                    print("Recovery failed. Check logs for details.")
            else:
                print("Invalid selection")
        except ValueError:
            print("Please enter a valid number")
    
    def manage_schedule(self):
        """Manage backup schedule"""
        current_schedule = self.dr_system.config.get('schedule', {})
        
        print("\nCurrent Backup Schedule:")
        if current_schedule.get('daily'):
            print(f"Daily at {current_schedule['daily']}")
        elif current_schedule.get('hourly'):
            print("Hourly")
        elif current_schedule.get('weekly'):
            print("Weekly")
        else:
            print("No schedule configured")
        
        print("\nOptions:")
        print("1. Enable daily backups")
        print("2. Enable hourly backups")
        print("3. Disable scheduling")
        print("4. Return to main menu")
        
        try:
            choice = int(input("Select option: "))
            if choice == 1:
                time = input("Enter time (HH:MM): ")
                self.dr_system.config['schedule'] = {'daily': time}
                print("Daily schedule set. Restart scheduler to apply changes.")
            elif choice == 2:
                self.dr_system.config['schedule'] = {'hourly': True}
                print("Hourly schedule set. Restart scheduler to apply changes.")
            elif choice == 3:
                self.dr_system.config.pop('schedule', None)
                print("Scheduling disabled. Restart scheduler to apply changes.")
            elif choice == 4:
                return
            else:
                print("Invalid option")
        except ValueError:
            print("Please enter a valid number")
    
    def run_monitoring(self):
        """Run system monitoring"""
        print("System monitoring not fully implemented yet")
        # TODO: Implement monitoring display
    
    def show_help(self):
        """Display help information"""
        print("\nAvailable Commands:")
        print("backup   - Run a manual backup")
        print("list     - List available recovery points")
        print("recover  - Recover from a backup")
        print("schedule - Configure backup scheduling")
        print("monitor  - Show system monitoring")
        print("help     - Show this help message")
        print("exit     - Exit the program")

if __name__ == "__main__":
    try:
        # Initialize the disaster recovery system
        dr_system = DisasterRecoverySystem()
        
        # Start scheduled backups if configured
        if dr_system.config.get('schedule'):
            dr_system.start_scheduled_backups()
        
        # Start the CLI interface
        cli = DisasterRecoveryCLI(dr_system)
        cli.run()
        
        # Clean up when exiting
        dr_system.stop_scheduled_backups()
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)