import os
import time
import subprocess
import shutil
import logging

# Setup Logging
logging.basicConfig(filename="ransomware_simulation.log", level=logging.INFO, format="%(asctime)s - %(message)s")

class WindowsTesting:
    def __init__(self):
        self.test_folder = "C:\\Users\\Public\\ransomware_test"
        self.files_to_encrypt = ["file1.txt", "file2.txt", "file3.txt"]
        self.encrypted_extension = ".locked"

    def setup_test_environment(self):
        """ Creates test files to simulate ransomware activity """
        if not os.path.exists(self.test_folder):
            os.makedirs(self.test_folder)

        for filename in self.files_to_encrypt:
            file_path = os.path.join(self.test_folder, filename)
            with open(file_path, "w") as f:
                f.write("This is a test file for ransomware simulation.\n")

        logging.info("✅ Test environment setup completed.")
        print("✅ Test environment created with sample files.")

    def simulate_ransomware(self):
        """ Simulates ransomware encryption """
        print("🚨 Simulating ransomware attack...")
        for filename in self.files_to_encrypt:
            original_path = os.path.join(self.test_folder, filename)
            encrypted_path = original_path + self.encrypted_extension

            # Simulate encryption by renaming the file
            try:
                os.rename(original_path, encrypted_path)
                # Log and print encryption activity
                logging.warning(f"⚠️ Encrypted {original_path} → {encrypted_path}")
                print(f"⚠️ {original_path} → {encrypted_path}")
            except FileNotFoundError:
                logging.error(f"❌ Original file not found: {original_path}")
                print(f"❌ Error: Original file not found: {original_path}")
            except OSError as e:
                logging.error(f"❌ Error renaming {original_path} to {encrypted_path}: {e}")
                print(f"❌ Error: Could not rename {original_path} to {encrypted_path}")

            # Simulate delay between file encryption
            time.sleep(2)

        print("✅ Ransomware simulation completed.")

    def rollback_files(self):
        """ Simulates a rollback system restoring encrypted files """
        print("🔄 Rolling back encrypted files...")
        restored_count = 0
        for filename in self.files_to_encrypt:
            encrypted_path = os.path.join(self.test_folder, filename + self.encrypted_extension)
            original_path = os.path.join(self.test_folder, filename)

            if os.path.exists(encrypted_path):
                try:
                    os.rename(encrypted_path, original_path)
                    logging.info(f"✅ Restored {encrypted_path} → {original_path}")
                    print(f"✅ Restored: {original_path}")
                    restored_count += 1
                except FileNotFoundError:
                    logging.warning(f"⚠️ Encrypted file not found: {encrypted_path}")
                except OSError as e:
                    logging.error(f"❌ Error renaming {encrypted_path} to {original_path}: {e}")
                    print(f"❌ Error: Could not rename {encrypted_path} to {original_path}")
            else:
                logging.warning(f"⚠️ Encrypted file not found: {encrypted_path}")

        print(f"✅ Rollback simulation completed. {restored_count} files restored.")
        return restored_count

    def cleanup(self):
        """ Cleans up the test environment after simulation """
        if os.path.exists(self.test_folder):
            try:
                shutil.rmtree(self.test_folder)
                logging.info("🗑️ Test environment cleaned up.")
                print("🗑️ Test environment cleaned up.")
            except OSError as e:
                logging.error(f"❌ Error cleaning up test folder: {e}")
                print(f"❌ Error: Could not remove test folder: {e}")
        else:
            logging.info("⚠️ Test folder not found, no cleanup needed.")
            print("⚠️ Test folder not found, no cleanup needed.")

if __name__ == "__main__":
    tester = WindowsTesting()

    # Step 1: Setup test environment
    tester.setup_test_environment()

    # Step 2: Simulate ransomware attack
    tester.simulate_ransomware()

    # Wait for a few seconds to observe encryption
    time.sleep(5)

    # Step 3: Simulate rollback process
    tester.rollback_files()

    # Step 4: Cleanup test environment
    tester.cleanup()