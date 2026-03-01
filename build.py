"""
Build SecureAccess into a standalone executable using PyInstaller.
Run: python build.py
"""
import subprocess
import sys
import os

def build():
    print("🛡️  Building SecureAccess...")
    print("=" * 50)

    # Install dependencies
    print("\n📦 Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

    # Build with PyInstaller
    print("\n🔨 Building executable...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=SecureAccess",
        "--onefile",
        "--windowed",
        "--add-data", f"database.py{os.pathsep}.",
        "--icon=NONE",
        "--clean",
        "app.py"
    ]
    subprocess.check_call(cmd)

    print("\n✅ Build complete!")
    print(f"   Executable: dist/SecureAccess{'.exe' if os.name == 'nt' else ''}")
    print("   Share this file — it runs on any machine without Python installed.")

if __name__ == "__main__":
    build()
