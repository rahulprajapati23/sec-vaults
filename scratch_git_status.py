import subprocess

try:
    result = subprocess.run(["git", "status"], capture_output=True, text=True, check=True)
    print(result.stdout)
except Exception as e:
    print(f"Error: {e}")
