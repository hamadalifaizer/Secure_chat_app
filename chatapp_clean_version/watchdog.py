import subprocess
import time
import signal
import os
import psutil

server_script = 'server.py'
max_restarts = 5

def start_server():
    return subprocess.Popen(['python', server_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def terminate_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()  # Send terminate signal
        process.wait(timeout=10)  # Wait for process to terminate
    except psutil.NoSuchProcess:
        pass
    except psutil.TimeoutExpired:
        process.kill()  # Force kill if not terminated

def main():
    restart_count = 0
    process = start_server()

    while restart_count < max_restarts:
        process.poll()  # Check if process has exited
        if process.returncode is not None:  # Process has exited
            print("Server crashed or stopped. Shutting down all processes and restarting...")
            terminate_process(process.pid)  # Terminate the existing process
            restart_count += 1
            process = start_server()  # Restart the server
        time.sleep(5)  # Check every 5 seconds

    print("Server has crashed multiple times. Exiting.")
    # Optionally: send an alert or take additional actions here

if __name__ == '__main__':
    main()
