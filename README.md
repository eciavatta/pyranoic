pyranoic
==

High-level network analyzer created for the CyberChallenge attack/defense competition by the Unibo team

### Features
- Capture raw packets from a local or remote source (via ssh) and save them in chunks
- Apply a filter function to the raw packet stream to isolate the desired packets
- Apply a preset to the packet flow (for now only tcp and http) and associate an evaluation function with high-level
conversations
- It allows to write the filter function and the evaluation function in Python
- It can analyze conversations that occurred in the past by selecting a desired time interval


## Getting started

### Installation
Clone the repository locally and position yourself in the project root.
Install the tool in user space using pip (Python 3 is required)

```bash
pip3 install .
```

### Usage
Create a new folder and initialize a new project.
```bash
mkdir myproject
pyranoic init
```

Provide guidance on the interface to capture. If it is a remote capture, enter the remote server interface, and provide
credentials to log in via ssh.

You are now ready to start the capture.
```bash
pyranoic run
```

Use `-d` argument to run the capture as daemon.

Create a new service to monitor
```bash
pyranoic service --create myservice
```

and start monitoring it
```bash
pyranoic watch myservice
```

Done! A Python REPL console opens and you can use the `commands()` command to see the list of available commands with
an associated description.

Good luck!
