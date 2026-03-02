# Deployment Guide — SecureAccess

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Required for `str | None` union syntax |
| pip | 22+ | Package installer |
| tkinter | stdlib | Included with most Python installations |
| Git | Any | For source installation |

On **Ubuntu/Debian**, tkinter must be installed separately:
```bash
sudo apt-get install python3-tk
```

On **Fedora/RHEL**:
```bash
sudo dnf install python3-tkinter
```

On **macOS** (Homebrew Python):
```bash
brew install python-tk@3.11
```

---

## Installation from Source

### 1. Clone the Repository

```bash
git clone https://github.com/Toddni8022/SecureAccess.git
cd SecureAccess
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv

# Activate:
source .venv/bin/activate        # macOS / Linux
.venv\Scripts\activate           # Windows (Command Prompt)
.venv\Scripts\Activate.ps1       # Windows (PowerShell)
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Launch the Application

```bash
python app.py
```

On first launch, SecureAccess will:
1. Create the database directory (`~/.local/share/SecureAccess/` on Linux/macOS, `%LOCALAPPDATA%\SecureAccess\` on Windows)
2. Initialize the SQLite database with default roles, users, and password policy
3. Open the main application window

---

## Building Standalone Executables

SecureAccess uses [PyInstaller](https://pyinstaller.org/) to produce single-file executables that require no Python installation on the target machine.

### Prerequisites

```bash
pip install pyinstaller
pip install -r requirements.txt
```

### Build

```bash
python build.py
```

The executable will be created in the `dist/` directory:

| Platform | Output |
|----------|--------|
| Windows | `dist/SecureAccess.exe` |
| macOS | `dist/SecureAccess` |
| Linux | `dist/SecureAccess` |

### Cross-Platform Notes

- **Windows:** Build on Windows. The `.exe` is portable and does not require Python.
- **macOS:** Build on macOS. You may need to codesign the binary for distribution (`codesign --deep --force --sign - dist/SecureAccess`).
- **Linux:** Build on the target Linux distribution for best compatibility. The binary links against the system `libc`.

---

## Using Pre-built Releases

Download the latest release from the [GitHub Releases](https://github.com/Toddni8022/SecureAccess/releases) page.

| Platform | File |
|----------|------|
| Windows 10/11 | `SecureAccess.exe` |
| macOS 12+ | `SecureAccess` |
| Ubuntu 22.04+ | `SecureAccess` |

**Windows:**
```
Double-click SecureAccess.exe
```

**macOS / Linux:**
```bash
chmod +x SecureAccess
./SecureAccess
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECUREACCESS_DB_PATH` | OS app data dir | Override the database file path |
| `LOG_LEVEL` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `APP_THEME` | `dark` | UI theme: `dark`, `light`, `system` |
| `DISPLAY` | `:0` | X11 display server (Linux / Docker only) |

Copy `.env.example` to `.env` to configure locally:

```bash
cp .env.example .env
# Edit .env with your settings
```

---

## Docker Deployment

SecureAccess can be run in Docker for headless server environments or containerized deployments. GUI output requires an X11 display server on the host.

### Build the Image

```bash
docker build -t secureaccess:latest .
```

### Run with Docker (Linux / X11)

```bash
xhost +local:docker
docker run --rm \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v secureaccess_data:/root/.local/share/SecureAccess \
  secureaccess:latest
```

### Run with Docker Compose

```bash
docker-compose up
```

The `docker-compose.yml` mounts a named volume (`secureaccess_data`) to persist the database between container restarts.

### Dockerfile Reference

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DISPLAY=:0

ENTRYPOINT ["python", "app.py"]
```

---

## Cross-Platform Notes

### Windows

- Requires Windows 10 or later
- Tested on Python 3.10, 3.11, 3.12
- The database is stored in `%LOCALAPPDATA%\SecureAccess\secureaccess.db`
- PyInstaller builds a single `.exe` file

### macOS

- Requires macOS 12 (Monterey) or later
- Tkinter may require a separate installation when using Homebrew Python:
  ```bash
  brew install python-tk@3.11
  ```
- The database is stored in `~/.local/share/SecureAccess/secureaccess.db`

### Linux

- Requires tkinter: `sudo apt-get install python3-tk`
- The database is stored in `~/.local/share/SecureAccess/secureaccess.db`
- For headless/server deployments, use Docker with X11 forwarding or VNC

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'tkinter'`

Install tkinter for your platform:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora/RHEL
sudo dnf install python3-tkinter

# macOS (Homebrew)
brew install python-tk@3.11
```

### `ModuleNotFoundError: No module named 'customtkinter'`

Install dependencies:
```bash
pip install -r requirements.txt
```

### Application fails to start on Linux (no display)

Set the `DISPLAY` environment variable:
```bash
export DISPLAY=:0
python app.py
```

For remote/headless servers, install and configure a VNC server, or use X11 forwarding via SSH:
```bash
ssh -X user@server
python app.py
```

### Database permission errors

Ensure the app data directory is writable:
```bash
# Linux/macOS
chmod 700 ~/.local/share/SecureAccess

# Or set a custom path
export SECUREACCESS_DB_PATH=/path/to/writable/secureaccess.db
python app.py
```

### PyInstaller build fails

Ensure all dependencies are installed in the active environment:
```bash
pip install pyinstaller
pip install -r requirements.txt
python build.py
```

If the build fails due to missing hidden imports, add them to `build.py`:
```python
hiddenimports=["your.missing.module"]
```

### Slow startup on first launch

The first launch initializes the database and seeds default data. This is a one-time operation and subsequent launches are significantly faster.
