#!/bin/bash

# Detect Python command (python3 preferred, fallback to python)
if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
else
    PYTHON_CMD=python
fi

# Define script path
SCRIPT_PATH="$(realpath "$0")"

# Check if the script has restarted
if [ "$PYENV_RESTARTED" != "1" ]; then
    echo "Installing Pyenv..."
    # Install Pyenv dependencies
    sudo apt update
    sudo apt install -y git curl libssl-dev zlib1g-dev libbz2-dev libreadline-dev \
        libsqlite3-dev wget curl llvm make libncurses5-dev libncursesw5-dev xz-utils \
        tk-dev liblzma-dev python3-openssl git

    # Install Pyenv
    curl https://pyenv.run | bash

    # Restart the terminal to apply changes
    echo "Restarting terminal to apply changes..."
    export PYENV_RESTARTED=1
    exec "$SCRIPT_PATH"
    exit
fi

# Ensure Pyenv is available in the current session
echo "Reloading environment variables..."
export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"

# Install Python versions if not already installed
if ! pyenv versions --bare | grep -q "3.8.10"; then
    echo "Installing Python 3.8.10..."
    pyenv install 3.8.10
fi

if ! pyenv versions --bare | grep -q "3.10.11"; then
    echo "Installing Python 3.10.11..."
    pyenv install 3.10.11
fi

# Set Python 3.8.10 as active version
echo "Setting Python 3.8.10 as active version..."
pyenv global 3.8.10

# Navigate to static_ml_analysis directory
echo "Navigating to 'static_ml_analysis' directory..."
cd static_ml_analysis || { echo "Directory static_ml_analysis not found"; exit 1; }

# Create virtual environment 'env' using pyenv
echo "Creating virtual environment 'env' using Python 3.8.10 with pyenv..."
pyenv virtualenv 3.8.10 env

# Activate the virtual environment using pyenv
echo "Activating virtual environment 'env'..."
pyenv activate env

echo "Installing dependencies from requirements.new.txt..."
pip install -r requirements.new.txt

echo "Deactivating virtual environment 'env'..."
pyenv deactivate

echo "Returning to the previous directory..."
cd ..

# Set Python 3.10.11 as active version
echo "Setting Python 3.10.11 as active version..."
pyenv global 3.10.11

# Create virtual environment 'venv' using pyenv
echo "Creating virtual environment 'venv' using Python 3.10.11 with pyenv..."
pyenv virtualenv 3.10.11 venv

# Activate the virtual environment using pyenv
echo "Activating virtual environment 'venv'..."
pyenv activate venv

echo "Installing dependencies from requirements.new.txt..."
pip install -r requirements.new.txt

# Install build tools
echo "Installing dependencies for build tools..."
sudo apt install -y build-essential cmake

echo "Installation completed successfully!"

# Install flare-floss package
pip install flare-floss

echo "Deactivating virtual environment 'venv'..."
pyenv deactivate

# Set Python 3.8.10 as active version again
echo "Setting Python 3.8.10 as active version..."
pyenv global 3.8.10

# Navigate back to the static_ml_analysis directory to create the final virtual environment
echo "Navigating to 'static_ml_analysis' directory again..."
cd static_ml_analysis || { echo "Directory static_ml_analysis not found"; exit 1; }

# Create virtual environment 'env' again using pyenv
echo "Creating virtual environment 'env' using Python 3.8.10 again with pyenv..."
pyenv virtualenv 3.8.10 env

# Activate the virtual environment using pyenv
echo "Activating virtual environment 'env'..."
pyenv activate env

echo "Installing dependencies from requirements.new.txt..."
pip install -r requirements.new.txt

echo "Deactivating virtual environment 'env'..."
pyenv deactivate


