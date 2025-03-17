#!/bin/bash

# Define script path
SCRIPT_PATH="$(realpath "$0")"

# Check if the script has restarted
if [ "$PYENV_RESTARTED" != "1" ]; then
    echo "Installing Pyenv..."
    # Install Pyenv dependencies
    sudo apt update
    sudo apt install -y git curl libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm make libncurses5-dev libncursesw5-dev xz-utils tk-dev liblzma-dev python3-openssl git

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

# Create virtual environment 'env' using Python 3.8.10
echo "Creating virtual environment 'env' using Python 3.8.10..."
python -m venv env

VENV_PATH="./env/bin/activate"
if [ -f "$VENV_PATH" ]; then
    echo "Activating virtual environment 'env'..."
    source "$VENV_PATH"
else
    echo "Error: Virtual environment not found. Run 'python -m venv env' first."
    exit 1
fi

echo "Installing dependencies from requirements.new.txt..."
pip install -r requirements.new.txt

echo "Deactivating virtual environment 'env'..."
deactivate

echo "Returning to the previous directory..."
cd ..

# Set Python 3.10.11 as active version
echo "Setting Python 3.10.11 as active version..."
pyenv global 3.10.11

# Create virtual environment 'venv' using Python 3.10.11
echo "Creating virtual environment 'venv' using Python 3.10.11..."
python -m venv venv

VENV_PATH="./venv/bin/activate"
if [ -f "$VENV_PATH" ]; then
    echo "Activating virtual environment 'venv'..."
    source "$VENV_PATH"
else
    echo "Error: Virtual environment not found. Run 'python -m venv venv' first."
    exit 1
fi

echo "Installing dependencies from requirements.new.txt..."
pip install -r requirements.new.txt

# Install Visual Studio Build Tools equivalent on Ubuntu
echo "Installing dependencies for build tools..."
sudo apt install -y build-essential cmake

echo "Installation completed successfully!"

# Install flare-floss package
pip install flare-floss

echo "Deactivating virtual environment 'venv'..."
deactivate

# Set Python 3.8.10 as active version again (for consistency)
echo "Setting Python 3.8.10 as active version..."
pyenv global 3.8.10

# Navigate back to the static_ml_analysis directory to create the final virtual environment
echo "Navigating to 'static_ml_analysis' directory again..."
cd static_ml_analysis || { echo "Directory static_ml_analysis not found"; exit 1; }

# Create virtual environment 'env' again using Python 3.8.10
echo "Creating virtual environment 'env' using Python 3.8.10 again..."
python -m venv env

VENV_PATH="./env/bin/activate"
if [ -f "$VENV_PATH" ]; then
    echo "Activating virtual environment 'env'..."
    source "$VENV_PATH"
else
    echo "Error: Virtual environment not found. Run 'python -m venv env' first."
    exit 1
fi

echo "Installing dependencies from requirements.new.txt..."
pip install -r requirements.new.txt

echo "Deactivating virtual environment 'env'..."
deactivate

echo "Returning to the previous directory..."
cd ..

