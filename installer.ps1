# Testing code ...
# # Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"; &"./install-pyenv-win.ps1"

# # pyenv install 3.10.11

# # pyenv shell 3.10.11

# # pyenv exec python -m venv venv

# # $venvPath = ".\venv\Scripts\Activate.ps1"
# # if (Test-Path $venvPath) {
# #     & $venvPath
# # } else {
# #     Write-Host "Error: Virtual environment not found. Run 'pyenv exec python -m venv venv' first."
# #     exit 1
# # }

# # python -m pip install -r requirements.new.txt
# # pip install flare-floss

# # deactivate

# # pyenv install 3.8.10
# pyenv shell 3.8.10
# cd static_ml_analysis
# # pyenv exec python -m venv env

# $venvPath = ".\env\Scripts\Activate.ps1"
# if (Test-Path $venvPath) {
#     & $venvPath
# } else {
#     Write-Host "Error: Virtual environment not found. Run 'pyenv exec python -m venv env' first."
#     exit 1
# }

# # pyenv exec python -m pip install -r requirements.new.txt

# python -m pip install pefile joblib scikit-learn

# # deactivate
# cd ..


#####################################################################################################3
# Deployment 1 code ... 

# # Install Pyenv
# Write-Host "Installing Pyenv..." -ForegroundColor Cyan
# Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"
# Write-Host "Running Pyenv installation script..." -ForegroundColor Green
# & "./install-pyenv-win.ps1"

# # Restart the terminal
# Write-Host "Restarting terminal to apply changes..." -ForegroundColor Yellow
# Start-Process powershell -ArgumentList "-NoExit", "-Command cd $PWD"
# exit

# # Install Python 3.10.11
# Write-Host "Installing Python 3.10.11..." -ForegroundColor Cyan
# pyenv install 3.10.11
# Write-Host "Setting Python 3.10.11 as active version..." -ForegroundColor Green
# pyenv shell 3.10.11
# Write-Host "Creating virtual environment 'venv' using Python 3.10.11..." -ForegroundColor Yellow
# pyenv exec python -m venv venv

# $venvPath = ".\venv\Scripts\Activate.ps1"
# if (Test-Path $venvPath) {
#     Write-Host "Activating virtual environment 'venv'..." -ForegroundColor Green
#     & $venvPath
# } else {
#     Write-Host "Error: Virtual environment not found. Run 'pyenv exec python -m venv venv' first." -ForegroundColor Red
#     exit 1
# }

# Write-Host "Installing dependencies from requirements.new.txt..." -ForegroundColor Cyan
# pyenv exec python -m pip install -r requirements.new.txt

# Write-Host "Deactivating virtual environment 'venv'..." -ForegroundColor Yellow
# deactivate

# # Install Python 3.8.10
# Write-Host "Installing Python 3.8.10..." -ForegroundColor Cyan
# pyenv install 3.8.10
# Write-Host "Setting Python 3.8.10 as active version..." -ForegroundColor Green
# pyenv shell 3.8.10

# # Navigate to static_ml_analysis directory
# Write-Host "Navigating to 'static_ml_analysis' directory..." -ForegroundColor Cyan
# cd static_ml_analysis

# # Create virtual environment using Python 3.8.10
# Write-Host "Creating virtual environment 'env' using Python 3.8.10..." -ForegroundColor Yellow
# pyenv exec python -m venv env

# $venvPath = ".\env\Scripts\Activate.ps1"
# if (Test-Path $venvPath) {
#     Write-Host "Activating virtual environment 'env'..." -ForegroundColor Green
#     & $venvPath
# } else {
#     Write-Host "Error: Virtual environment not found. Run 'pyenv exec python -m venv env' first." -ForegroundColor Red
#     exit 1
# }

# Write-Host "Installing dependencies from requirements.new.txt..." -ForegroundColor Cyan
# pyenv exec python -m pip install -r requirements.new.txt

# Write-Host "Deactivating virtual environment 'env'..." -ForegroundColor Yellow
# deactivate

# Write-Host "Returning to the previous directory..." -ForegroundColor Cyan
# cd ..
 ########################################################
 # Deployment code final


# Define script path
$scriptPath = $MyInvocation.MyCommand.Definition

# Check if the script has restarted
if ($env:PYENV_RESTARTED -ne "1") {
    Write-Host "Installing Pyenv..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"
    Write-Host "Running Pyenv installation script..." -ForegroundColor Green
    & "./install-pyenv-win.ps1"

    # Restart the terminal and resume script execution
    Write-Host "Restarting terminal to apply changes..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command `$env:PYENV_RESTARTED='1'; & '$scriptPath'" -Wait
    exit
}

# Ensure Pyenv is available in the current session
Write-Host "Reloading environment variables..." -ForegroundColor Cyan
$env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")

# Install Python 3.10.11
Write-Host "Installing Python 3.10.11..." -ForegroundColor Cyan
pyenv install 3.10.11
Write-Host "Setting Python 3.10.11 as active version..." -ForegroundColor Green
pyenv shell 3.10.11
Write-Host "Creating virtual environment 'venv' using Python 3.10.11..." -ForegroundColor Yellow
pyenv exec python -m venv venv

$venvPath = ".\venv\Scripts\Activate.ps1"
if (Test-Path $venvPath) {
    Write-Host "Activating virtual environment 'venv'..." -ForegroundColor Green
    & $venvPath
} else {
    Write-Host "Error: Virtual environment not found. Run 'pyenv exec python -m venv venv' first." -ForegroundColor Red
    exit 1
}

Write-Host "Installing dependencies from requirements.new.txt..." -ForegroundColor Cyan
pyenv exec python -m pip install -r requirements.new.txt

Write-Host "Deactivating virtual environment 'venv'..." -ForegroundColor Yellow
deactivate

# Install Python 3.8.10
Write-Host "Installing Python 3.8.10..." -ForegroundColor Cyan
pyenv install 3.8.10
Write-Host "Setting Python 3.8.10 as active version..." -ForegroundColor Green
pyenv shell 3.8.10

# Navigate to static_ml_analysis directory
Write-Host "Navigating to 'static_ml_analysis' directory..." -ForegroundColor Cyan
cd static_ml_analysis

# Create virtual environment using Python 3.8.10
Write-Host "Creating virtual environment 'env' using Python 3.8.10..." -ForegroundColor Yellow
pyenv exec python -m venv env

$venvPath = ".\env\Scripts\Activate.ps1"
if (Test-Path $venvPath) {
    Write-Host "Activating virtual environment 'env'..." -ForegroundColor Green
    & $venvPath
} else {
    Write-Host "Error: Virtual environment not found. Run 'pyenv exec python -m venv env' first." -ForegroundColor Red
    exit 1
}

Write-Host "Installing dependencies from requirements.new.txt..." -ForegroundColor Cyan
pyenv exec python -m pip install -r requirements.new.txt

Write-Host "Deactivating virtual environment 'env'..." -ForegroundColor Yellow
deactivate

Write-Host "Returning to the previous directory..." -ForegroundColor Cyan
cd ..
