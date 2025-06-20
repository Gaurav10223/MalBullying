# Use Ubuntu as base image for better compatibility with pyenv
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYENV_ROOT=/root/.pyenv
ENV PATH=$PYENV_ROOT/bin:$PATH

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
    llvm \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libffi-dev \
    liblzma-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install pyenv
RUN git clone https://github.com/pyenv/pyenv.git $PYENV_ROOT && \
    echo 'eval "$(pyenv init --path)"' >> ~/.bashrc && \
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc

# Copy application code
COPY . /app

# Make install script executable and run it
RUN chmod +x install.sh && \
    bash -c 'source ~/.bashrc && \
    eval "$(pyenv init --path)" && \
    eval "$(pyenv init -)" && \
    pyenv install 3.10.11 && \
    pyenv shell 3.10.11 && \
    python -m venv venv && \
    source venv/bin/activate && \
    pip install -r requirements.new.txt && \
    pip install flare-floss && \
    deactivate && \
    pyenv install 3.8.10 && \
    pyenv shell 3.8.10 && \
    cd static_ml_analysis && \
    python -m venv env && \
    source env/bin/activate && \
    pip install -r requirements.new.txt && \
    deactivate'

# Expose port
EXPOSE 5000

# Command to run the application
CMD ["bash", "-c", "source venv/bin/activate && python app.main.py"]
