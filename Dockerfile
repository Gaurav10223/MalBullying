# # # Use Ubuntu as base image for better compatibility with pyenv
# # FROM ubuntu:22.04

# # # Set environment variables
# # ENV DEBIAN_FRONTEND=noninteractive
# # ENV PYENV_ROOT=/root/.pyenv
# # ENV PATH=$PYENV_ROOT/bin:$PATH

# # # Set working directory
# # WORKDIR /app

# # # Install system dependencies
# # RUN apt-get update && apt-get install -y \
# #     build-essential \
# #     libssl-dev \
# #     zlib1g-dev \
# #     libbz2-dev \
# #     libreadline-dev \
# #     libsqlite3-dev \
# #     wget \
# #     curl \
# #     llvm \
# #     libncursesw5-dev \
# #     xz-utils \
# #     tk-dev \
# #     libxml2-dev \
# #     libxmlsec1-dev \
# #     libffi-dev \
# #     liblzma-dev \
# #     git \
# #     ca-certificates \
# #     && rm -rf /var/lib/apt/lists/*

# # # Install pyenv
# # RUN git clone https://github.com/pyenv/pyenv.git $PYENV_ROOT && \
# #     echo 'eval "$(pyenv init --path)"' >> ~/.bashrc && \
# #     echo 'eval "$(pyenv init -)"' >> ~/.bashrc

# # # Copy application code
# # COPY . /app

# # # Make install script executable and run it
# # RUN chmod +x install.sh && \
# #     bash -c 'source ~/.bashrc && \
# #     eval "$(pyenv init --path)" && \
# #     eval "$(pyenv init -)" && \
# #     pyenv install 3.10.11 && \
# #     pyenv shell 3.10.11 && \
# #     python -m venv venv && \
# #     source venv/bin/activate && \
# #     pip install -r requirements.new.txt && \
# #     pip install flare-floss && \
# #     deactivate && \
# #     pyenv install 3.8.10 && \
# #     pyenv shell 3.8.10 && \
# #     cd static_ml_analysis && \
# #     python -m venv env && \
# #     source env/bin/activate && \
# #     pip install -r requirements.new.txt && \
# #     deactivate'

# # # Expose port
# # EXPOSE 8080

# # # Command to run the application
# # CMD ["bash", "-c", "source venv/bin/activate && python app.main.py"]


# FROM ubuntu:22.04

# # Set environment variables
# ENV DEBIAN_FRONTEND=noninteractive
# ENV PYENV_ROOT=/root/.pyenv
# ENV PATH=$PYENV_ROOT/bin:$PATH

# # Set working directory
# WORKDIR /app

# # Install system dependencies
# RUN apt-get update && apt-get install -y \
#     build-essential \
#     libssl-dev \
#     zlib1g-dev \
#     libbz2-dev \
#     libreadline-dev \
#     libsqlite3-dev \
#     wget \
#     curl \
#     llvm \
#     libncursesw5-dev \
#     xz-utils \
#     tk-dev \
#     libxml2-dev \
#     libxmlsec1-dev \
#     libffi-dev \
#     liblzma-dev \
#     git \
#     ca-certificates \
#     python3-dev \
#     && rm -rf /var/lib/apt/lists/*

# # Install pyenv
# RUN git clone https://github.com/pyenv/pyenv.git $PYENV_ROOT && \
#     echo 'eval "$(pyenv init --path)"' >> ~/.bashrc && \
#     echo 'eval "$(pyenv init -)"' >> ~/.bashrc

# # Copy application code
# COPY . /app

# # Make install script executable and run it
# RUN chmod +x install.sh && \
#     bash -c 'source ~/.bashrc && \
#     eval "$(pyenv init --path)" && \
#     eval "$(pyenv init -)" && \
#     pyenv install 3.10.11 && \
#     pyenv shell 3.10.11 && \
#     python -m venv --without-pip venv && \
#     source venv/bin/activate && \
#     curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
#     python get-pip.py && \
#     pip install -r requirements.new.txt && \
#     pip install flare-floss && \
#     deactivate && \
#     pyenv install 3.8.10 && \
#     pyenv shell 3.8.10 && \
#     cd static_ml_analysis && \
#     python -m venv --without-pip env && \
#     source env/bin/activate && \
#     curl https://bootstrap.pypa.io/pip/3.8/get-pip.py -o get-pip.py && \
#     python get-pip.py && \
#     pip install -r requirements.new.txt && \
#     deactivate'

# # Expose port
# EXPOSE 8080

# # Command to run the application
# CMD ["bash", "-c", "source venv/bin/activate && python app.main.py"]


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
    python3-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install pyenv
RUN git clone https://github.com/pyenv/pyenv.git $PYENV_ROOT && \
    echo 'eval "$(pyenv init --path)"' >> ~/.bashrc && \
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc

# Install Python 3.10.11 and 3.8.10 via pyenv
RUN bash -c 'source ~/.bashrc && \
    eval "$(pyenv init --path)" && \
    eval "$(pyenv init -)" && \
    pyenv install 3.10.11 && \
    pyenv install 3.8.10'

# Set Python 3.10.11 as global default
RUN bash -c 'source ~/.bashrc && \
    eval "$(pyenv init --path)" && \
    pyenv global 3.10.11'

# Install pip for Python 3.10.11
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    /root/.pyenv/versions/3.10.11/bin/python get-pip.py && \
    rm get-pip.py

# Copy application code
COPY . /app

# Install Python dependencies for Python 3.10.11 globally
RUN /root/.pyenv/versions/3.10.11/bin/pip install -r requirements.new.txt && \
    /root/.pyenv/versions/3.10.11/bin/pip install flare-floss

# Switch to Python 3.8.10 for static_ml_analysis
# Switch to Python 3.8.10 for static_ml_analysis
RUN bash -c 'eval "$(pyenv init --path)" && \
    eval "$(pyenv init -)" && \
    pyenv shell 3.8.10 && \
    curl https://bootstrap.pypa.io/pip/3.8/get-pip.py -o get-pip.py && \
    /root/.pyenv/versions/3.8.10/bin/python get-pip.py && \
    rm get-pip.py && \
    cd static_ml_analysis && \
    /root/.pyenv/versions/3.8.10/bin/pip install -r requirements.new.txt'

# Expose port
EXPOSE 8080

# Command to run the application
CMD ["/root/.pyenv/versions/3.10.11/bin/python", "app.main.py"]
