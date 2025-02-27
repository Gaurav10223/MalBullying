import sys
import os
import json
import subprocess
import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import hashlib

app = Flask(__name__, static_folder='static')
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe'}
ML_API_URL = "http://localhost:4000/scan"
VIRUSTOTAL_API_KEY = "10b9b04880cbcb20edee98837bf7812d431658b9aa6ebb8a4918f33763d0b7be"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# Create static folder if it doesn't exist
os.makedirs('static', exist_ok=True)

# Global variables
current_file_path = None
results = {
    "static_analysis": None,
    "ml_static_analysis": None,
    "dynamic_analysis": None,
    "hash_based_scanner": None
}

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def run_static_analysis():
    """Run static analysis on the current file"""
    global current_file_path
    try:
        if not current_file_path:
            return False
        
        process = subprocess.Popen(
            [sys.executable, "static_analysis.py", current_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        output = process.communicate()[0]
        results["static_analysis"] = {"output": output}
        return process.returncode == 0
    except Exception as e:
        results["static_analysis"] = {"error": str(e)}
        return False

def run_ml_static_analysis():
    """Run ML-based static analysis using local Python module"""
    global current_file_path
    try:
        if not current_file_path:
            return False
        base_dir = os.path.dirname(os.path.abspath(__file__))
        python_executable = os.path.join(base_dir, "static_ml_analysis", "env", "Scripts", "python.exe")
        script_path = os.path.join(base_dir, "static_ml_analysis", "main.py")
        print([python_executable, script_path,  current_file_path])
        # Option 2: Run the ML analysis script directly (new method)
        process = subprocess.Popen(
            # [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "static_ml_analysis", "main.py"),  current_file_path],
            [python_executable, script_path,  current_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        output = process.communicate()[0]
        
        # Parse the output
        is_legitimate = "legitimate" in output.lower()
        features_info = ""
        
        if "Features used for classification:" in output:
            features_info = output.split("Features used for classification:")[1].strip()
        
        results["ml_static_analysis"] = {
            "output": output,
            "is_legitimate": is_legitimate,
            "features_info": features_info,
            "classification": "Legitimate" if is_legitimate else "Malicious"
        }
        
        return process.returncode == 0
    except Exception as e:
        results["ml_static_analysis"] = {"error": str(e)}
        return False

def run_dynamic_analysis():
    """Run dynamic analysis on the current file"""
    global current_file_path
    try:
        if not current_file_path:
            return False
        
        process = subprocess.Popen(
            [sys.executable, "dynamic_analysis.py", "--target", current_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        output = process.communicate()[0]
        results["dynamic_analysis"] = {"output": output}
        return process.returncode == 0
    except Exception as e:
        results["dynamic_analysis"] = {"error": str(e)}
        return False

def run_hash_based_scanner():
    """Check file against VirusTotal database"""
    global current_file_path
    try:
        if not current_file_path:
            return False
        
        # Calculate file hash
        file_hash = calculate_file_hash(current_file_path)
        
        # Query VirusTotal API with the file hash
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(f"{VIRUSTOTAL_API_URL}{file_hash}", headers=headers)
        
        if response.status_code == 200:
            vt_data = response.json()
            # Extract relevant information
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            # Calculate risk score (example: percentage of engines that flagged it as malicious)
            total_scans = sum(stats.values()) or 1  # Avoid division by zero
            malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
            risk_score = (malicious_count / total_scans) * 100
            
            results["hash_based_scanner"] = {
                "hash": file_hash,
                "risk_score": round(risk_score, 2),
                "stats": stats,
                "malicious_count": malicious_count,
                "total_scans": total_scans,
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
            return True
        elif response.status_code == 404:
            # File not found in VirusTotal database
            results["hash_based_scanner"] = {
                "hash": file_hash,
                "error": "File not found in VirusTotal database",
                "message": "Consider uploading the file for analysis"
            }
            return False
        else:
            # API error
            results["hash_based_scanner"] = {
                "hash": file_hash,
                "error": f"API Error: {response.status_code}",
                "message": response.text
            }
            return False
            
    except Exception as e:
        results["hash_based_scanner"] = {"error": str(e)}
        return False

# Serve the frontend
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    global current_file_path
    
    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400
    
    file = request.files['file']
    
    # Check if the file is selected
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400
    
    # Check if the file extension is allowed
    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": f"File type not allowed. Only {', '.join(ALLOWED_EXTENSIONS)} files are supported"}), 400
    
    # Save the file
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        current_file_path = file_path
        
        # Reset analysis results
        for key in results:
            results[key] = None
            
        return jsonify({"success": True, "filename": filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    """Run the specified analysis type"""
    global current_file_path
    
    if not current_file_path:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400
        
    analysis_type = request.json.get('type', '')
    
    if analysis_type == 'static':
        success = run_static_analysis()
    elif analysis_type == 'ml_static':
        success = run_ml_static_analysis()
    elif analysis_type == 'dynamic':
        success = run_dynamic_analysis()
    elif analysis_type == 'hash_based':
        success = run_hash_based_scanner()
    elif analysis_type == 'all':
        static_success = run_static_analysis()
        ml_static_success = run_ml_static_analysis()
        dynamic_success = run_dynamic_analysis()
        vt_success = run_hash_based_scanner()
        success = static_success and ml_static_success and dynamic_success and vt_success
    else:
        return jsonify({"success": False, "error": f"Unknown analysis type: {analysis_type}"}), 400
    
    return jsonify({
        "success": success, 
        "message": f"{analysis_type.replace('_', ' ').title()} analysis completed successfully" if success else f"{analysis_type.replace('_', ' ').title()} analysis failed"
    })

@app.route('/ml-direct', methods=['POST'])
def ml_direct():
    """Direct proxy to ML backend"""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        # Forward the file directly to the ML backend
        files = {"file": (file.filename, file.stream, file.content_type)}
        response = requests.post(ML_API_URL, files=files)
        
        # Return the ML backend's response as-is
        return response.content, response.status_code, response.headers.items()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/results', methods=['GET'])
def get_results():
    """Return all analysis results"""
    return jsonify(results)

if __name__ == '__main__':
    print("Starting server at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)