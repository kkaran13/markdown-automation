#!/usr/bin/env python3
import os, re, ast, glob, json, logging, sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("env-scanner")

# Get target repository and branch from environment variables
target_repo = os.getenv("TARGET_REPO", "")
target_branch = os.getenv("TARGET_BRANCH", "main")
repo_dir = os.getcwd()
report = {}

# Language-specific environment access patterns - expanded for better coverage
patterns = {
    "python": [
        r"os\.environ\.get\(['\"]([^'\"]+)['\"]",                  # os.environ.get("VAR")
        r"os\.getenv\(['\"]([^'\"]+)['\"]",                        # os.getenv("VAR")
        r"os\.environ\[['\"]([^'\"]+)['\"]\]",                     # os.environ["VAR"]
        r"config\(['\"]([^'\"]+)['\"]",                            # config("VAR")
        r"settings\(['\"]([^'\"]+)['\"]",                          # settings("VAR")
        r"env\(['\"]([^'\"]+)['\"]",                               # env("VAR")
        r"Environment\.GetEnvironmentVariable\(['\"]([^'\"]+)['\"]", # Environment.GetEnvironmentVariable("VAR")
        r"os\.getenv\(['\"]([^'\"]+)['\"]",                        # os.getenv("VAR")
        r"dotenv\.get_key\([^,]+,\s*['\"]([^'\"]+)['\"]",          # dotenv.get_key(file, "VAR")
    ],
    "javascript": [
        r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)",                 # process.env.VAR
        r"process\.env\[['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",       # process.env["VAR"]
        r"getEnv\(['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",             # getEnv("VAR")
        r"config\.get\(['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",        # config.get("VAR")
        r"env\(['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",                # env("VAR")
        r"dotenv\.config\(\)[^;]*?\.([A-Za-z_][A-Za-z0-9_]*)",     # dotenv.config().VAR
    ],
    "java": [
        r"System\.getenv\(['\"]([^'\"]+)['\"]",                    # System.getenv("VAR")
        r"System\.getProperty\(['\"]([^'\"]+)['\"]",               # System.getProperty("VAR")
        r"env\.get[A-Za-z]*\(['\"]([^'\"]+)['\"]",                 # env.getString("VAR")
        r"@Value\(['\"][$#]\{([^:}\"]+)[:\}]['\"]",                # @Value("${VAR}")
    ],
    "go": [
        r"os\.Getenv\(['\"]([^'\"]+)['\"]",                        # os.Getenv("VAR") 
        r"viper\.Get[A-Za-z]*\(['\"]([^'\"]+)['\"]",               # viper.GetString("VAR")
    ],
    "ruby": [
        r"ENV\[['\"]([^'\"]+)['\"]\]",                             # ENV["VAR"]
        r"ENV\.['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"?]",              # ENV.VAR or ENV["VAR"]
    ],
    "php": [
        r"\$_ENV\[['\"]([^'\"]+)['\"]\]",                          # $_ENV["VAR"]
        r"getenv\(['\"]([^'\"]+)['\"]",                            # getenv("VAR")
        r"env\(['\"]([^'\"]+)['\"]",                               # env("VAR")
    ],
    "shell": [
        r"export\s+([A-Za-z_][A-Za-z0-9_]*)=",                     # export VAR=value
        r"\${([A-Za-z_][A-Za-z0-9_]*)}",                           # ${VAR}
        r"\$([A-Za-z_][A-Za-z0-9_]*)",                             # $VAR
        r"source .*\.env",                                          # source .env (flag env file)
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)=",                          # VAR=value
    ],
    "dotnet": [
        r"Environment\.GetEnvironmentVariable\(['\"]([^'\"]+)['\"]", # Environment.GetEnvironmentVariable("VAR")
        r"Configuration\[['\"]([^'\"]+)['\"]\]",                   # Configuration["VAR"]
    ],
    "docker": [
        r"ENV\s+([A-Za-z_][A-Za-z0-9_]*)",                         # ENV VAR=value
        r"ARG\s+([A-Za-z_][A-Za-z0-9_]*)",                         # ARG VAR
    ],
    "yaml": [
        r"[$#]\{([^}:]+)[}:]",                                     # ${VAR} or ${VAR:default}
        r"env:\s*([A-Za-z_][A-Za-z0-9_]*)",                        # env: VAR
    ]
}

def extract_python_envs(path):
    """AST-based extraction for Python env access - with better error handling"""
    envs = set()
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        
        # Skip empty files
        if not content.strip():
            return envs
            
        try:
            tree = ast.parse(content, path)
        except SyntaxError as e:
            logger.warning(f"Python syntax error in {path}: {e}")
            return envs
            
        for node in ast.walk(tree):
            # Method 1: getenv and similar calls
            if isinstance(node, ast.Call):
                func = getattr(node.func, "attr", "")
                if func in ("getenv", "get", "get_key", "getenv"):
                    # Look at first argument
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        envs.add(node.args[0].value)
                    
            # Method 2: os.environ["VAR"] and similar access
            elif isinstance(node, ast.Subscript):
                value = node.value
                if hasattr(value, "attr") and value.attr in ("environ", "env"):
                    # Handle slice in different Python versions
                    slice_value = None
                    if isinstance(node.slice, ast.Constant):  # Python 3.8+
                        slice_value = node.slice.value
                    elif hasattr(node.slice, "value") and isinstance(node.slice.value, ast.Constant):  # Python < 3.8
                        slice_value = node.slice.value.value
                    elif isinstance(node.slice, ast.Index) and hasattr(node.slice, "value"):  # Older Python versions
                        if isinstance(node.slice.value, ast.Str):
                            slice_value = node.slice.value.s
                            
                    if isinstance(slice_value, str):
                        envs.add(slice_value)
    except Exception as e:
        logger.warning(f"Error processing Python file {path}: {e}")
    
    return envs

def extract_envs_from_text(text, lang):
    """Extract environment variables using regex patterns"""
    found = set()
    for p in patterns.get(lang, []):
        try:
            matches = re.findall(p, text)
            for match in matches:
                # Filter out common false positives and very short vars
                if isinstance(match, str) and len(match) > 1:
                    if match not in ['true', 'false', 'null', 'undefined', 'NaN']:
                        found.add(match)
        except re.error as e:
            logger.warning(f"Regex error with pattern {p}: {e}")
    return found

def get_file_lang(path):
    """Determine language based on file extension"""
    ext = Path(path).suffix.lower()
    
    if ext == ".py":
        return "python"
    elif ext in [".js", ".jsx", ".ts", ".tsx"]:
        return "javascript"
    elif ext == ".java":
        return "java"
    elif ext in [".sh", ".bash"]:
        return "shell"
    elif ext == ".env":
        return "shell"  # .env files use shell-like syntax
    elif ext == ".go":
        return "go"
    elif ext in [".rb", ".rake"]:
        return "ruby"
    elif ext == ".php":
        return "php"
    elif ext in [".cs", ".vb"]:
        return "dotnet"
    elif ext == ".dockerfile" or path.lower().endswith("dockerfile"):
        return "docker"
    elif ext in [".yml", ".yaml"]:
        return "yaml"
    
    return None

def is_binary_file(path):
    """Check if a file appears to be binary"""
    try:
        with open(path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk  # Simple heuristic for binary files
    except Exception:
        return True  # If we can't read the file, assume it's binary

def scan_repo(repo_dir):
    """Scan repository for environment variables"""
    logger.info(f"Scanning repository: {repo_dir}")
    logger.info(f"Target branch: {target_branch}")
    
    # Track what we've scanned
    file_count = 0
    env_var_count = 0
    
    # Binary file extensions to skip
    binary_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", 
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".flv", ".mkv",
        ".zip", ".gz", ".tar", ".rar", ".7z", ".jar", ".war", 
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".bin", ".exe", ".dll", ".so", ".dylib", ".class", ".pyc",
        ".ttf", ".woff", ".woff2", ".eot"
    }
    
    # Directories to skip
    skip_dirs = {
        ".git", "node_modules", "venv", "env", "__pycache__", 
        "dist", "build", "target", "bin", "obj", "out", 
        "coverage", "vendor", "bower_components"
    }
    
    # Scan all files recursively
    for path in

def generate_markdown(report, branch):
    md = ["# Environment Variables Report", f"Scanned Branch: **{branch}**", ""]
    if not report:
        md.append("✅ No environment variables found.")
    else:
        for file, vars_ in report.items():
            md.append(f"## {file}")
            for v in vars_:
                md.append(f"- `{v}`")
            md.append("")
    Path("DEPLOYMENT_DOCUMENT.md").write_text("\n".join(md))
    logging.info("Report written to DEPLOYMENT_DOCUMENT.md")

if __name__ == "__main__":
    branch = os.getenv("TARGET_BRANCH", "main")
    logging.info(f"Scanning branch: {branch}")
    result = scan_repo(repo_dir)
    generate_markdown(result, branch)
