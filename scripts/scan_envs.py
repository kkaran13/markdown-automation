#!/usr/bin/env python3
import os, re, ast, glob, json, logging, sys, datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("env-scanner")

# Get target repository, branch, and scan directory from environment variables
target_repo = os.getenv("TARGET_REPO", "")
target_branch = os.getenv("TARGET_BRANCH", "main")
# Use SCAN_DIR if provided, otherwise use current directory
repo_dir = os.getenv("SCAN_DIR", os.getcwd())
logger.info(f"Using scan directory: {repo_dir}")
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
                    if node.args and len(node.args) > 0:
                        arg = node.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            envs.add(arg.value)
                        # Handle older Python versions before 3.8
                        elif hasattr(arg, 's') and isinstance(arg.s, str):
                            envs.add(arg.s)
                    
            # Method 2: os.environ["VAR"] and similar access
            elif isinstance(node, ast.Subscript):
                value = node.value
                if hasattr(value, "attr") and value.attr in ("environ", "env"):
                    # Handle slice in different Python versions
                    slice_value = None
                    if isinstance(node.slice, ast.Constant):  # Python 3.8+
                        slice_value = node.slice.value
                    elif hasattr(node.slice, "value"):  # Python < 3.8
                        if isinstance(node.slice.value, ast.Constant):
                            slice_value = node.slice.value.value
                        elif isinstance(node.slice.value, ast.Str):
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
                    if match.lower() not in ['true', 'false', 'null', 'undefined', 'nan']:
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
    for path in glob.glob(f"{repo_dir}/**/*", recursive=True):
        # Skip directories
        if os.path.isdir(path):
            # Check if it's a directory we should skip
            if Path(path).name in skip_dirs:
                continue
            continue
            
        # Skip binary files by extension
        if Path(path).suffix.lower() in binary_exts:
            continue
            
        # Skip binary files by content check
        if is_binary_file(path):
            continue

        # Get relative path for display
        try:
            rel_path = path
            # Try to make the path relative to current directory
            try:
                rel_path = str(Path(path).relative_to(repo_dir))
            except:
                pass  # Keep the original path if this fails
            
            # Read file content
            content = ""
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    file_count += 1
            except Exception as e:
                logger.warning(f"Could not read file {rel_path}: {e}")
                continue
                
            if not content.strip():
                continue
                
            # Determine language for specific patterns
            lang = get_file_lang(path)
            envs = set()
            
            # Use AST parsing for Python files (more accurate)
            if lang == "python":
                py_envs = extract_python_envs(path)
                if py_envs:
                    envs |= py_envs
                    
            # Use regex patterns based on language
            if lang:
                regex_envs = extract_envs_from_text(content, lang)
                if regex_envs:
                    envs |= regex_envs
                    
            # Generic patterns for any file - for .env files or config files
            if ".env" in path.lower() or "config" in path.lower():
                # Apply shell patterns as these often contain env vars
                shell_envs = extract_envs_from_text(content, "shell")
                if shell_envs:
                    envs |= shell_envs
            
            # Filter out common false positives and non-env-var names
            filtered_envs = set()
            for env in envs:
                # Skip very short names (likely false positives)
                if len(env) < 2:
                    continue
                    
                # Skip common programming words that aren't likely env vars
                if env.lower() in {'self', 'this', 'true', 'false', 'null', 'none', 
                                  'undefined', 'nan', 'inf', 'encoding', 'format'}:
                    continue
                    
                filtered_envs.add(env)
            
            if filtered_envs:
                env_var_count += len(filtered_envs)
                report[rel_path] = sorted(filtered_envs)
                
        except Exception as e:
            logger.error(f"Error processing {path}: {e}")
            
    logger.info(f"Scan complete: {file_count} files scanned, {env_var_count} environment variables found")
    return report

def extract_vars_from_md(content):
    """Extract environment variables from an existing markdown document"""
    existing_vars = set()
    
    # Use regex to extract variables enclosed in backticks after bullet points
    var_pattern = r'- `([^`]+)`'
    matches = re.findall(var_pattern, content)
    
    for match in matches:
        existing_vars.add(match)
    
    return existing_vars

def get_all_vars_from_report(report):
    """Get all environment variables from the report dictionary"""
    all_vars = set()
    for file_vars in report.values():
        all_vars.update(file_vars)
    return all_vars

# logic -> 1
# def generate_markdown(report, branch, existing_content=None):
    # """Generate markdown report from scan results, appending new variables to existing content if provided"""
    # repo_name = target_repo or "local-repository"
    
    # # Get all variables from the current scan
    # all_current_vars = get_all_vars_from_report(report)
    
    # # If existing content is provided, extract variables from it
    # existing_vars = set()
    # if existing_content:
    #     existing_vars = extract_vars_from_md(existing_content)
    
    # # Find new variables that are not in the existing document
    # new_vars = all_current_vars - existing_vars
    
    # # If no new variables and existing content exists, no need to update
    # if not new_vars and existing_content:
    #     logger.info("No new environment variables found. Existing document is up to date.")
    #     with open("report_updated.txt", "w") as f:
    #         f.write("no_update")
    #     return False

    # total_vars = len(all_current_vars)
    # total_files = len(report)

    # output_path = Path("DEPLOYMENT_DOCUMENT.md")

    # # Create the markdown header and summary (for new or first-time creation)
    # md = [
    #     "# Environment Variables Report",
    #     f"Repository: **{repo_name}**",
    #     f"Branch: **{branch}**",
    #     f"Scan Date: **{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**",
    #     ""
    # ]

    # if not report:
    #     md.append("✅ No environment variables found in this repository.")
    #     new_md_content = "\n".join(md)
    # else:
    #     total_vars = sum(len(vars_) for vars_ in report.values())
    #     md.append(f"## Summary\n- Total variables: **{total_vars}**\n- Files: **{len(report)}**\n")

    #     md.append("## Variables by File")
    #     for file in sorted(report.keys()):
    #         md.append(f"### {file}")
    #         for var in sorted(report[file]):
    #             md.append(f"- `{var}`")
    #         md.append("")
        
    #     new_md_content = "\n".join(md)

    # output_path = Path("DEPLOYMENT_DOCUMENT.md")

    # # ✅ If an existing document exists, append new variables instead of overwriting
    # if existing_content and new_vars:
    #     logger.info("Appending new environment variables to existing DEPLOYMENT_DOCUMENT.md")

    #     append_section = [
    #         "\n## Newly Detected Variables (Appended Automatically)\n",
    #     ]
    #     for var in sorted(new_vars):
    #         append_section.append(f"- `{var}`")

    #     updated_content = existing_content.strip() + "\n" + "\n".join(append_section) + "\n"
    #     output_path.write_text(updated_content)

    # else:
    #     # Create or fully rewrite document (first-time creation)
    #     output_path.write_text(new_md_content)

    # logger.info("Report written to DEPLOYMENT_DOCUMENT.md")

    # # Create marker file indicating the report was updated
    # with open("report_updated.txt", "w") as f:
    #     f.write("updated")

    # return True

# def generate_markdown(report, branch, existing_content=None):
#     """Generate markdown report from scan results, updating total variable count and appending new variables."""
#     repo_name = target_repo or "local-repository"
#     all_current_vars = get_all_vars_from_report(report)
    
#     # Extract existing vars (if document already exists)
#     existing_vars = set()
#     if existing_content:
#         existing_vars = extract_vars_from_md(existing_content)
    
#     new_vars = all_current_vars - existing_vars

#     if not new_vars and existing_content:
#         logger.info("No new environment variables found. Existing document is up to date.")
#         with open("report_updated.txt", "w") as f:
#             f.write("no_update")
#         return False

#     total_vars = len(all_current_vars)
#     total_files = len(report)

#     output_path = Path("DEPLOYMENT_DOCUMENT.md")

#     # If no existing content → create a new file from scratch
#     if not existing_content:
#         md = [
#             "# Environment Variables Report",
#             f"Repository: **{repo_name}**",
#             f"Branch: **{branch}**",
#             f"Scan Date: **{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**",
#             "",
#             f"## Summary\n- Total variables: **{total_vars}**\n- Files: **{total_files}**\n",
#             "## Variables by File"
#         ]
#         for file in sorted(report.keys()):
#             md.append(f"### {file}")
#             for var in sorted(report[file]):
#                 md.append(f"- `{var}`")
#             md.append("")
#         output_path.write_text("\n".join(md))
#         logger.info("Created new DEPLOYMENT_DOCUMENT.md")
#     else:
#         # Update existing content: refresh total variable count and append new vars
#         logger.info("Updating existing DEPLOYMENT_DOCUMENT.md")

#         # 1️⃣ Update total variable count in summary using regex
#         updated_content = re.sub(
#             r"- Total variables: \*\*\d+\*\*",
#             f"- Total variables: **{total_vars}**",
#             existing_content
#         )

#         # 2️⃣ Append newly detected vars
#         if new_vars:
#             append_section = [
#                 "\n## Newly Detected Variables (Appended Automatically)\n",
#             ]
#             for var in sorted(new_vars):
#                 append_section.append(f"- `{var}`")
#             updated_content = updated_content.strip() + "\n" + "\n".join(append_section) + "\n"

#         output_path.write_text(updated_content)
#         logger.info("Appended new variables and updated total count in DEPLOYMENT_DOCUMENT.md")

#     # Create marker file
#     with open("report_updated.txt", "w") as f:
#         f.write("updated")

#     return True

def generate_markdown(report, branch, existing_content=None):
    """Generate markdown report from scan results, updating total variable count and appending new variables."""
    repo_name = target_repo or "local-repository"
    all_current_vars = get_all_vars_from_report(report)

    # Extract existing vars (if document already exists)
    existing_vars = set()
    if existing_content:
        existing_vars = extract_vars_from_md(existing_content)

    new_vars = all_current_vars - existing_vars

    if not new_vars and existing_content:
        logger.info("No new environment variables found. Existing document is up to date.")
        with open("report_updated.txt", "w") as f:
            f.write("no_update")
        return False

    # When updating an existing doc, total_vars should reflect the union of existing + current
    if existing_content:
        total_vars = len(existing_vars | all_current_vars)
    else:
        total_vars = len(all_current_vars)

    total_files = len(report)
    output_path = Path("DEPLOYMENT_DOCUMENT.md")

    # If no existing content → create a new file from scratch
    if not existing_content:
        md = [
            "# Environment Variables Report",
            f"Repository: **{repo_name}**",
            f"Branch: **{branch}**",
            f"Scan Date: **{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**",
            "",
            f"## Summary\n- Total variables: **{total_vars}**\n- Files: **{total_files}**\n",
            "## Variables by File"
        ]
        for file in sorted(report.keys()):
            md.append(f"### {file}")
            for var in sorted(report[file]):
                md.append(f"- `{var}`")
            md.append("")
        output_path.write_text("\n".join(md))
        logger.info("Created new DEPLOYMENT_DOCUMENT.md")
    else:
        # Update existing content: refresh total variable count and append new vars
        logger.info("Updating existing DEPLOYMENT_DOCUMENT.md")

        # Update total variable count in summary using regex (safer with optional spaces)
        updated_content = re.sub(
            r"-\s*Total variables:\s*\*\*\d+\*\*",
            f"- Total variables: **{total_vars}**",
            existing_content,
            count=1,
            flags=re.IGNORECASE
        )

        # Update files count in summary if present
        updated_content = re.sub(
            r"-\s*Files:\s*\*\*\d+\*\*",
            f"- Files: **{total_files}**",
            updated_content,
            count=1,
            flags=re.IGNORECASE
        )

        # Append newly detected vars (if any)
        if new_vars:
            append_section = [
                "\n## Newly Detected Variables (Appended Automatically)\n",
            ]
            for var in sorted(new_vars):
                append_section.append(f"- `{var}`")
            updated_content = updated_content.strip() + "\n" + "\n".join(append_section) + "\n"

        output_path.write_text(updated_content)
        logger.info("Appended new variables and updated total count in DEPLOYMENT_DOCUMENT.md")

    # Create marker file
    with open("report_updated.txt", "w") as f:
        f.write("updated")

    return True

def check_existing_deployment_doc():
    """Check if DEPLOYMENT_DOCUMENT.md exists in target repository and return its content if found"""
    if not target_repo or not target_branch:
        return None
        
    # Check if we're in a GitHub Actions environment
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        # We're likely running locally, check if file exists locally
        deployment_doc_path = Path("DEPLOYMENT_DOCUMENT.md")
        if deployment_doc_path.exists():
            logger.info("Found existing DEPLOYMENT_DOCUMENT.md locally")
            try:
                with open(deployment_doc_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Error reading local DEPLOYMENT_DOCUMENT.md: {e}")
        return None
        
    # We're in GitHub Actions, check via API
    try:
        import requests
        import base64
        
        api_url = f"https://api.github.com/repos/{target_repo}/contents/DEPLOYMENT_DOCUMENT.md?ref={target_branch}"
        headers = {"Authorization": f"Bearer {github_token}"}
        
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            logger.info(f"Found existing DEPLOYMENT_DOCUMENT.md in {target_repo}:{target_branch}")
            try:
                content_b64 = response.json()["content"]
                content = base64.b64decode(content_b64).decode("utf-8")
                return content
            except Exception as e:
                logger.warning(f"Error decoding content from GitHub API: {e}")
        else:
            logger.info(f"No existing DEPLOYMENT_DOCUMENT.md found in {target_repo}:{target_branch}")
    except Exception as e:
        logger.warning(f"Error checking for existing document: {e}")
        
    return None

if __name__ == "__main__":
    try:
        branch = os.getenv("TARGET_BRANCH", "main")
        repo = os.getenv("TARGET_REPO", "local-repository")
        
        logger.info(f"Starting environment variable scan")
        logger.info(f"Target repository: {repo}")
        logger.info(f"Target branch: {branch}")
        
        # Check if DEPLOYMENT_DOCUMENT.md already exists
        existing_content = check_existing_deployment_doc()
        
        # Scan repository for environment variables
        result = scan_repo(repo_dir)
        
        # Generate markdown, comparing with existing content if available
        was_updated = generate_markdown(result, branch, existing_content)
        
        if was_updated:
            logger.info("Environment variables report updated with new variables.")
        else:
            logger.info("No changes needed to environment variables report.")
        
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        sys.exit(1)