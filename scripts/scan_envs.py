#!/usr/bin/env python3
import os, re, ast, glob, json, logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

repo_dir = os.getcwd()
report = {}
patterns = {
    "generic": [
        r"export\s+([A-Za-z_][A-Za-z0-9_]*)=",
        r"\${([A-Za-z_][A-Za-z0-9_]*)}",
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"].*['\"]",
    ],
    "python": [
        r"os\.environ\.get\(['\"]([^'\"]+)['\"]\)",
        r"os\.getenv\(['\"]([^'\"]+)['\"]\)",
        r"os\.environ\[['\"]([^'\"]+)['\"]\]",
    ],
    "javascript": [
        r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)",
    ],
    "java": [
        r"System\.getenv\(['\"]([^'\"]+)['\"]\)",
    ],
}

def extract_python_envs(path):
    """AST-based extraction for Python env access"""
    envs = set()
    try:
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read(), path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = getattr(node.func, "attr", "")
                if func in ("getenv", "get"):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            envs.add(arg.value)
            elif isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Attribute) and getattr(node.value, "attr", "") == "environ":
                    if isinstance(node.slice, ast.Constant):
                        envs.add(node.slice.value)
    except Exception as e:
        logging.warning(f"AST parse error in {path}: {e}")
    return envs

def extract_envs_from_text(text, lang):
    found = set()
    for p in patterns.get(lang, []) + patterns["generic"]:
        found |= set(re.findall(p, text))
    return found

def scan_repo(repo_dir):
    for path in glob.glob(f"{repo_dir}/**/*", recursive=True):
        if os.path.isdir(path):
            continue
        if any(path.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".mp3", ".mp4", ".zip", ".gz", ".pdf"]):
            continue

        ext = Path(path).suffix.lower()
        try:
            text = Path(path).read_text(errors="ignore")
        except:
            continue

        envs = set()
        if ext == ".py":
            envs |= extract_python_envs(path)
            envs |= extract_envs_from_text(text, "python")
        elif ext in [".js", ".ts"]:
            envs |= extract_envs_from_text(text, "javascript")
        elif ext == ".java":
            envs |= extract_envs_from_text(text, "java")
        elif ext in [".sh", ".bash", ".env"]:
            envs |= extract_envs_from_text(text, "generic")
        else:
            envs |= extract_envs_from_text(text, "generic")

        if envs:
            report[path] = sorted(envs)
    return report

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
    logging.info(f"Report written to DEPLOYMENT_DOCUMENT.md")

if __name__ == "__main__":
    branch = os.getenv("TARGET_BRANCH", "main")
    logging.info(f"Scanning branch: {branch}")
    result = scan_repo(repo_dir)
    generate_markdown(result, branch)