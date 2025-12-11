import os
import json
import shlex
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, flash

# ---------- CONFIG ----------
UPLOAD_FOLDER = "uploads"
CMD_TIMEOUT = 25  # per-tool timeout
SAMPLE_FILE_PATH = "/mnt/data/A_digital_photograph_displays_a_daytime_landscape_.png"

# Tools we will actually run (safe CLI tools). If not installed, results show 'binary-not-found'
TOOL_COMMANDS = {
    # Images / common
    "exiftool": ["exiftool", "{file}"],
    "exiv2": ["exiv2", "{file}"],
    "identify": ["identify", "-verbose", "{file}"],  # ImageMagick
    "mat2": ["mat2", "{file}"],
    "strings": ["strings", "-a", "{file}"],
    "binwalk": ["binwalk", "{file}"],

    # Video/Audio
    "ffprobe": ["ffprobe", "-v", "error", "-show_format", "-show_streams", "-print_format", "json", "{file}"],
    "mediainfo": ["mediainfo", "{file}"],

    # Binary/Firmware
    "readelf": ["readelf", "-h", "{file}"],
    "objdump": ["objdump", "-f", "{file}"],
    "rabin2": ["rabin2", "-I", "{file}"],  # radare2 info tool (rabin2), if installed

    # Documents
    "pdfinfo": ["pdfinfo", "{file}"],
    "pdfimages": ["pdfimages", "-list", "{file}"],
    "docx2txt": ["docx2txt", "{file}", "-"],
    "qpdf": ["qpdf", "--show-encryption", "{file}"],
    "mutool": ["mutool", "info", "{file}"],

    # Network (pcap)
    "tshark": ["tshark", "-r", "{file}"],

    # misc
    "file": ["file", "-k", "{file}"],
}

# Tools we show as info only (not executed)
DANGEROUS_TOOLS = [
    "autopsy", "sleuthkit", "blkid", "lsblk", "dumpe2fs", "mmls", "fsstat", "istat",
    "tcpdump (root)", "pdftk (may require extra packages)", "metadata-cleaner (GUI)", "exiftool-gui"
]

IMAGE_TOOLS = ["exiftool", "exiv2", "identify", "mat2", "strings", "binwalk"]
VIDEO_TOOLS = ["ffprobe", "mediainfo"]
BINARY_TOOLS = ["readelf", "objdump", "rabin2", "strings", "file"]
DOC_TOOLS = ["pdfinfo", "pdfimages", "docx2txt", "qpdf", "mutool"]
NETWORK_TOOLS = ["tshark"]

# ---------- APP ----------
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = "change-me-for-prod"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------- Helpers ----------
def safe_run(cmd_list, timeout=CMD_TIMEOUT):
    """
    Run command list (no shell). Returns dict with stdout, stderr, returncode, elapsed.
    """
    try:
        start = datetime.now()
        proc = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        end = datetime.now()
        return {
            "cmd": " ".join(shlex.quote(x) for x in cmd_list),
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "elapsed": (end - start).total_seconds()
        }
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(shlex.quote(x) for x in cmd_list), "error": "timeout"}
    except FileNotFoundError:
        return {"cmd": " ".join(shlex.quote(x) for x in cmd_list), "error": "binary-not-found"}
    except Exception as e:
        return {"cmd": " ".join(shlex.quote(x) for x in cmd_list), "error": str(e)}

def run_tools_on_file(filepath, selected_tools):
    results = {}
    for t in selected_tools:
        if t not in TOOL_COMMANDS:
            results[t] = {"error": "tool-not-configured"}
            continue
        cmd_template = TOOL_COMMANDS[t]
        cmd = [part.format(file=filepath) for part in cmd_template]
        results[t] = safe_run(cmd)
    return results

def save_uploaded_file(file_storage):
    filename = os.path.basename(file_storage.filename)
    dest_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    base, ext = os.path.splitext(filename)
    i = 1
    while os.path.exists(dest_path):
        filename = f"{base}_{i}{ext}"
        dest_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        i += 1
    file_storage.save(dest_path)
    return os.path.abspath(dest_path), filename

# ---------- Suspicion scoring ----------
def compute_suspicion_score(results, filename):
    score = 0
    reasons = []

    # file command mismatch
    f_out = results.get("file", {})
    if f_out and f_out.get("stdout"):
        s = f_out.get("stdout").lower()
        if "jpeg" in s and not filename.lower().endswith((".jpg", ".jpeg")):
            score += 15; reasons.append("File type says JPEG but extension mismatch")
        if "png" in s and not filename.lower().endswith(".png"):
            score += 12; reasons.append("File type says PNG but extension mismatch")
        if "pdf" in s and not filename.lower().endswith(".pdf"):
            score += 14; reasons.append("File says PDF but extension mismatch")

    # strings analysis
    s_out = results.get("strings", {}).get("stdout", "").lower()
    if s_out:
        # look in the first 800 chars for headers
        head = s_out[:800]
        if "mz" in head:
            score += 25; reasons.append("Found 'MZ' header inside file — possible embedded PE")
        if "elf" in head:
            score += 22; reasons.append("Found 'ELF' inside file — possible embedded binary")
        for kw in ["password", "secret", "key=", "private key", "-----begin"]:
            if kw in s_out:
                score += 8; reasons.append(f"Found suspicious keyword: {kw}")

    # binwalk
    bw = results.get("binwalk", {})
    if bw and bw.get("stdout"):
        out = bw.get("stdout").strip()
        if out and len(out.splitlines()) > 2:
            score += min(25, 5 + len(out.splitlines()))
            reasons.append(f"Binwalk found embedded content ({len(out.splitlines())} lines)")

    # ffprobe/mediainfo parse issues
    ff = results.get("ffprobe", {}) or results.get("mediainfo", {})
    if ff and ff.get("stderr"):
        score += 10; reasons.append("ffprobe/mediainfo reported errors parsing media")

    # readelf
    re_out = results.get("readelf", {}).get("stdout", "")
    if re_out and "ELF" in re_out:
        score += 25; reasons.append("readelf reports ELF header inside file")

    score = max(0, min(100, score))
    verdict = "Likely Malicious" if score >= 50 else "Possibly Suspicious" if score >= 25 else "Likely Clean"
    return score, verdict, reasons

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html",
                           image_tools=IMAGE_TOOLS,
                           video_tools=VIDEO_TOOLS,
                           binary_tools=BINARY_TOOLS,
                           doc_tools=DOC_TOOLS,
                           network_tools=NETWORK_TOOLS,
                           dangerous_tools=DANGEROUS_TOOLS,
                           sample_path=SAMPLE_FILE_PATH)

@app.route("/analyze", methods=["POST"])
def analyze():
    use_sample = request.form.get("use_sample") == "1"
    selected_tools = request.form.getlist("tools")
    # If user didn't pick any tools, default to some sensible ones
    if not selected_tools:
        selected_tools = ["file", "strings", "exiftool"]

    if use_sample:
        filepath = SAMPLE_FILE_PATH
        if not os.path.exists(filepath):
            flash("Sample file missing on server.", "danger")
            return redirect(url_for("index"))
        filename = os.path.basename(filepath)
    else:
        if "file" not in request.files:
            flash("No file uploaded.", "danger")
            return redirect(url_for("index"))
        f = request.files["file"]
        if f.filename == "":
            flash("Empty filename.", "danger")
            return redirect(url_for("index"))
        filepath, filename = save_uploaded_file(f)

    results = run_tools_on_file(filepath, selected_tools)
    score, verdict, reasons = compute_suspicion_score(results, filename)

    # Save JSON report
    json_name = f"{filename}_analysis.json"
    json_path = os.path.join(app.config["UPLOAD_FOLDER"], json_name)
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump({
            "file": filename,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "results": results
        }, jf, indent=2)

    return render_template("results.html",
                           filename=filename,
                           results=results,
                           score=score,
                           verdict=verdict,
                           reasons=reasons,
                           json_download=url_for("download_json", name=json_name))

@app.route("/download/<path:name>")
def download_json(name):
    path = os.path.join(app.config["UPLOAD_FOLDER"], name)
    if not os.path.exists(path):
        flash("File not found.", "danger")
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True)

@app.route("/ping")
def ping():
    return "pong"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
