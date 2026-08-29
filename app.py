import os
import json
import hashlib
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify
from werkzeug.utils import secure_filename
from sqlalchemy import text

from db import db, Analysis
from analysis import analyze_file
from report_gen import create_pdf_report, generate_ai_malware_report, generate_ai_svg_diagram
from malware_info import get_malware_info, MALWARE_FAMILIES
from models_loader import get_models

import logging

# Configure structured logging to display console output when running `python app.py`
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("malvision")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'malvision_super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///malvision.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
PENDING_UPLOAD_FOLDER = os.path.join(app.instance_path, 'pending_uploads')
os.makedirs(PENDING_UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)

with app.app_context():
    db.create_all()
    # Dynamic DB upgrade migrations to avoid sqlite3 errors for existing databases
    try:
        db.session.execute(text("ALTER TABLE analyses ADD COLUMN ai_report TEXT"))
        db.session.commit()
        print("Migration: Added column 'ai_report' to 'analyses' table.")
    except Exception:
        db.session.rollback()
        
    try:
        db.session.execute(text("ALTER TABLE analyses ADD COLUMN chat_history_json TEXT"))
        db.session.commit()
        print("Migration: Added column 'chat_history_json' to 'analyses' table.")
    except Exception:
        db.session.rollback()

# Load models once at startup
get_models()

def _create_analysis(filepath, filename):
    """Run the normal pipeline and persist one analysis session."""
    results = analyze_file(filepath, app.config['UPLOAD_FOLDER'])
    analysis = Analysis(
        filename=filename, file_size=results['meta']['size_bytes'], file_type=results['meta']['file_type'],
        entropy=results['meta']['entropy'], md5=results['meta']['md5'], sha1=results['meta']['sha1'],
        sha256=results['meta']['sha256'], sha512=results['meta']['sha512'], png_path=results['png_filename'],
        cnn_pred=results['model_results']['CNN']['class'], cnn_conf=results['model_results']['CNN']['confidence'],
        lstm_pred=results['model_results']['RNN_BiLSTM']['class'], lstm_conf=results['model_results']['RNN_BiLSTM']['confidence'],
        hybrid_pred=results['model_results']['Hybrid_CNN_LSTM']['class'], hybrid_conf=results['model_results']['Hybrid_CNN_LSTM']['confidence'],
        consensus=results['consensus'], agreement=results['agreement'], verdict=results['verdict'],
        all_probs_json=json.dumps(results['all_probs'])
    )
    db.session.add(analysis)
    db.session.commit()
    analysis.ai_report = generate_ai_malware_report(analysis)
    db.session.commit()
    generate_ai_svg_diagram(analysis, app.config['UPLOAD_FOLDER'])
    return analysis

def _delete_analysis_assets(analysis):
    """Remove an analysis and its generated artifacts as one recoverable operation boundary."""
    filename = analysis.filename
    for path in (
        os.path.join(app.config['UPLOAD_FOLDER'], analysis.png_path),
        os.path.join(app.config['UPLOAD_FOLDER'], f"report_{analysis.sha256}.pdf"),
        os.path.join(app.config['UPLOAD_FOLDER'], f"diagram_{analysis.sha256}.svg"),
        os.path.join(app.config['UPLOAD_FOLDER'], f"{analysis.sha256}{os.path.splitext(filename)[1]}"),
        os.path.join(app.config['UPLOAD_FOLDER'], filename),
    ):
        if os.path.exists(path):
            os.remove(path)
    db.session.delete(analysis)
    db.session.commit()

@app.after_request
def log_request_info(response):
    # Explicit access logger to guarantee stdout HTTP access logs when running python app.py
    logger.info(f'{request.remote_addr or "127.0.0.1"} - "{request.method} {request.path}" {response.status_code}')
    return response

@app.route('/')
def index():
    # Sort families to display
    families = []
    for name, info in MALWARE_FAMILIES.items():
        families.append({
            'name': name,
            'type': info['type'],
            'risk': info['risk'],
            'description': info['description']
        })
    return render_template('index.html', families=families)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'GET':
        return render_template('analyze.html')
        
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
        
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
        
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Read file bytes in memory for duplicate check
        file_bytes = file.read()
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        logger.info(f"Received upload: '{filename}' ({len(file_bytes)} bytes, MD5: {md5_hash})")
        
        # Duplicate detection: retain the submitted bytes briefly while the user chooses an action.
        existing = Analysis.query.filter_by(md5=md5_hash).first()
        if existing:
            token = uuid.uuid4().hex
            ext = os.path.splitext(filename)[1]
            with open(os.path.join(PENDING_UPLOAD_FOLDER, f"{token}{ext}"), 'wb') as pending:
                pending.write(file_bytes)
            logger.info(f"Duplicate upload detected for MD5 '{md5_hash}'. Awaiting user decision.")
            return render_template('analyze.html', duplicate=existing, duplicate_token=token, duplicate_filename=filename)
            
        # Write file bytes since we read them
        with open(filepath, 'wb') as f:
            f.write(file_bytes)
        
        try:
            logger.info(f"Running 3-model ensemble visual classification on '{filename}'...")
            analysis = _create_analysis(filepath, filename)
            return redirect(url_for('results', sha256=analysis.sha256))
            
        except Exception as e:
            logger.error(f"Error analyzing file '{filename}': {str(e)}", exc_info=True)
            flash(f"Error analyzing file: {str(e)}")
            return redirect(url_for('analyze'))

@app.route('/analyze/duplicate-action', methods=['POST'])
def duplicate_action():
    token = request.form.get('token', '')
    action = request.form.get('action', 'cancel')
    existing = Analysis.query.filter_by(sha256=request.form.get('sha256', '')).first_or_404()
    pending_files = [f for f in os.listdir(PENDING_UPLOAD_FOLDER) if f.startswith(token + '.')]
    pending_path = os.path.join(PENDING_UPLOAD_FOLDER, pending_files[0]) if pending_files else None

    def discard_pending():
        if pending_path and os.path.exists(pending_path): os.remove(pending_path)

    if action == 'cancel':
        discard_pending()
        return redirect(url_for('analyze'))
    if action == 'open':
        discard_pending()
        return redirect(url_for('results', sha256=existing.sha256))
    if action == 'reanalyze':
        discard_pending()
        return reanalyze(existing.sha256)
    if action == 'rename':
        new_name = secure_filename(request.form.get('new_filename', ''))
        if new_name:
            original_ext = os.path.splitext(existing.filename)[1]
            requested_base = os.path.splitext(new_name)[0]
            new_name = f"{requested_base}{original_ext}"
            existing.filename = new_name
            db.session.commit()
            flash(f"Existing analysis renamed to '{new_name}'. The binary hash is unchanged.")
        discard_pending()
        return redirect(url_for('results', sha256=existing.sha256))
    if action == 'replace' and pending_path:
        new_filename = secure_filename(request.form.get('new_filename', '')) or existing.filename
        try:
            _delete_analysis_assets(existing)
            analysis = _create_analysis(pending_path, new_filename)
            return redirect(url_for('results', sha256=analysis.sha256))
        except Exception as exc:
            logger.error(f"Replacement analysis failed: {exc}", exc_info=True)
            flash(f"Could not analyze the replacement file: {exc}")
            return redirect(url_for('analyze'))
    discard_pending()
    flash('The duplicate upload session expired. Please upload the file again.')
    return redirect(url_for('analyze'))

@app.route('/history')
def history():
    analyses = Analysis.query.order_by(Analysis.timestamp.desc()).all()
    return render_template('history.html', analyses=analyses)

@app.route('/history/delete/<string:sha256>', methods=['POST'])
def delete_analysis(sha256):
    analysis = Analysis.query.filter_by(sha256=sha256).first_or_404()
    filename = analysis.filename
    try:
        # Delete visual PNG representation
        png_path = os.path.join(app.config['UPLOAD_FOLDER'], analysis.png_path)
        if os.path.exists(png_path):
            os.remove(png_path)
            
        # Delete generated PDF report
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f"report_{analysis.sha256}.pdf")
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
            
        # Delete AI SVG diagram
        svg_path = os.path.join(app.config['UPLOAD_FOLDER'], f"diagram_{analysis.sha256}.svg")
        if os.path.exists(svg_path):
            os.remove(svg_path)
            
        # Delete actual binary file (renamed to sha256 + ext)
        ext = os.path.splitext(filename)[1]
        bin_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{analysis.sha256}{ext}")
        if os.path.exists(bin_path):
            os.remove(bin_path)
            
        # Delete original binary path if exists
        orig_bin_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(orig_bin_path):
            os.remove(orig_bin_path)
            
    except Exception as e:
        print(f"Error deleting analysis files: {e}")
        
    db.session.delete(analysis)
    db.session.commit()
    flash(f"Analysis session for {filename} has been successfully deleted.")
    return redirect(url_for('history'))

@app.route('/results/<string:sha256>/reanalyze', methods=['POST'])
def reanalyze(sha256):
    analysis = Analysis.query.filter_by(sha256=sha256).first_or_404()
    filename = analysis.filename
    try:
        # Find file path of original uploaded binary
        ext = os.path.splitext(filename)[1]
        bin_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{analysis.sha256}{ext}")
        if not os.path.exists(bin_path):
            # Try fallback to original name
            bin_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
        if not os.path.exists(bin_path):
            flash("Original binary file not found on disk. Cannot reanalyze.")
            return redirect(url_for('results', sha256=sha256))
            
        # Run analysis again
        results = analyze_file(bin_path, app.config['UPLOAD_FOLDER'])
        
        # Overwrite DB record values
        analysis.cnn_pred = results['model_results']['CNN']['class']
        analysis.cnn_conf = results['model_results']['CNN']['confidence']
        analysis.lstm_pred = results['model_results']['RNN_BiLSTM']['class']
        analysis.lstm_conf = results['model_results']['RNN_BiLSTM']['confidence']
        analysis.hybrid_pred = results['model_results']['Hybrid_CNN_LSTM']['class']
        analysis.hybrid_conf = results['model_results']['Hybrid_CNN_LSTM']['confidence']
        analysis.consensus = results['consensus']
        analysis.agreement = results['agreement']
        analysis.verdict = results['verdict']
        analysis.all_probs_json = json.dumps(results['all_probs'])
        
        # Regenerate AI report (forces overwrite)
        analysis.ai_report = generate_ai_malware_report(analysis)
        analysis.chat_history_json = None # reset chat history
        db.session.commit()
        
        # Regenerate SVG diagram (forces overwrite)
        svg_filename = f"diagram_{analysis.sha256}.svg"
        svg_full_path = os.path.join(app.config['UPLOAD_FOLDER'], svg_filename)
        if os.path.exists(svg_full_path):
            os.remove(svg_full_path)
        generate_ai_svg_diagram(analysis, app.config['UPLOAD_FOLDER'])
        
        flash("Reanalysis completed successfully. All prediction models and AI reports have been refreshed.")
    except Exception as e:
        flash(f"Error during reanalysis: {str(e)}")
        
    return redirect(url_for('results', sha256=sha256))

@app.route('/results/<string:sha256>')
def results(sha256):
    analysis = Analysis.query.filter_by(sha256=sha256).first_or_404()
    # Generate report on demand if not present (for old database records)
    if not analysis.ai_report:
        analysis.ai_report = generate_ai_malware_report(analysis)
        db.session.commit()
        
    # Generate SVG on demand if not present
    svg_filename = f"diagram_{analysis.sha256}.svg"
    svg_full_path = os.path.join(app.config['UPLOAD_FOLDER'], svg_filename)
    if not os.path.exists(svg_full_path):
        generate_ai_svg_diagram(analysis, app.config['UPLOAD_FOLDER'])
        
    chat_history = []
    if analysis.chat_history_json:
        try:
            chat_history = json.loads(analysis.chat_history_json)
        except Exception:
            chat_history = []
            
    return render_template(
        'results.html', 
        analysis=analysis, 
        mal_info=get_malware_info(analysis.consensus), 
        all_probs=json.loads(analysis.all_probs_json),
        chat_history=chat_history
    )

@app.route('/results/<string:sha256>/chat', methods=['POST'])
def chat_session(sha256):
    analysis = Analysis.query.filter_by(sha256=sha256).first_or_404()
    data = request.json or {}
    user_message = data.get("message", "").strip()
    history = data.get("history", [])
    
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
        
    from report_gen import read_openai_key
    from openai import OpenAI
    api_key = read_openai_key()
    if not api_key or OpenAI is None:
        return jsonify({
            "reply": "AI Chatbot is currently offline because the OpenAI API key is not configured or the library is missing."
        })
        
    client = OpenAI(api_key=api_key)
    mal_info = get_malware_info(analysis.consensus)
    
    system_content = (
        "You are MalVision's highly intelligent AI Malware Analyst Assistant. "
        "You specialize in reverse engineering, binary visual analytics, entropy investigation, and threat containment. "
        "Be helpful, professional, and concise. "
        "Base your answers on the visual machine learning consensus results and file metadata provided. "
        "If the user asks for recommendations, refer to the family threat profile and standard mitigation frameworks.\n\n"
        "REPORT SUGGESTION INSTRUCTION: If your response identifies a key recommendation or threat containment note that should be added to the report, append a block at the very end of your response formatted exactly as:\n"
        "---SUGGESTION---\n"
        "<concise Markdown bullet points of the finding or note to append to report>\n\n"
        f"Current Sample Context:\n"
        f"- Filename: {analysis.filename}\n"
        f"- File Size: {analysis.file_size} bytes\n"
        f"- Shannon Entropy: {analysis.entropy:.4f}\n"
        f"- File Type: {analysis.file_type}\n"
        f"- Consensus Malware Family: {analysis.consensus} ({mal_info['type']})\n"
        f"- ML Confidences: CNN ({analysis.cnn_conf*100:.1f}%), BiLSTM ({analysis.lstm_conf*100:.1f}%), Hybrid ({analysis.hybrid_conf*100:.1f}%)\n"
        f"- Risk Rating: {mal_info['risk']}\n"
        f"- Threat Details: {mal_info['description']}\n\n"
        f"Current Report Body:\n{analysis.ai_report}"
    )
    
    messages = [{"role": "system", "content": system_content}]
    for msg in history[-10:]:
        role = msg.get("role")
        content = msg.get("content")
        if role in {"user", "assistant"} and isinstance(content, str):
            messages.append({"role": role, "content": content[:2000]})
            
    messages.append({"role": "user", "content": user_message})
    
    try:
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            messages=messages,
            temperature=0.3
        )
        raw_reply = response.choices[0].message.content or ""
        
        suggestion = ""
        reply_clean = raw_reply
        if "---SUGGESTION---" in raw_reply:
            parts = raw_reply.split("---SUGGESTION---")
            reply_clean = parts[0].strip()
            suggestion = parts[1].strip()
            
        updated_history = history + [{"role": "user", "content": user_message}, {"role": "assistant", "content": reply_clean}]
        analysis.chat_history_json = json.dumps(updated_history)
        db.session.commit()
        
        res_payload = {"reply": reply_clean}
        if suggestion:
            res_payload["suggestion"] = suggestion
        return jsonify(res_payload)
    except Exception as e:
        return jsonify({"reply": f"**API Error:** {str(e)}"})

@app.route('/results/<string:sha256>/append_report', methods=['POST'])
def append_ai_report(sha256):
    analysis = Analysis.query.filter_by(sha256=sha256).first_or_404()
    data = request.json or {}
    text_to_append = str(data.get("text", "")).strip()
    if not text_to_append:
        return jsonify({"ok": False, "error": "No text provided"}), 400
        
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    current_content = analysis.ai_report or ""
    addition = f"\n\n## Analyst Note & Chat Suggestion ({timestamp})\n{text_to_append}\n"
    updated_content = current_content.rstrip() + addition
    analysis.ai_report = updated_content
    db.session.commit()
    
    return jsonify({"ok": True, "message": "Suggestion appended.", "report": updated_content})

@app.route('/results/<string:sha256>/report_text')
def get_report_text(sha256):
    analysis = Analysis.query.filter_by(sha256=sha256).first_or_404()
    return jsonify({"report": analysis.ai_report or ""})

@app.route('/report/<string:sha256>')
def generate_report(sha256):
    analysis = Analysis.query.filter_by(sha256=sha256).first_or_404()
    pdf_filename = create_pdf_report(analysis, app.config['UPLOAD_FOLDER'])
    
    # Secure report file download naming logic
    clean_bin_name = secure_filename(analysis.filename)
    base_name = os.path.splitext(clean_bin_name)[0]
    download_name = f"{base_name}_{analysis.sha256}.pdf"
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        pdf_filename, 
        as_attachment=True,
        download_name=download_name
    )

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    logger.info("==========================================================")
    logger.info("  MalVision AI Malware Analysis Server Started           ")
    logger.info("  Running on http://127.0.0.1:5000 (all network interfaces)")
    logger.info("==========================================================")
    app.run(host='0.0.0.0', port=5000)
