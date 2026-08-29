import os
import math
import hashlib
import numpy as np
import magic
from PIL import Image

# Use our global loader
from models_loader import get_models

Image.MAX_IMAGE_PIXELS = None

ALL_CLASSES = [
    'Adialer.C', 'Agent.FYI', 'Allaple.A', 'Allaple.L', 'Alueron.gen!J',
    'Autorun.K', 'C2LOP.P', 'C2LOP.gen!g', 'Dialplatform.B', 'Dontovo.A',
    'Fakerean', 'Instantaccess', 'Lolyda.AA1', 'Lolyda.AA2', 'Lolyda.AA3',
    'Lolyda.AT', 'Malex.gen!J', 'Obfuscator.AD', 'Rbot!gen', 'Rbotigen',
    'Skintrim.N', 'Swizzor.gen!E', 'Swizzor.gen!I', 'VB.AT', 'Wintrim.BX',
    'Yuner.A'
]

IMG_SIZE = 64

def shannon_entropy(data):
    """Calculate the Shannon entropy of a byte array."""
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return float(entropy)

def compute_hashes_and_entropy(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()
    entropy = shannon_entropy(data)
    
    # python-magic file type
    file_type = magic.from_file(filepath)
    size_bytes = len(data)
    
    return {
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
        'sha512': sha512,
        'entropy': entropy,
        'file_type': file_type,
        'size_bytes': size_bytes
    }

def binary_to_grayscale(filepath, upload_dir, base_name=None):
    with open(filepath, 'rb') as f:
        bytearr = np.frombuffer(f.read(), dtype=np.uint8)

    size = len(bytearr)
    width = int(math.sqrt(size))
    if width < 1:
        raise ValueError("File too small")

    height = math.ceil(size / width)
    padded = np.zeros(width * height, dtype=np.uint8)
    padded[:size] = bytearr
    img_arr = padded.reshape((height, width))

    img = Image.fromarray(img_arr, mode='L')
    if not base_name:
        base_name = os.path.splitext(os.path.basename(filepath))[0]
    out_name = f"{base_name}_gray.png"
    out_path = os.path.join(upload_dir, out_name)
    img.save(out_path)
    return out_path, out_name

def preprocess_image(path):
    img = Image.open(path).convert('L').resize((IMG_SIZE, IMG_SIZE))
    arr = np.array(img, dtype=np.float32) / 255.0
    return arr[np.newaxis, ..., np.newaxis], arr[np.newaxis, ...]

def predict(image_path):
    cnn, lstm, hybrid = get_models()
    cnn_input, rnn_input = preprocess_image(image_path)

    cnn_pred = cnn.predict(cnn_input, verbose=0)[0]
    lstm_pred = lstm.predict(rnn_input, verbose=0)[0]
    hybrid_pred = hybrid.predict(cnn_input, verbose=0)[0]

    all_probs = {
        'CNN': {ALL_CLASSES[i]: float(cnn_pred[i]) for i in range(len(ALL_CLASSES))},
        'RNN_BiLSTM': {ALL_CLASSES[i]: float(lstm_pred[i]) for i in range(len(ALL_CLASSES))},
        'Hybrid_CNN_LSTM': {ALL_CLASSES[i]: float(hybrid_pred[i]) for i in range(len(ALL_CLASSES))}
    }

    preds = [
        ('CNN', cnn_pred),
        ('RNN_BiLSTM', lstm_pred),
        ('Hybrid_CNN_LSTM', hybrid_pred)
    ]

    votes = {}
    model_results = {}
    
    for model_name, pred in preds:
        idx = int(np.argmax(pred))
        cls = ALL_CLASSES[idx]
        conf = float(pred[idx])
        votes[cls] = votes.get(cls, 0) + 1
        model_results[model_name] = {'class': cls, 'confidence': conf}

    consensus = max(votes, key=votes.get)
    agreement = votes[consensus]

    if agreement == 3:
        verdict = "HIGH CONFIDENCE"
    elif agreement == 2:
        verdict = "MODERATE CONFIDENCE"
    else:
        verdict = "LOW CONFIDENCE - models disagree"

    return model_results, all_probs, consensus, agreement, verdict

def analyze_file(filepath, upload_dir):
    meta = compute_hashes_and_entropy(filepath)
    
    # Rename file to its sha256 hash
    ext = os.path.splitext(filepath)[1]
    new_filename = f"{meta['sha256']}{ext}"
    new_filepath = os.path.join(upload_dir, new_filename)
    if os.path.abspath(filepath) != os.path.abspath(new_filepath):
        if os.path.exists(new_filepath):
            os.remove(new_filepath)
        os.rename(filepath, new_filepath)
    
    png_path, png_filename = binary_to_grayscale(new_filepath, upload_dir, meta['sha256'])
    model_results, all_probs, consensus, agreement, verdict = predict(png_path)
    
    return {
        'meta': meta,
        'png_filename': png_filename,
        'model_results': model_results,
        'all_probs': all_probs,
        'consensus': consensus,
        'agreement': agreement,
        'verdict': verdict
    }
