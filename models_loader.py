import os
import tensorflow as tf

# Suppress TF logs
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

base_dir = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(base_dir, 'malware_v2', 'models')
if not os.path.exists(MODELS_DIR):
    MODELS_DIR = os.path.join(os.path.dirname(base_dir), 'malware_v2', 'models')

# Global variables for models
_cnn = None
_lstm = None
_hybrid = None

def get_models():
    global _cnn, _lstm, _hybrid
    if _cnn is None:
        print("Loading models...")
        _cnn = tf.keras.models.load_model(os.path.join(MODELS_DIR, 'CNN_best.h5'))
        _lstm = tf.keras.models.load_model(os.path.join(MODELS_DIR, 'RNN_BiLSTM_best.h5'))
        _hybrid = tf.keras.models.load_model(os.path.join(MODELS_DIR, 'Hybrid_CNN_LSTM_best.h5'))
        print("Models loaded successfully.")
    return _cnn, _lstm, _hybrid
