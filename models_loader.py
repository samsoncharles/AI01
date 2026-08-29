import os
import tensorflow as tf

# Suppress TF logs
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import logging

base_dir = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(base_dir, 'malware_v2', 'models')

# Global variables for models
_cnn = None
_lstm = None
_hybrid = None

def get_models():
    global _cnn, _lstm, _hybrid
    if _cnn is None:
        if not os.path.exists(MODELS_DIR):
            logging.warning(f"Models directory not found at {MODELS_DIR}. Skipping model loading.")
            return None, None, None
            
        try:
            print("Loading models...")
            _cnn = tf.keras.models.load_model(os.path.join(MODELS_DIR, 'CNN_best.h5'))
            _lstm = tf.keras.models.load_model(os.path.join(MODELS_DIR, 'RNN_BiLSTM_best.h5'))
            _hybrid = tf.keras.models.load_model(os.path.join(MODELS_DIR, 'Hybrid_CNN_LSTM_best.h5'))
            print("Models loaded successfully.")
        except Exception as e:
            logging.warning(f"Failed to load models: {e}. Skipping model loading.")
            _cnn = None
            _lstm = None
            _hybrid = None
            return None, None, None
    return _cnn, _lstm, _hybrid
