"""
Semantic Attack Detector Service
Uses sentence-transformers to detect paraphrased attacks via semantic similarity
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from sentence_transformers import SentenceTransformer, util
import os
import json
import numpy as np
import csv
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Global model and embeddings cache
model = None
attack_embeddings = {}
attack_texts = {}

def load_model():
    """Load sentence transformer model on startup"""
    global model
    print("[*] Loading semantic model...")
    # Using lightweight fast model (80MB, good for paraphrase detection)
    model = SentenceTransformer('paraphrase-MiniLM-L3-v2')
    print("[+] Model loaded successfully")

def load_attack_patterns():
    """Load attack patterns from CSV files and pre-compute embeddings"""
    global attack_embeddings, attack_texts
    
    print("[*] Loading attack patterns...")
    
    # Path to datasets
    datasets_dir = Path(__file__).parent.parent / 'prototype' / 'datasets'
    
    categories = {
        'promptInjection': [],
        'jailbreak': [],
        'dataLeakage': []
    }
    
    # Load CSV files
    csv_files = {
        'promptInjection': datasets_dir / 'prompt_injection_attacks.csv',
        'jailbreak': datasets_dir / 'jailbreak_attacks.csv',
        'dataLeakage': datasets_dir / 'data_leakage_attacks.csv',
        'real': datasets_dir / 'prompt_injections.csv'
    }
    
    for category, filepath in csv_files.items():
        if not filepath.exists():
            print(f"   [!] Missing: {filepath.name}")
            continue
            
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Extract text (different columns for different CSVs)
                text = row.get('template') or row.get('text', '')
                if text:
                    if category == 'real':
                        # Map real attacks to internal categories
                        ext_category = row.get('category', '')
                        if 'Instruction' in ext_category or 'Hijacking' in ext_category:
                            categories['promptInjection'].append(text)
                        elif 'Jailbreak' in ext_category or 'Role' in ext_category:
                            categories['jailbreak'].append(text)
                        else:
                            categories['jailbreak'].append(text)
                    else:
                        categories[category].append(text)
    
    # Pre-compute embeddings for each category
    for category, texts in categories.items():
        if texts:
            print(f"   [*] Computing embeddings for {len(texts)} {category} attacks...")
            embeddings = model.encode(texts, convert_to_tensor=True)
            attack_embeddings[category] = embeddings
            attack_texts[category] = texts
            print(f"   [+] {category}: {len(texts)} patterns loaded")
    
    total = sum(len(texts) for texts in categories.values())
    print(f"[+] Total patterns embedded: {total}\n")

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'patterns_loaded': len(attack_embeddings)
    })

@app.route('/detect', methods=['POST'])
def detect():
    """
    Detect attack similarity
    Request: { "text": "user input", "category": "promptInjection" }
    Response: { "score": 0-100, "similarity": 0-1, "matched": "closest pattern" }
    """
    try:
        data = request.json
        text = data.get('text', '')
        category = data.get('category', 'promptInjection')
        
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        if category not in attack_embeddings:
            return jsonify({'error': f'Unknown category: {category}'}), 400
        
        # Encode user input
        text_embedding = model.encode(text, convert_to_tensor=True)
        
        # Calculate similarity with all attack patterns in category
        similarities = util.cos_sim(text_embedding, attack_embeddings[category])
        
        # Find best match
        max_similarity = float(similarities.max())
        best_match_idx = int(similarities.argmax())
        matched_pattern = attack_texts[category][best_match_idx]
        
        # Convert to 0-100 score
        score = int(max_similarity * 100)
        
        return jsonify({
            'score': score,
            'similarity': round(max_similarity, 4),
            'matched': matched_pattern[:100],  # Truncate for readability
            'category': category
        })
        
    except Exception as e:
        print(f"[-] Error in detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/batch-detect', methods=['POST'])
def batch_detect():
    """
    Batch detection for multiple categories
    Request: { "text": "user input" }
    Response: { "promptInjection": score, "jailbreak": score, "dataLeakage": score }
    """
    try:
        data = request.json
        text = data.get('text', '')
        
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Encode once
        text_embedding = model.encode(text, convert_to_tensor=True)
        
        results = {}
        for category, embeddings in attack_embeddings.items():
            similarities = util.cos_sim(text_embedding, embeddings)
            max_similarity = float(similarities.max())
            results[category] = int(max_similarity * 100)
        
        return jsonify(results)
        
    except Exception as e:
        print(f"[-] Error in batch detection: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("Semantic Attack Detector Service")
    print("=" * 50)
    
    # Load model and patterns
    load_model()
    load_attack_patterns()
    
    print("=" * 50)
    print("Server starting on http://localhost:5001")
    print("=" * 50)
    
    # Start Flask server
    app.run(host='0.0.0.0', port=5001, debug=False)
