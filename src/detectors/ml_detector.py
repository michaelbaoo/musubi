import numpy as np
import pickle
from typing import Dict, List, Tuple, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from loguru import logger
import re
from datetime import datetime
import joblib

class MLSpamDetector:
    def __init__(self, model_path: Optional[str] = None):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=10000,
            ngram_range=(1, 3),
            stop_words='english',
            min_df=2,
            max_df=0.95
        )
        
        self.ensemble_models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boost': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'naive_bayes': MultinomialNB(),
            'logistic': LogisticRegression(max_iter=1000, random_state=42)
        }
        
        self.bert_tokenizer = None
        self.bert_model = None
        self.model_path = model_path
        self.is_trained = False
        
        if model_path:
            self.load_models(model_path)
    
    def extract_features(self, email_content: str, headers: Dict[str, str]) -> Dict[str, float]:
        features = {}
        
        features['length'] = len(email_content)
        features['num_links'] = len(re.findall(r'https?://\S+', email_content))
        features['num_emails'] = len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email_content))
        
        features['caps_ratio'] = sum(1 for c in email_content if c.isupper()) / max(len(email_content), 1)
        features['exclamation_count'] = email_content.count('!')
        features['question_count'] = email_content.count('?')
        features['dollar_count'] = email_content.count('$')
        
        spam_keywords = [
            'free', 'win', 'winner', 'cash', 'prize', 'bonus', 'earn',
            'income', 'double', 'triple', 'thousand', 'million', 'billion',
            'click here', 'click now', 'urgent', 'act now', 'limited time',
            'special offer', 'guarantee', 'risk-free', 'no cost', 'no fees',
            'congratulations', 'viagra', 'pharmacy', 'pills', 'medication',
            'weight loss', 'lose weight', 'diet', 'bitcoin', 'crypto',
            'investment', 'forex', 'trading', 'profit', 'revenue'
        ]
        
        email_lower = email_content.lower()
        for keyword in spam_keywords:
            features[f'keyword_{keyword.replace(" ", "_")}'] = int(keyword in email_lower)
        
        features['has_unsubscribe'] = int('unsubscribe' in email_lower)
        features['has_reply_to'] = int('Reply-To' in headers)
        features['has_list_unsubscribe'] = int('List-Unsubscribe' in headers)
        
        suspicious_patterns = [
            r'[A-Z]{5,}',  # Many consecutive capitals
            r'\d{5,}',  # Many consecutive numbers
            r'[!]{3,}',  # Multiple exclamation marks
            r'[A-Za-z]+\d+[A-Za-z]+',  # Mixed alphanumeric
        ]
        
        for i, pattern in enumerate(suspicious_patterns):
            features[f'pattern_{i}'] = len(re.findall(pattern, email_content))
        
        return features
    
    def train_ensemble(self, X_train: np.ndarray, y_train: np.ndarray):
        for name, model in self.ensemble_models.items():
            logger.info(f"Training {name} model...")
            model.fit(X_train, y_train)
            
            scores = cross_val_score(model, X_train, y_train, cv=5)
            logger.info(f"{name} CV Score: {scores.mean():.3f} (+/- {scores.std() * 2:.3f})")
        
        self.is_trained = True
    
    def predict_ensemble(self, X: np.ndarray) -> Tuple[float, Dict[str, float]]:
        if not self.is_trained:
            raise ValueError("Models must be trained before prediction")
        
        predictions = {}
        weights = {
            'random_forest': 0.3,
            'gradient_boost': 0.3,
            'naive_bayes': 0.2,
            'logistic': 0.2
        }
        
        weighted_sum = 0
        for name, model in self.ensemble_models.items():
            pred_proba = model.predict_proba(X)[0][1]  # Probability of spam
            predictions[name] = pred_proba
            weighted_sum += pred_proba * weights[name]
        
        return weighted_sum, predictions
    
    def load_bert_model(self, model_name: str = "bert-base-uncased"):
        try:
            self.bert_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.bert_model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=2
            )
            self.bert_model.eval()
            logger.info(f"Loaded BERT model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to load BERT model: {e}")
            self.bert_model = None
            self.bert_tokenizer = None
    
    def predict_bert(self, text: str) -> float:
        if not self.bert_model or not self.bert_tokenizer:
            return 0.5  # Neutral score if BERT not available
        
        try:
            inputs = self.bert_tokenizer(
                text,
                truncation=True,
                padding=True,
                max_length=512,
                return_tensors="pt"
            )
            
            with torch.no_grad():
                outputs = self.bert_model(**inputs)
                logits = outputs.logits
                probabilities = torch.nn.functional.softmax(logits, dim=-1)
                spam_probability = probabilities[0][1].item()
            
            return spam_probability
        except Exception as e:
            logger.error(f"BERT prediction failed: {e}")
            return 0.5
    
    def detect_spam(
        self,
        email_content: str,
        subject: str,
        headers: Dict[str, str],
        use_bert: bool = True
    ) -> Tuple[float, List[str], Dict[str, Any]]:
        
        full_text = f"{subject} {email_content}"
        features = self.extract_features(full_text, headers)
        
        reasons = []
        details = {
            'features': features,
            'model_scores': {}
        }
        
        feature_vector = np.array(list(features.values())).reshape(1, -1)
        
        if self.is_trained:
            ensemble_score, model_predictions = self.predict_ensemble(feature_vector)
            details['model_scores']['ensemble'] = model_predictions
            details['ensemble_score'] = ensemble_score
        else:
            ensemble_score = 0.5
        
        if use_bert and self.bert_model:
            bert_score = self.predict_bert(full_text)
            details['model_scores']['bert'] = bert_score
        else:
            bert_score = ensemble_score
        
        final_score = (ensemble_score * 0.6 + bert_score * 0.4) if use_bert else ensemble_score
        
        if features['caps_ratio'] > 0.3:
            reasons.append("High ratio of capital letters")
            final_score += 0.1
        
        if features['num_links'] > 5:
            reasons.append(f"Contains {features['num_links']} links")
            final_score += 0.15
        
        if features['exclamation_count'] > 3:
            reasons.append("Excessive exclamation marks")
            final_score += 0.1
        
        spam_keyword_count = sum(1 for k, v in features.items() if k.startswith('keyword_') and v == 1)
        if spam_keyword_count > 3:
            reasons.append(f"Contains {spam_keyword_count} spam keywords")
            final_score += 0.2
        
        if not features['has_unsubscribe'] and features['num_links'] > 0:
            reasons.append("Commercial email without unsubscribe option")
            final_score += 0.1
        
        final_score = min(1.0, final_score)
        
        if final_score > 0.7:
            reasons.insert(0, f"High spam probability: {final_score:.2%}")
        elif final_score > 0.5:
            reasons.insert(0, f"Medium spam probability: {final_score:.2%}")
        
        return final_score, reasons, details
    
    def save_models(self, path: str):
        model_data = {
            'ensemble_models': self.ensemble_models,
            'tfidf_vectorizer': self.tfidf_vectorizer,
            'is_trained': self.is_trained,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        joblib.dump(model_data, path)
        logger.info(f"Models saved to {path}")
    
    def load_models(self, path: str):
        try:
            model_data = joblib.load(path)
            self.ensemble_models = model_data['ensemble_models']
            self.tfidf_vectorizer = model_data['tfidf_vectorizer']
            self.is_trained = model_data['is_trained']
            logger.info(f"Models loaded from {path}")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            self.is_trained = False