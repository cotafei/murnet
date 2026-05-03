"""
MURNET AUTH v5.0
JWT-based authentication for REST API
"""

import jwt
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable
from functools import wraps
from dataclasses import dataclass
import threading


@dataclass
class AuthToken:
    """JWT токен с метаданными"""
    token: str
    expires_at: float
    node_address: str
    client_type: str
    permissions: list


class AuthManager:
    """
    Управление аутентификацией
    - JWT tokens
    - API Keys для автоматизации
    - Rate limiting
    """
    
    def __init__(self, secret_key: Optional[str] = None, 
                 token_expire_hours: int = 24):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_expire_hours = token_expire_hours
        
        # Хранилище активных токенов (для отзыва)
        self.active_tokens: Dict[str, AuthToken] = {}
        self.token_lock = threading.RLock()
        
        # Rate limiting
        self.request_counts: Dict[str, list] = {}  # IP -> [timestamps]
        self.rate_lock = threading.Lock()
        
        # API Keys (для сервисов)
        self.api_keys: Dict[str, Dict] = {}
    
    def generate_token(self, node_address: str, 
                       client_type: str = "android",
                       permissions: Optional[list] = None) -> AuthToken:
        """Генерация JWT токена"""
        now = datetime.utcnow()
        expires = now + timedelta(hours=self.token_expire_hours)
        
        payload = {
            'iss': 'murnet',
            'sub': node_address,
            'iat': now,
            'exp': expires,
            'client_type': client_type,
            'permissions': permissions or ['read', 'write'],
            'jti': secrets.token_hex(16)  # Unique token ID
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        auth_token = AuthToken(
            token=token,
            expires_at=expires.timestamp(),
            node_address=node_address,
            client_type=client_type,
            permissions=payload['permissions']
        )
        
        with self.token_lock:
            self.active_tokens[payload['jti']] = auth_token
        
        return auth_token
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Верификация JWT токена"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Проверка отзыва
            jti = payload.get('jti')
            with self.token_lock:
                if jti and jti not in self.active_tokens:
                    return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Отзыв токена"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'], 
                               options={"verify_exp": False})
            jti = payload.get('jti')
            
            with self.token_lock:
                if jti in self.active_tokens:
                    del self.active_tokens[jti]
                    return True
            return False
            
        except jwt.InvalidTokenError:
            return False
    
    def cleanup_expired_tokens(self):
        """Очистка истёкших токенов"""
        now = time.time()
        with self.token_lock:
            expired = [
                jti for jti, token in self.active_tokens.items()
                if token.expires_at < now
            ]
            for jti in expired:
                del self.active_tokens[jti]
            return len(expired)
    
    def generate_api_key(self, name: str, permissions: list) -> str:
        """Генерация API ключа для сервисов"""
        key = f"mn_{secrets.token_urlsafe(32)}"
        self.api_keys[key] = {
            'name': name,
            'permissions': permissions,
            'created': time.time(),
            'last_used': None
        }
        return key
    
    def verify_api_key(self, key: str) -> Optional[Dict]:
        """Проверка API ключа"""
        if key in self.api_keys:
            self.api_keys[key]['last_used'] = time.time()
            return self.api_keys[key]
        return None
    
    def check_rate_limit(self, identifier: str, 
                        max_requests: int = 100,
                        window_seconds: int = 60) -> bool:
        """Проверка rate limit"""
        now = time.time()
        
        with self.rate_lock:
            if identifier not in self.request_counts:
                self.request_counts[identifier] = []
            
            # Очистка старых запросов
            self.request_counts[identifier] = [
                t for t in self.request_counts[identifier]
                if now - t < window_seconds
            ]
            
            # Проверка лимита
            if len(self.request_counts[identifier]) >= max_requests:
                return False
            
            # Добавление текущего запроса
            self.request_counts[identifier].append(now)
            return True
    
    def get_rate_limit_status(self, identifier: str,
                              max_requests: int = 100,
                              window_seconds: int = 60) -> Dict:
        """Статус rate limit"""
        now = time.time()
        
        with self.rate_lock:
            requests = self.request_counts.get(identifier, [])
            current_window = [t for t in requests if now - t < window_seconds]
            
            return {
                'limit': max_requests,
                'remaining': max(0, max_requests - len(current_window)),
                'reset_at': min(current_window) + window_seconds if current_window else now,
                'window': window_seconds
            }


# ==================== DECORATORS ====================

def require_auth(auth_manager: AuthManager, permissions: Optional[list] = None):
    """Декоратор для проверки аутентификации"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # В FastAPI/Flask токен берётся из headers
            # Здесь заглушка для примера
            token = kwargs.get('token') or (args[0] if args else None)
            
            if not token:
                raise AuthenticationError("Token required")
            
            payload = auth_manager.verify_token(token)
            if not payload:
                raise AuthenticationError("Invalid or expired token")
            
            # Проверка permissions
            if permissions:
                user_perms = set(payload.get('permissions', []))
                if not set(permissions).issubset(user_perms):
                    raise AuthorizationError("Insufficient permissions")
            
            # Добавляем payload в kwargs
            kwargs['auth_payload'] = payload
            return func(*args, **kwargs)
        return wrapper
    return decorator


def rate_limited(auth_manager: AuthManager, 
                 max_requests: int = 100,
                 window_seconds: int = 60,
                 identifier_func: Optional[Callable] = None):
    """Декоратор для rate limiting"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Определяем идентификатор
            if identifier_func:
                identifier = identifier_func(*args, **kwargs)
            else:
                identifier = kwargs.get('client_ip', 'unknown')
            
            if not auth_manager.check_rate_limit(identifier, max_requests, window_seconds):
                raise RateLimitError("Rate limit exceeded")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ==================== EXCEPTIONS ====================

class AuthenticationError(Exception):
    """Ошибка аутентификации"""
    pass


class AuthorizationError(Exception):
    """Ошибка авторизации (недостаточно прав)"""
    pass


class RateLimitError(Exception):
    """Превышен rate limit"""
    pass


# ==================== MOBILE AUTH ====================

class MobileAuthManager(AuthManager):
    """Расширенный auth manager для мобильных устройств"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.device_tokens: Dict[str, str] = {}  # device_id -> token
        self.push_tokens: Dict[str, str] = {}    # node_address -> push_token
    
    def register_device(self, device_id: str, node_address: str,
                       push_token: Optional[str] = None) -> AuthToken:
        """Регистрация мобильного устройства"""
        # Отзыв старого токена
        if device_id in self.device_tokens:
            old_token = self.device_tokens[device_id]
            self.revoke_token(old_token)
        
        # Создание нового токена с длительным сроком
        token = self.generate_token(
            node_address=node_address,
            client_type="android",
            permissions=['read', 'write', 'sync', 'push']
        )
        
        self.device_tokens[device_id] = token.token
        
        if push_token:
            self.push_tokens[node_address] = push_token
        
        return token
    
    def get_push_token(self, node_address: str) -> Optional[str]:
        """Получение push токена для уведомлений"""
        return self.push_tokens.get(node_address)
    
    def validate_mobile_request(self, token: str, device_id: str) -> Optional[Dict]:
        """Валидация запроса от мобильного устройства"""
        # Проверяем, что токен соответствует device_id
        if device_id not in self.device_tokens:
            return None
        
        if self.device_tokens[device_id] != token:
            return None
        
        return self.verify_token(token)
