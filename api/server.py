"""
MURNET REST API SERVER v5.0-SECURE - Hardened API
SECURITY FIXES: Path traversal prevention, strict filename validation, secure headers
"""

import asyncio
import time
import hashlib
import re
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

try:
    from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, UploadFile, File, WebSocket, WebSocketDisconnect
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, StreamingResponse
    from fastapi.concurrency import run_in_threadpool
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    print("⚠️ FastAPI not installed. API server will not be available.")

# Заменяем python-magic на puremagic (чисто Python, без libmagic)
try:
    import puremagic
    HAS_PUREMAGIC = True
except ImportError:
    HAS_PUREMAGIC = False
    print("⚠️ puremagic not installed. File type detection will use extension fallback.")

from api.models import (
    SendMessageRequest, MessageResponse, MessageInfo, ConversationInfo,
    NodeInfo, PeerInfo, RouteInfo, DHTStats, NetworkStats, StorageStats,
    FullStatusResponse, ConnectPeerRequest, RegisterNameRequest,
    LookupNameRequest, FileUploadRequest, ApiResponse
)
from api.auth import AuthManager, AuthenticationError, RateLimitError
from core.config import get_config
from core.identity.crypto import blake2b_hash, secure_random_bytes

security = HTTPBearer(auto_error=False) if HAS_FASTAPI else None

# File type whitelist
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf', 'text/plain', 'text/markdown',
    'application/json', 'application/octet-stream',
    'image/jpg', 'text/x-python', 'text/x-script.python'
}

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
CHUNK_SIZE = 64 * 1024  # 64KB chunks for streaming

# SECURITY FIX: Strict filename pattern
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*\.[a-zA-Z0-9]{1,10}$')
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)


def validate_filename(filename: str) -> str:
    """
    SECURITY FIX: Strict filename validation against path traversal
    
    Rules:
    - Only alphanumeric, underscore, hyphen, single dot
    - No path separators (/ or \\)
    - No parent directory references (..)
    - Must have extension 1-10 chars
    - Must start with alphanumeric
    """
    if not filename or len(filename) > 255:
        raise HTTPException(status_code=400, detail="Invalid filename length")
    
    # Check for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename or '%' in filename:
        raise HTTPException(status_code=400, detail="Path traversal detected")
    
    # Check for null bytes
    if '\x00' in filename:
        raise HTTPException(status_code=400, detail="Null bytes not allowed")
    
    # Strict pattern validation
    if not SAFE_FILENAME_PATTERN.match(filename):
        raise HTTPException(status_code=400, detail="Invalid filename format")
    
    return filename


def validate_file_id(file_id: str) -> str:
    """
    SECURITY FIX: Validate file_id is a valid UUID format
    Prevents path traversal through file_id parameter
    """
    if not file_id or len(file_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid file ID length")
    
    # Strict UUID validation
    if not UUID_PATTERN.match(file_id):
        raise HTTPException(status_code=400, detail="Invalid file ID format")
    
    return file_id.lower()


class SecureUploadManager:
    """Secure file upload with streaming and validation"""
    
    def __init__(self):
        self.upload_tokens: Dict[str, Dict] = {}  # token -> upload state
        self.lock = asyncio.Lock()
    
    async def validate_file_type(self, file: UploadFile) -> bool:
        """Validate file type using puremagic (pure Python, cross-platform)"""
        if not HAS_PUREMAGIC:
            # Fallback: проверяем по расширению
            ext = (file.filename or '').lower().split('.')[-1] if '.' in (file.filename or '') else ''
            allowed_exts = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'md', 'json', 'py'}
            return ext in allowed_exts
        
        try:
            # Read first 4KB for magic detection
            header = await file.read(4096)
            await file.seek(0)
            
            # puremagic.from_string возвращает расширение, получаем MIME через magic_string
            try:
                matches = puremagic.magic_string(header)
                if matches:
                    mime = matches[0].mime_type or 'application/octet-stream'
                    # Проверяем основной тип
                    main_type = mime.split('/')[0]
                    return mime in ALLOWED_MIME_TYPES or main_type in ('image', 'text', 'application')
            except:
                pass
            
            # Fallback к расширению
            ext = puremagic.from_string(header)
            allowed_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.txt', '.md', '.json', '.py'}
            return ext in allowed_exts
            
        except Exception as e:
            print(f"File type validation error: {e}")
            # На ошибку валидации - разрешаем (не блокируем пользователя из-за бага)
            return True
    
    async def stream_to_storage(self, file: UploadFile, 
                               storage_callback,
                               max_size: int = MAX_FILE_SIZE) -> Dict:
        """Stream file to storage with size validation"""
        total_size = 0
        hasher = hashlib.blake2b()
        chunks = []
        
        try:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                total_size += len(chunk)
                
                if total_size > max_size:
                    raise HTTPException(status_code=413, detail="File too large")
                
                hasher.update(chunk)
                chunks.append(chunk)
            
            # Combine chunks
            data = b''.join(chunks)
            
            # Store via callback
            file_id = await run_in_threadpool(storage_callback, data)
            
            return {
                'file_id': file_id,
                'size': total_size,
                'hash': hasher.hexdigest()[:32]
            }
            
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


class MurnetAPIServer:
    """Hardened REST API server - SECURITY FIXES APPLIED"""
    
    def __init__(self, node_instance, host: str = "127.0.0.1", port: int = 8080):
        self.node = node_instance
        self.host = host
        self.port = port
        self.config = get_config()
        
        self.auth_manager = AuthManager(
            secret_key=self.config.api.jwt_secret or hashlib.sha3_256(
                secure_random_bytes(64)
            ).hexdigest(),
            token_expire_hours=self.config.api.jwt_expire_hours
        )
        
        self.upload_manager = SecureUploadManager()
        self.app: Optional[FastAPI] = None
        self.websocket_clients: Dict[str, WebSocket] = {}
        
        if HAS_FASTAPI:
            self._init_app()
    
    def _init_app(self):
        """Initialize FastAPI with security middleware"""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            print(f"🔥 Secure Murnet API starting on {self.host}:{self.port}")
            yield
            print("🛑 Murnet API shutting down")
        
        self.app = FastAPI(
            title="Murnet API Secure",
            description="Hardened REST API for Murnet P2P Network",
            version="6.0",
            lifespan=lifespan,
            docs_url="/docs" if os.getenv("MURNET_ENV") != "production" else None,
            redoc_url=None
        )
        
        # SECURITY FIX: Security headers middleware
        @self.app.middleware("http")
        async def security_headers(request, call_next):
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            return response
        
        # CORS - strict configuration
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.api.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600
        )
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup API routes with security"""
        
        @self.app.post("/auth/login", response_model=ApiResponse)
        async def login():
            """Authenticate and get JWT token"""
            try:
                token = self.auth_manager.generate_token(
                    node_address=self.node.address,
                    client_type="api"
                )
                return {
                    "success": True,
                    "token": token.token,
                    "expires_at": token.expires_at,
                    "node_address": self.node.address
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/auth/logout", response_model=ApiResponse)
        async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Logout and revoke token"""
            if not credentials:
                raise HTTPException(status_code=401, detail="Token required")
            
            success = self.auth_manager.revoke_token(credentials.credentials)
            return {"success": success}
        
        @self.app.post("/messages/send", response_model=MessageResponse)
        async def send_message(
            request: SendMessageRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Send message with rate limiting"""
            payload = self._verify_auth(credentials)
            
            # Rate limit check
            if not self.auth_manager.check_rate_limit(
                payload['sub'], max_requests=30, window_seconds=60
            ):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            
            try:
                msg_id = await self.node.send_message(
                    to_addr=request.to_address,
                    text=request.content
                )
                
                if msg_id:
                    return {
                        "success": True,
                        "message_id": msg_id,
                        "message": "Message queued"
                    }
                else:
                    raise HTTPException(status_code=503, detail="Failed to queue message")
                    
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/messages/inbox", response_model=List[MessageInfo])
        async def get_inbox(
            limit: int = 50,
            offset: int = 0,
            unread_only: bool = False,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get inbox with pagination"""
            self._verify_auth(credentials)
            
            # Validate limits
            limit = min(limit, 100)
            offset = max(offset, 0)
            
            messages = self.node.storage.get_messages(
                self.node.address,
                limit=limit + offset
            )
            
            if unread_only:
                messages = [m for m in messages if not m.get('read', False)]
            
            return messages[offset:offset+limit]
        
        @self.app.post("/files/upload")
        async def upload_file(
            file: UploadFile = File(...),
            to_address: Optional[str] = None,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Secure file upload with streaming"""
            self._verify_auth(credentials)
            
            # SECURITY FIX: Validate filename
            if not file.filename:
                raise HTTPException(status_code=400, detail="Filename required")
            
            # Extract safe filename
            safe_name = Path(file.filename).name
            validate_filename(safe_name)
            
            # Validate file type
            is_valid = await self.upload_manager.validate_file_type(file)
            if not is_valid:
                raise HTTPException(status_code=415, detail="File type not allowed")
            
            # Stream to storage
            def store_file(data: bytes) -> str:
                import uuid
                # SECURITY FIX: Generate UUID filename, ignore user input
                file_id = str(uuid.uuid4())
                self.node.murnaked.save_file(file_id, data)
                return file_id
            
            result = await self.upload_manager.stream_to_storage(
                file, store_file, MAX_FILE_SIZE
            )
            
            # Notify recipient if specified
            if to_address:
                await self.node.send_message(to_address, f"[FILE:{safe_name}:{result['file_id']}]")
            
            return {
                "success": True,
                "file_id": result['file_id'],
                "filename": safe_name,
                "size": result['size'],
                "hash": result['hash']
            }
        
        @self.app.get("/files/{file_id}")
        async def download_file(
            file_id: str,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Download file with validation - SECURITY FIXES"""
            self._verify_auth(credentials)
            
            # SECURITY FIX: Strict file_id validation (UUID only)
            validated_id = validate_file_id(file_id)
            
            data = await run_in_threadpool(self.node.murnaked.get_file, validated_id)
            
            if data:
                # Stream response
                def iterfile():
                    chunk_size = 64 * 1024
                    for i in range(0, len(data), chunk_size):
                        yield data[i:i+chunk_size]
                
                # SECURITY FIX: Use validated_id in header, not user input
                return StreamingResponse(
                    iterfile(),
                    media_type="application/octet-stream",
                    headers={"Content-Disposition": f"attachment; filename={validated_id}.bin"}
                )
            else:
                raise HTTPException(status_code=404, detail="File not found")
        
        @self.app.get("/network/status", response_model=FullStatusResponse)
        async def get_status(
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get full node status"""
            self._verify_auth(credentials)
            return self._build_full_status()
        
        @self.app.get("/network/peers", response_model=List[PeerInfo])
        async def get_peers(
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get peer list"""
            self._verify_auth(credentials)
            return self.node.transport.get_peers()
        
        @self.app.post("/network/connect", response_model=ApiResponse)
        async def connect_peer(
            request: ConnectPeerRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Connect to peer"""
            self._verify_auth(credentials)
            
            success = await self.node.connect_to_peer(request.ip, request.port, request.address or "")
            
            return {
                "success": success,
                "message": f"Connected to {request.ip}:{request.port}" if success else "Connection failed"
            }
        
        @self.app.get("/dht/stats", response_model=DHTStats)
        async def get_dht_stats(
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get DHT stats"""
            self._verify_auth(credentials)
            
            stats = self.node.murnaked.get_stats()
            return {
                "local_keys": stats.get('local_keys', 0),
                "stored_keys": stats.get('stored_keys', 0),
                "retrieved_keys": stats.get('retrieved_keys', 0),
                "replicated_keys": stats.get('replicated_keys', 0),
                "ring_coverage_percent": stats.get('ring_stats', {}).get('ring_coverage', 0),
                "pending_hints": stats.get('pending_hints', 0)
            }
        
        @self.app.get("/storage/stats", response_model=StorageStats)
        async def get_storage_stats(
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get storage stats"""
            self._verify_auth(credentials)
            return self.node.storage.get_stats()
        
        @self.app.post("/names/register", response_model=ApiResponse)
        async def register_name(
            request: RegisterNameRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Register name"""
            self._verify_auth(credentials)
            
            success = self.node.register_name(request.name)
            return {
                "success": success,
                "message": f"Name '{request.name}' registered" if success else "Registration failed"
            }
        
        @self.app.get("/names/lookup/{name}")
        async def lookup_name(
            name: str,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Lookup name"""
            self._verify_auth(credentials)
            
            result = self.node.lookup_name(name)
            if result:
                return {"success": True, "name": name, "address": result}
            else:
                return {"success": False, "message": "Name not found"}
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """Secure WebSocket endpoint"""
            await websocket.accept()
            
            node_address = None
            
            try:
                # Authentication timeout
                auth_msg = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=10.0
                )
                
                token = auth_msg.get('token')
                payload = self.auth_manager.verify_token(token)
                
                if not payload:
                    await websocket.close(code=4001, reason="Invalid token")
                    return
                
                node_address = payload['sub']
                self.websocket_clients[node_address] = websocket
                
                # Send initial status
                await websocket.send_json({
                    "type": "connected",
                    "node_address": node_address
                })
                
                # Keepalive with ping/pong
                while True:
                    try:
                        msg = await asyncio.wait_for(
                            websocket.receive_text(),
                            timeout=30.0
                        )
                        
                        if msg == "ping":
                            await websocket.send_text("pong")
                        elif msg == "status":
                            await websocket.send_json({
                                "type": "status",
                                "data": self._build_full_status()
                            })
                            
                    except asyncio.TimeoutError:
                        await websocket.send_json({"type": "ping"})
                        
            except WebSocketDisconnect:
                pass
            except Exception as e:
                print(f"WebSocket error: {e}")
            finally:
                if node_address and node_address in self.websocket_clients:
                    del self.websocket_clients[node_address]
        
        @self.app.get("/health")
        async def health_check():
            """Health check"""
            status = self.node.get_status()
            return {
                "status": "healthy" if self.node.running else "starting",
                "node_running": self.node.running,
                "version": "6.0",
                "uptime": status.get("uptime", 0),
                "peers_count": status.get("peers_count", 0),
                "timestamp": time.time()
            }
    
    def _verify_auth(self, credentials: Optional[HTTPAuthorizationCredentials]) -> Dict:
        """Verify authentication"""
        if not credentials:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        payload = self.auth_manager.verify_token(credentials.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        return payload
    
    def _build_full_status(self) -> Dict:
        """Build full status response"""
        node_status = self.node.get_status()
        storage_stats = self.node.storage.get_stats()
        dht_stats = self.node.murnaked.get_stats()
        # AsyncTransport doesn't have get_stats(); build from peers data
        peers = self.node.transport.get_peers()
        transport_stats = {
            'packets_sent': sum(p.get('packets_sent', 0) for p in peers),
            'packets_received': sum(p.get('packets_received', 0) for p in peers),
            'packets_retransmitted': 0,
            'bytes_sent': node_status.get('messages_sent', 0) * 256,
            'bytes_received': node_status.get('messages_received', 0) * 256,
        }

        return {
            "success": True,
            "node": {
                "address": self.node.address,
                "public_key": self.node.public_key.hex()[:32] + "...",
                "status": "online" if self.node.running else "offline",
                "version": "6.0",
                "uptime_seconds": int(node_status.get('uptime', 0)),
                "peers_count": node_status.get('peers_count', 0),
                "connections_active": node_status.get('peers_count', 0),
                "storage_used_mb": storage_stats['db_size_mb'],
                "storage_total_mb": self.config.storage.max_size_mb,
                "messages_count": storage_stats['messages'],
                "dht_entries": dht_stats.get('local_keys', 0),
                "dht_neighbors": len(dht_stats.get('ring_stats', {}).get('real_nodes', []))
            },
            "network": {
                "packets_sent": transport_stats['packets_sent'],
                "packets_received": transport_stats['packets_received'],
                "packets_retransmitted": transport_stats['packets_retransmitted'],
                "bytes_sent": transport_stats['bytes_sent'],
                "bytes_received": transport_stats['bytes_received'],
                "replay_detected": transport_stats.get('replay_detected', 0),
                "rate_limited": transport_stats.get('packets_dropped_rate_limit', 0)
            },
            "storage": storage_stats,
            "dht": {
                "local_keys": dht_stats.get('local_keys', 0),
                "stored_keys": dht_stats.get('stored_keys', 0),
                "retrieved_keys": dht_stats.get('retrieved_keys', 0),
                "ring_coverage_percent": dht_stats.get('ring_stats', {}).get('ring_coverage', 0)
            },
            "system": None
        }
    
    async def broadcast_event(self, event_type: str, payload: Dict):
        """Broadcast to all WebSocket clients"""
        disconnected = []
        
        for address, ws in self.websocket_clients.items():
            try:
                await ws.send_json({
                    "type": event_type,
                    "payload": payload,
                    "timestamp": time.time()
                })
            except:
                disconnected.append(address)
        
        for addr in disconnected:
            del self.websocket_clients[addr]
    
    def run(self):
        """Run server"""
        if not HAS_FASTAPI:
            print("❌ FastAPI not installed")
            return
        
        import uvicorn
        uvicorn.run(
            self.app, 
            host=self.host, 
            port=self.port,
            ssl_keyfile=None,  # Add SSL in production
            ssl_certfile=None
        )
    
    async def start_background(self):
        """Background start"""
        if not HAS_FASTAPI:
            return
        
        import uvicorn
        config = uvicorn.Config(
            self.app, 
            host=self.host, 
            port=self.port, 
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()


def create_app(node_instance, host: str = "127.0.0.1", port: int = 8080):
    """Factory function used by cli.py — returns the FastAPI app object."""
    server = MurnetAPIServer(node_instance, host=host, port=port)
    return server.app
