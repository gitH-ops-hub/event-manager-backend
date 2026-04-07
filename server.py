from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, Query
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Any
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from bson import ObjectId
import qrcode
import barcode
from barcode.writer import ImageWriter
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from io import BytesIO
import base64
import asyncio

# Try to import resend, but make it optional
try:
    import resend
    resend.api_key = os.environ.get("RESEND_API_KEY", "")
except ImportError:
    resend = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
db_name = os.environ.get('DB_NAME', 'event_manager')
client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# JWT Config
JWT_ALGORITHM = "HS256"
JWT_SECRET = os.environ.get("JWT_SECRET", "change-this-secret-in-production")

# Email Config
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "onboarding@resend.dev")

# Create the main app
app = FastAPI(title="Event Management API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ============== Helper Functions ==============

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def get_jwt_secret() -> str:
    return JWT_SECRET

def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=60),
        "type": "access"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "refresh"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============== Pydantic Models ==============

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str

class CustomField(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    label: str
    field_type: str = "text"
    required: bool = False
    options: Optional[List[str]] = None
    placeholder: Optional[str] = None

class EventCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    date: str
    time: str
    location: str
    guidelines: Optional[str] = ""
    max_registrations: int = 100
    custom_fields: Optional[List[CustomField]] = []
    is_active: bool = True

class EventUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    date: Optional[str] = None
    time: Optional[str] = None
    location: Optional[str] = None
    guidelines: Optional[str] = None
    max_registrations: Optional[int] = None
    custom_fields: Optional[List[CustomField]] = None
    is_active: Optional[bool] = None

class RegistrationCreate(BaseModel):
    event_id: str
    first_name: str
    last_name: str
    nationality: str
    email: EmailStr
    custom_fields: Optional[dict] = {}

class WalkInRegistration(BaseModel):
    event_id: str
    first_name: str
    last_name: str
    nationality: str
    email: Optional[EmailStr] = None
    custom_fields: Optional[dict] = {}
    notes: Optional[str] = ""

class VerifyRequest(BaseModel):
    code: str
    event_id: Optional[str] = None

class BrandingUpdate(BaseModel):
    company_name: Optional[str] = None
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None
    tagline: Optional[str] = None

class EmailTicketRequest(BaseModel):
    registration_id: str
    recipient_email: EmailStr

# ============== Auth Endpoints ==============

@api_router.post("/auth/login")
async def login(request: LoginRequest, response: Response):
    email = request.email.lower()
    user = await db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id = str(user["_id"])
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="none", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="none", max_age=604800, path="/")
    
    return {
        "id": user_id,
        "email": user["email"],
        "name": user.get("name", "Admin"),
        "role": user.get("role", "admin"),
        "access_token": access_token
    }

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out successfully"}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    return {
        "id": user["_id"],
        "email": user["email"],
        "name": user.get("name", "Admin"),
        "role": user.get("role", "admin")
    }

# ============== Event Endpoints ==============

@api_router.post("/events")
async def create_event(event: EventCreate, request: Request):
    await get_current_user(request)
    
    event_dict = event.model_dump()
    event_dict["id"] = str(uuid.uuid4())
    event_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    event_dict["registration_count"] = 0
    
    if event_dict.get("custom_fields"):
        event_dict["custom_fields"] = [cf if isinstance(cf, dict) else cf.model_dump() for cf in event_dict["custom_fields"]]
    
    await db.events.insert_one(event_dict)
    return event_dict

@api_router.get("/events")
async def get_events(active_only: bool = False):
    query = {}
    if active_only:
        query["is_active"] = True
    
    events = await db.events.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return events

@api_router.get("/events/{event_id}")
async def get_event(event_id: str):
    event = await db.events.find_one({"id": event_id}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

@api_router.put("/events/{event_id}")
async def update_event(event_id: str, event: EventUpdate, request: Request):
    await get_current_user(request)
    
    existing = await db.events.find_one({"id": event_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Event not found")
    
    update_data = {k: v for k, v in event.model_dump().items() if v is not None}
    
    if update_data.get("custom_fields"):
        update_data["custom_fields"] = [cf if isinstance(cf, dict) else cf.model_dump() for cf in update_data["custom_fields"]]
    
    if update_data:
        await db.events.update_one({"id": event_id}, {"$set": update_data})
    
    updated = await db.events.find_one({"id": event_id}, {"_id": 0})
    return updated

@api_router.delete("/events/{event_id}")
async def delete_event(event_id: str, request: Request):
    await get_current_user(request)
    
    result = await db.events.delete_one({"id": event_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    
    await db.registrations.delete_many({"event_id": event_id})
    
    return {"message": "Event deleted successfully"}

# ============== Registration Endpoints ==============

def generate_registration_code():
    return str(uuid.uuid4()).replace("-", "")[:12].upper()

def generate_qr_code(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode()

def generate_barcode(data: str) -> str:
    code128 = barcode.get_barcode_class('code128')
    barcode_instance = code128(data, writer=ImageWriter())
    
    buffer = BytesIO()
    barcode_instance.write(buffer, options={'write_text': True, 'module_height': 15})
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode()

@api_router.post("/registrations")
async def create_registration(registration: RegistrationCreate):
    event = await db.events.find_one({"id": registration.event_id}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if not event.get("is_active", True):
        raise HTTPException(status_code=400, detail="Event registration is closed")
    
    current_count = await db.registrations.count_documents({"event_id": registration.event_id})
    if current_count >= event.get("max_registrations", 100):
        raise HTTPException(status_code=400, detail="Event is full")
    
    existing = await db.registrations.find_one({
        "event_id": registration.event_id,
        "email": registration.email.lower()
    })
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered for this event")
    
    reg_code = generate_registration_code()
    
    reg_dict = registration.model_dump()
    reg_dict["id"] = str(uuid.uuid4())
    reg_dict["code"] = reg_code
    reg_dict["email"] = registration.email.lower()
    reg_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    reg_dict["checked_in"] = False
    reg_dict["checked_in_at"] = None
    reg_dict["is_walk_in"] = False
    
    reg_dict["qr_code"] = generate_qr_code(reg_code)
    reg_dict["barcode"] = generate_barcode(reg_code)
    
    await db.registrations.insert_one(reg_dict)
    
    await db.events.update_one(
        {"id": registration.event_id},
        {"$inc": {"registration_count": 1}}
    )
    
    reg_dict.pop("_id", None)
    reg_dict["event"] = event
    
    return reg_dict

@api_router.post("/registrations/walk-in")
async def create_walk_in_registration(registration: WalkInRegistration, request: Request):
    await get_current_user(request)
    
    event = await db.events.find_one({"id": registration.event_id}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    reg_code = generate_registration_code()
    
    reg_dict = registration.model_dump()
    reg_dict["id"] = str(uuid.uuid4())
    reg_dict["code"] = reg_code
    reg_dict["email"] = registration.email.lower() if registration.email else ""
    reg_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    reg_dict["checked_in"] = True
    reg_dict["checked_in_at"] = datetime.now(timezone.utc).isoformat()
    reg_dict["is_walk_in"] = True
    
    reg_dict["qr_code"] = generate_qr_code(reg_code)
    reg_dict["barcode"] = generate_barcode(reg_code)
    
    await db.registrations.insert_one(reg_dict)
    
    await db.events.update_one(
        {"id": registration.event_id},
        {"$inc": {"registration_count": 1}}
    )
    
    reg_dict.pop("_id", None)
    reg_dict["event"] = event
    
    return reg_dict

@api_router.get("/registrations")
async def get_registrations(
    request: Request,
    event_id: Optional[str] = None,
    checked_in: Optional[bool] = None
):
    await get_current_user(request)
    
    query = {}
    if event_id:
        query["event_id"] = event_id
    if checked_in is not None:
        query["checked_in"] = checked_in
    
    registrations = await db.registrations.find(query, {"_id": 0}).sort("created_at", -1).to_list(10000)
    return registrations

@api_router.get("/registrations/{registration_id}")
async def get_registration(registration_id: str):
    registration = await db.registrations.find_one({"id": registration_id}, {"_id": 0})
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")
    
    event = await db.events.find_one({"id": registration["event_id"]}, {"_id": 0})
    registration["event"] = event
    
    return registration

@api_router.get("/registrations/code/{code}")
async def get_registration_by_code(code: str):
    registration = await db.registrations.find_one({"code": code.upper()}, {"_id": 0})
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")
    
    event = await db.events.find_one({"id": registration["event_id"]}, {"_id": 0})
    registration["event"] = event
    
    return registration

# ============== Verification Endpoints ==============

@api_router.post("/verify")
async def verify_registration(verify: VerifyRequest, request: Request):
    await get_current_user(request)
    
    query = {"code": verify.code.upper()}
    if verify.event_id:
        query["event_id"] = verify.event_id
    
    registration = await db.registrations.find_one(query, {"_id": 0})
    
    if not registration:
        return {
            "valid": False,
            "message": "Registration not found",
            "registration": None
        }
    
    event = await db.events.find_one({"id": registration["event_id"]}, {"_id": 0})
    
    if registration.get("checked_in"):
        return {
            "valid": True,
            "message": "Already checked in",
            "already_checked_in": True,
            "checked_in_at": registration.get("checked_in_at"),
            "registration": registration,
            "event": event
        }
    
    await db.registrations.update_one(
        {"code": verify.code.upper()},
        {"$set": {
            "checked_in": True,
            "checked_in_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    registration["checked_in"] = True
    registration["checked_in_at"] = datetime.now(timezone.utc).isoformat()
    
    return {
        "valid": True,
        "message": "Check-in successful",
        "already_checked_in": False,
        "registration": registration,
        "event": event
    }

# ============== PDF Generation ==============

@api_router.get("/registrations/{registration_id}/pdf")
async def generate_ticket_pdf(registration_id: str):
    registration = await db.registrations.find_one({"id": registration_id}, {"_id": 0})
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")
    
    event = await db.events.find_one({"id": registration["event_id"]}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    branding = await db.branding.find_one({}, {"_id": 0})
    
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    
    company_name = branding.get("company_name", "Event Manager") if branding else "Event Manager"
    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(width/2, height - 50, company_name)
    
    c.setFont("Helvetica", 12)
    tagline = branding.get("tagline", "") if branding else ""
    if tagline:
        c.drawCentredString(width/2, height - 70, tagline)
    
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(width/2, height - 110, "EVENT TICKET")
    
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width/2, height - 140, event["name"])
    
    c.setFont("Helvetica", 12)
    y_pos = height - 170
    
    c.drawString(50, y_pos, f"Date: {event['date']}")
    y_pos -= 20
    c.drawString(50, y_pos, f"Time: {event['time']}")
    y_pos -= 20
    c.drawString(50, y_pos, f"Location: {event['location']}")
    
    y_pos -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_pos, "Attendee Information")
    
    c.setFont("Helvetica", 12)
    y_pos -= 25
    c.drawString(50, y_pos, f"Name: {registration['first_name']} {registration['last_name']}")
    y_pos -= 20
    c.drawString(50, y_pos, f"Email: {registration['email']}")
    y_pos -= 20
    c.drawString(50, y_pos, f"Nationality: {registration['nationality']}")
    y_pos -= 20
    c.drawString(50, y_pos, f"Registration Code: {registration['code']}")
    
    y_pos -= 40
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_pos, "Scan for Mobile Check-in:")
    
    qr_data = base64.b64decode(registration["qr_code"])
    qr_image = ImageReader(BytesIO(qr_data))
    c.drawImage(qr_image, 50, y_pos - 150, width=120, height=120)
    
    c.drawString(200, y_pos, "Scan with Handheld Scanner:")
    
    barcode_data = base64.b64decode(registration["barcode"])
    barcode_image = ImageReader(BytesIO(barcode_data))
    c.drawImage(barcode_image, 200, y_pos - 120, width=250, height=80)
    
    if event.get("guidelines"):
        y_pos -= 180
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_pos, "Entry Guidelines:")
        c.setFont("Helvetica", 10)
        
        guidelines = event["guidelines"].split("\n")
        for guideline in guidelines[:5]:
            y_pos -= 15
            if y_pos > 50:
                c.drawString(50, y_pos, f"• {guideline[:80]}")
    
    c.setFont("Helvetica", 8)
    c.drawCentredString(width/2, 30, "Please present this ticket at the venue entrance")
    
    c.save()
    buffer.seek(0)
    
    pdf_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return {
        "pdf": pdf_base64,
        "filename": f"ticket_{registration['code']}.pdf"
    }

# ============== Email Endpoints ==============

@api_router.post("/send-ticket-email")
async def send_ticket_email(email_request: EmailTicketRequest, request: Request):
    registration = await db.registrations.find_one({"id": email_request.registration_id}, {"_id": 0})
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")
    
    event = await db.events.find_one({"id": registration["event_id"]}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    branding = await db.branding.find_one({}, {"_id": 0})
    company_name = branding.get("company_name", "Event Manager") if branding else "Event Manager"
    
    pdf_response = await generate_ticket_pdf(email_request.registration_id)
    
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #0055FF;">{company_name}</h1>
        <h2>Your Event Ticket</h2>
        <p>Dear {registration['first_name']} {registration['last_name']},</p>
        <p>Thank you for registering for <strong>{event['name']}</strong>!</p>
        
        <div style="background: #f4f4f5; padding: 20px; border-radius: 4px; margin: 20px 0;">
            <h3>Event Details</h3>
            <p><strong>Date:</strong> {event['date']}</p>
            <p><strong>Time:</strong> {event['time']}</p>
            <p><strong>Location:</strong> {event['location']}</p>
        </div>
        
        <div style="background: #f4f4f5; padding: 20px; border-radius: 4px; margin: 20px 0;">
            <h3>Your Registration</h3>
            <p><strong>Code:</strong> {registration['code']}</p>
            <p>Please present this code or the attached PDF ticket at the venue.</p>
        </div>
        
        <p>Your ticket is attached to this email as a PDF.</p>
        
        <p>See you at the event!</p>
    </body>
    </html>
    """
    
    if not resend or not resend.api_key:
        return {
            "status": "error",
            "message": "Email service not configured. Please download the ticket instead."
        }
    
    try:
        params = {
            "from": SENDER_EMAIL,
            "to": [email_request.recipient_email],
            "subject": f"Your Ticket for {event['name']}",
            "html": html_content,
            "attachments": [
                {
                    "filename": f"ticket_{registration['code']}.pdf",
                    "content": pdf_response["pdf"]
                }
            ]
        }
        
        email = await asyncio.to_thread(resend.Emails.send, params)
        
        return {
            "status": "success",
            "message": f"Ticket sent to {email_request.recipient_email}",
            "email_id": email.get("id")
        }
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to send email: {str(e)}"
        }

# ============== Branding Endpoints ==============

@api_router.get("/branding")
async def get_branding():
    branding = await db.branding.find_one({}, {"_id": 0})
    if not branding:
        return {
            "company_name": "Event Manager",
            "logo_url": "",
            "primary_color": "#0055FF",
            "tagline": "Your Events, Simplified"
        }
    return branding

@api_router.put("/branding")
async def update_branding(branding: BrandingUpdate, request: Request):
    await get_current_user(request)
    
    update_data = {k: v for k, v in branding.model_dump().items() if v is not None}
    
    existing = await db.branding.find_one({})
    if existing:
        await db.branding.update_one({}, {"$set": update_data})
    else:
        update_data.setdefault("company_name", "Event Manager")
        update_data.setdefault("logo_url", "")
        update_data.setdefault("primary_color", "#0055FF")
        update_data.setdefault("tagline", "Your Events, Simplified")
        await db.branding.insert_one(update_data)
    
    return await db.branding.find_one({}, {"_id": 0})

# ============== Statistics ==============

@api_router.get("/stats")
async def get_stats(request: Request):
    await get_current_user(request)
    
    total_events = await db.events.count_documents({})
    active_events = await db.events.count_documents({"is_active": True})
    total_registrations = await db.registrations.count_documents({})
    checked_in = await db.registrations.count_documents({"checked_in": True})
    walk_ins = await db.registrations.count_documents({"is_walk_in": True})
    
    return {
        "total_events": total_events,
        "active_events": active_events,
        "total_registrations": total_registrations,
        "checked_in": checked_in,
        "pending_checkin": total_registrations - checked_in,
        "walk_ins": walk_ins
    }

# ============== Health Check ==============

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include the router
app.include_router(api_router)

# CORS Configuration - Allow GitHub Pages
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for GitHub Pages
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event
@app.on_event("startup")
async def startup_event():
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.events.create_index("id", unique=True)
    await db.registrations.create_index("id", unique=True)
    await db.registrations.create_index("code", unique=True)
    await db.registrations.create_index("event_id")
    
    # Seed admin user
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@eventmanager.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@123")
    
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        hashed = hash_password(admin_password)
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hashed,
            "name": "Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info(f"Admin user created: {admin_email}")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one(
            {"email": admin_email},
            {"$set": {"password_hash": hash_password(admin_password)}}
        )
        logger.info(f"Admin password updated for: {admin_email}")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
