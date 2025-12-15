import json
import logging
import os
import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    BotCommand
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)
from dotenv import load_dotenv

# ========== CONFIGURATION ==========
# إجبار استخدام متغيرات البيئة فقط
load_dotenv()

TOKEN = os.environ["BOT_TOKEN"]
ADMIN_ID = int(os.environ["ADMIN_ID"])

# JSON file paths
SUBSCRIBERS_FILE = "subscribers.json"
ANNOUNCEMENTS_FILE = "announcements.json"
READ_RECEIPTS_FILE = "read_receipts.json"

# تنظيف الإعلانات الأقدم من (أيام)
ANNOUNCEMENT_RETENTION_DAYS = 10

# Global lock for JSON file access
json_lock = asyncio.Lock()

# Allowed file extensions for safety
ALLOWED_EXTENSIONS = {
    '.pdf', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', '.mp4', '.wav',
    '.zip', '.rar', '.7z'
}

ALLOWED_MIME_TYPES = {
    'application/pdf',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
    'audio/mpeg', 'audio/wav',
    'video/mp4',
    'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed'
}

# ========== SECURITY FUNCTIONS ==========
def validate_file_safety(file_name: str, mime_type: str = None) -> bool:
    """Validate if a file is safe to send."""
    if not file_name:
        return False
    
    # Check file extension
    ext = os.path.splitext(file_name.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        logger.warning(f"Blocked file with extension: {ext}")
        return False
    
    # Check MIME type if provided
    if mime_type and mime_type not in ALLOWED_MIME_TYPES:
        logger.warning(f"Blocked file with MIME type: {mime_type}")
        return False
    
    # Block dangerous extensions even if they somehow pass
    dangerous_extensions = {'.exe', '.bat', '.cmd', '.sh', '.js', '.php', '.py', '.jar'}
    if ext in dangerous_extensions:
        logger.warning(f"Blocked dangerous file: {file_name}")
        return False
    
    return True

def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for logging."""
    return hashlib.sha256(data.encode()).hexdigest()[:8]

# ========== LOGGING SETUP ==========
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ========== JSON HANDLING FUNCTIONS ==========
def _read_file_sync(file_path: str):
    """Synchronous file reading - to be run in thread pool."""
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def _write_file_sync(file_path: str, data):
    """Synchronous file writing - to be run in thread pool."""
    os.makedirs(os.path.dirname(file_path) if os.path.dirname(file_path) else '.', exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

async def load_json(file_path: str, default: dict | list = None):
    """Load JSON data from file with async lock and basic validation."""
    async with json_lock:
        try:
            # Run blocking I/O in thread pool
            data = await asyncio.to_thread(_read_file_sync, file_path)
            
            if data is None:
                return default if default is not None else ([] if 'subscribers' in file_path else {})
            
            # Basic data validation
            if not isinstance(data, (dict, list)):
                logger.error(f"Invalid JSON format in {file_path}")
                return default if default is not None else ([] if 'subscribers' in file_path else {})
            
            return data
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Error loading {file_path}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading {file_path}: {e}")
        
        return default if default is not None else ([] if 'subscribers' in file_path else {})

async def save_json(file_path: str, data):
    """Save data to JSON file with async lock."""
    async with json_lock:
        try:
            # Validate data before saving
            if not isinstance(data, (dict, list)):
                logger.error(f"Invalid data type for {file_path}: {type(data)}")
                return False
            
            # Run blocking I/O in thread pool
            await asyncio.to_thread(_write_file_sync, file_path, data)
            
            logger.info(f"Successfully saved {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving to {file_path}: {e}")
            return False

async def atomic_read_modify_write(file_path: str, modify_callback):
    """
    Atomic read-modify-write operation with proper locking.
    
    Args:
        file_path: Path to JSON file
        modify_callback: Function that takes current data and returns modified data
    
    Returns:
        Tuple of (success, modified_data)
    """
    async with json_lock:
        try:
            # Read current data
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    current_data = json.load(f)
            else:
                current_data = [] if 'subscribers' in file_path else {}
            
            # Apply modification
            modified_data = modify_callback(current_data)
            
            # Validate modified data
            if not isinstance(modified_data, (dict, list)):
                logger.error(f"Invalid data type after modification: {type(modified_data)}")
                return False, None
            
            # Save modified data
            os.makedirs(os.path.dirname(file_path) if os.path.dirname(file_path) else '.', exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(modified_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Successfully performed atomic RMW on {file_path}")
            return True, modified_data
            
        except Exception as e:
            logger.error(f"Error in atomic RMW for {file_path}: {e}")
            return False, None

# ========== ANNOUNCEMENT CLEANUP ==========
async def cleanup_old_announcements():
    """Clean up announcements older than retention days to save JSON file space."""
    try:
        announcements = await load_json(ANNOUNCEMENTS_FILE, {})
        receipts = await load_json(READ_RECEIPTS_FILE, {})
        
        if not announcements:
            return 0
        
        cutoff_date = datetime.now() - timedelta(days=ANNOUNCEMENT_RETENTION_DAYS)
        deleted_count = 0
        
        # Find announcements older than retention period
        announcements_to_delete = []
        for ann_id, ann_data in announcements.items():
            try:
                announcement_date = datetime.fromisoformat(ann_data.get('timestamp', ''))
                if announcement_date < cutoff_date:
                    announcements_to_delete.append(ann_id)
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid timestamp in announcement {ann_id}: {e}")
                # Delete announcements with invalid timestamps
                announcements_to_delete.append(ann_id)
        
        # Delete old announcements
        for ann_id in announcements_to_delete:
            if ann_id in announcements:
                del announcements[ann_id]
                deleted_count += 1
            
            # Also delete corresponding receipts
            if ann_id in receipts:
                del receipts[ann_id]
        
        # Save cleaned data
        if deleted_count > 0:
            await save_json(ANNOUNCEMENTS_FILE, announcements)
            await save_json(READ_RECEIPTS_FILE, receipts)
            logger.info(f"Cleaned up {deleted_count} announcements older than {ANNOUNCEMENT_RETENTION_DAYS} days")
        
        return deleted_count
        
    except Exception as e:
        logger.error(f"Error cleaning up old announcements: {e}")
        return 0

async def cleanup_before_new_announcement():
    """Clean up old announcements before creating a new one."""
    deleted_count = await cleanup_old_announcements()
    if deleted_count > 0:
        logger.info(f"تم حذف {deleted_count} إعلان قديم (أقدم من {ANNOUNCEMENT_RETENTION_DAYS} يوم)")

# ========== DATA MODELS ==========
class SubscriberManager:
    """Manages subscriber data in JSON file with atomic operations."""
    
    @staticmethod
    async def add_subscriber(user_id: int) -> bool:
        """Add a new subscriber if not exists with atomic operation."""
        if not isinstance(user_id, int) or user_id <= 0:
            logger.warning(f"Invalid user_id: {user_id}")
            return False
        
        def modify_subscribers(current_data):
            """Modify callback for atomic operation."""
            if not isinstance(current_data, list):
                current_data = []
            
            # Prevent duplicates
            if user_id not in current_data:
                current_data.append(user_id)
            
            return current_data
        
        success, _ = await atomic_read_modify_write(SUBSCRIBERS_FILE, modify_subscribers)
        return success
    
    @staticmethod
    async def get_all_subscribers() -> List[int]:
        """Get all subscriber IDs with validation."""
        subscribers = await load_json(SUBSCRIBERS_FILE, [])
        
        # Filter invalid IDs
        return [uid for uid in subscribers if isinstance(uid, int) and uid > 0]
    
    @staticmethod
    async def count_subscribers() -> int:
        """Count total subscribers."""
        return len(await SubscriberManager.get_all_subscribers())
    
    @staticmethod
    async def remove_subscriber(user_id: int) -> bool:
        """Remove a subscriber with atomic operation."""
        def modify_subscribers(current_data):
            """Modify callback for atomic operation."""
            if not isinstance(current_data, list):
                current_data = []
            
            if user_id in current_data:
                current_data.remove(user_id)
            
            return current_data
        
        success, _ = await atomic_read_modify_write(SUBSCRIBERS_FILE, modify_subscribers)
        return success

class AnnouncementManager:
    """Manages announcements in JSON file with validation."""
    
    @staticmethod
    async def create_announcement(announcement_id: str, data: dict) -> bool:
        """Create a new announcement entry with timestamp and validation."""
        if not announcement_id or not isinstance(data, dict):
            logger.error("Invalid announcement_id or data")
            return False
            
        announcements = await load_json(ANNOUNCEMENTS_FILE, {})
        
        # Validate required fields
        if 'sender_id' not in data or 'message_id' not in data:
            logger.error("Missing required fields in announcement data")
            return False
        
        # Prepare announcement data
        announcement_data = {
            'id': announcement_id,
            'timestamp': datetime.now().isoformat(),
            'type': data.get('type', 'text'),
            'sender_id': data.get('sender_id'),
            'message_id': data.get('message_id'),
            'content': data.get('content', '')[:500],  # Limit content length
            'caption': data.get('caption', '')[:200],  # Limit caption length
            'file_id': data.get('file_id'),
            'file_name': data.get('file_name'),
            'media_group_id': data.get('media_group_id')
        }
        
        # If there's a caption but no content, use caption as content
        if not announcement_data['content'] and announcement_data['caption']:
            announcement_data['content'] = announcement_data['caption']
        
        announcements[announcement_id] = announcement_data
        
        return await save_json(ANNOUNCEMENTS_FILE, announcements)
    
    @staticmethod
    async def get_announcement(announcement_id: str) -> Optional[dict]:
        """Get announcement by ID with validation."""
        if not announcement_id:
            return None
            
        announcements = await load_json(ANNOUNCEMENTS_FILE, {})
        return announcements.get(announcement_id)
    
    @staticmethod
    async def get_all_announcements() -> Dict[str, dict]:
        """Get all announcements sorted by timestamp (newest first)."""
        announcements = await load_json(ANNOUNCEMENTS_FILE, {})
        
        # Filter invalid announcements
        valid_announcements = {}
        for ann_id, ann_data in announcements.items():
            if isinstance(ann_data, dict) and ann_data.get('id') == ann_id:
                valid_announcements[ann_id] = ann_data
        
        # Sort by timestamp descending (newest first)
        sorted_items = sorted(
            valid_announcements.items(),
            key=lambda x: x[1].get('timestamp', ''),
            reverse=True
        )
        
        return dict(sorted_items)
    
    @staticmethod
    async def announcement_exists(announcement_id: str) -> bool:
        """Check if announcement exists."""
        announcements = await load_json(ANNOUNCEMENTS_FILE, {})
        return announcement_id in announcements
    
    @staticmethod
    async def get_announcements_count() -> int:
        """Get total number of announcements."""
        announcements = await load_json(ANNOUNCEMENTS_FILE, {})
        return len(announcements)

class ReadReceiptManager:
    """Manages read receipts in JSON file with atomic operations."""
    
    @staticmethod
    async def mark_as_read(announcement_id: str, user_id: int) -> Tuple[bool, bool]:
        """
        Mark an announcement as read by a user with atomic operation.
        Returns: (success, is_duplicate)
        """
        if not announcement_id or not isinstance(user_id, int) or user_id <= 0:
            logger.warning(f"Invalid announcement_id or user_id: {announcement_id}, {user_id}")
            return False, False
        
        def modify_receipts(current_data):
            """Modify callback for atomic operation."""
            if not isinstance(current_data, dict):
                current_data = {}
            
            if announcement_id not in current_data:
                current_data[announcement_id] = []
            
            # Validate user list
            if not isinstance(current_data[announcement_id], list):
                current_data[announcement_id] = []
            
            # Check for duplicate
            if user_id in current_data[announcement_id]:
                return current_data, True  # Return data unchanged with duplicate flag
            
            # Add user
            current_data[announcement_id].append(user_id)
            return current_data, False
        
        # Perform atomic read-modify-write
        def modify_callback(current_data):
            data, is_duplicate = modify_receipts(current_data)
            return data
        
        success, modified_data = await atomic_read_modify_write(READ_RECEIPTS_FILE, modify_callback)
        
        if not success:
            return False, False
        
        # Check for duplicate in the modified data
        is_duplicate = (
            announcement_id in modified_data and 
            user_id in modified_data.get(announcement_id, [])
        )
        
        return success, is_duplicate
    
    @staticmethod
    async def get_read_count(announcement_id: str) -> int:
        """Get number of users who read an announcement."""
        if not announcement_id:
            return 0
            
        receipts = await load_json(READ_RECEIPTS_FILE, {})
        users = receipts.get(announcement_id, [])
        
        # Validate users list
        if not isinstance(users, list):
            return 0
            
        return len(users)
    
    @staticmethod
    async def get_read_users(announcement_id: str) -> List[int]:
        """Get list of users who read an announcement."""
        if not announcement_id:
            return []
            
        receipts = await load_json(READ_RECEIPTS_FILE, {})
        users = receipts.get(announcement_id, [])
        
        # Filter invalid user IDs
        return [uid for uid in users if isinstance(uid, int) and uid > 0]
    
    @staticmethod
    async def get_all_receipts() -> Dict[str, List[int]]:
        """Get all read receipts with validation."""
        receipts = await load_json(READ_RECEIPTS_FILE, {})
        
        # Validate receipts structure
        valid_receipts = {}
        for ann_id, users in receipts.items():
            if isinstance(users, list):
                valid_receipts[ann_id] = [uid for uid in users if isinstance(uid, int) and uid > 0]
        
        return valid_receipts

# ========== BOT HANDLERS ==========
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command from students."""
    user_id = update.effective_user.id
    
    # Admin shouldn't use /start
    if user_id == ADMIN_ID:
        await update.message.reply_text(
            "👨‍🏫 مرحبًا بالأستاذ!\n\n"
            "يمكنك إرسال الإعلانات مباشرة وسيتم بثها للطلاب.\n"
             "تم تطوير هذا البوت من طرف بوعناني عبد القادر.\n"
            "استخدم /stats لرؤية الإحصائيات."
        )
        return
    
    # Add student as subscriber with atomic operation
    if await SubscriberManager.add_subscriber(user_id):
        welcome_msg = (
            "✅ تم الاشتراك بنجاح!\n\n"
            "أنت الآن مشترك في قناة الإعلانات الدراسية.\n"
            "سيتم إرسال جميع الإعلانات والمواد الدراسية إليك هنا.\n\n"
            "🔔 **تذكير:** اضغط على زر 'تم الاستلام ✅' تحت كل إعلان لتأكيد الاستلام."
        )
    else:
        welcome_msg = (
            "👋 مرحباً بك مرة أخرى!\n\n"
            "أنت بالفعل مشترك في قناة الإعلانات الدراسية."
        )
    
    await update.message.reply_text(welcome_msg, parse_mode=ParseMode.MARKDOWN)

async def handle_student_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle any message from students (non-admin)."""
    user_id = update.effective_user.id
    
    # Ignore admin messages
    if user_id == ADMIN_ID:
        return
    
    # Polite rejection message
    rejection_msg = (
        "🤖 **هذا البوت مخصص فقط لاستقبال الإعلانات الدراسية**\n\n"
        "⚠️ لا يمكنك إرسال الرسائل أو الملفات هنا.\n\n"
        "للاستفسارات، يرجى التواصل مع الأستاذ مباشرة."
    )
    
    await update.message.reply_text(rejection_msg, parse_mode=ParseMode.MARKDOWN)

async def send_message_to_subscriber(context, subscriber_id, announcement_data, reply_markup):
    """Send message to a single subscriber with error handling."""
    try:
        if announcement_data['type'] == 'text':
            await context.bot.send_message(
                chat_id=subscriber_id,
                text=announcement_data['content'],
                reply_markup=reply_markup,
                parse_mode=ParseMode.MARKDOWN
            )
        elif announcement_data['type'] == 'photo':
            caption = announcement_data.get('caption', '')
            await context.bot.send_photo(
                chat_id=subscriber_id,
                photo=announcement_data['file_id'],
                caption=caption,
                reply_markup=reply_markup,
                parse_mode=ParseMode.MARKDOWN
            )
        elif announcement_data['type'] in ['document', 'pdf']:
            caption = announcement_data.get('caption', '')
            await context.bot.send_document(
                chat_id=subscriber_id,
                document=announcement_data['file_id'],
                caption=caption,
                reply_markup=reply_markup,
                parse_mode=ParseMode.MARKDOWN
            )
        elif announcement_data['type'] == 'audio':
            caption = announcement_data.get('caption', '')
            await context.bot.send_audio(
                chat_id=subscriber_id,
                audio=announcement_data['file_id'],
                caption=caption,
                reply_markup=reply_markup,
                parse_mode=ParseMode.MARKDOWN
            )
        elif announcement_data['type'] == 'video':
            caption = announcement_data.get('caption', '')
            await context.bot.send_video(
                chat_id=subscriber_id,
                video=announcement_data['file_id'],
                caption=caption,
                reply_markup=reply_markup,
                parse_mode=ParseMode.MARKDOWN
            )
        return True
    except Exception as e:
        logger.error(f"Failed to send to {subscriber_id}: {e}")
        return False

async def handle_admin_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle messages from admin and broadcast to all subscribers with security checks."""
    user_id = update.effective_user.id
    
    # Verify admin
    if user_id != ADMIN_ID:
        return await handle_student_message(update, context)
    
    # تنظيف الإعلانات القديمة قبل إنشاء إعلان جديد
    await cleanup_before_new_announcement()
    
    message = update.effective_message
    subscribers = await SubscriberManager.get_all_subscribers()
    
    if not subscribers:
        await message.reply_text("⚠️ لا يوجد طلاب مشتركين بعد.")
        return
    
    # Generate unique announcement ID
    announcement_id = str(uuid4())[:8]
    
    # Prepare announcement data based on message type
    announcement_data = {
        'sender_id': user_id,
        'message_id': message.message_id
    }
    
    # Determine message type and extract content
    if message.text:
        announcement_data['type'] = 'text'
        announcement_data['content'] = message.text
    elif message.caption:
        # For media with caption
        announcement_data['content'] = message.caption
        announcement_data['caption'] = message.caption
    else:
        announcement_data['content'] = "📎 ملف مرفق"
    
    # Handle different media types with security checks
    if message.document:
        # Security check for file type
        file_name = message.document.file_name
        mime_type = message.document.mime_type
        
        if not validate_file_safety(file_name, mime_type):
            await message.reply_text(
                "⚠️ **ملف غير مسموح به**\n\n"
                "نوع الملف أو امتداده غير مدعوم لأسباب أمنية.\n"
                "الملفات المسموح بها: PDF، صور، مستندات Office، ZIP، MP3، MP4.",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        announcement_data['type'] = 'document'
        announcement_data['file_id'] = message.document.file_id
        announcement_data['file_name'] = file_name
        
        # Check if it's a PDF
        if mime_type == 'application/pdf':
            announcement_data['type'] = 'pdf'
    
    elif message.photo:
        announcement_data['type'] = 'photo'
        announcement_data['file_id'] = message.photo[-1].file_id
    elif message.audio:
        announcement_data['type'] = 'audio'
        announcement_data['file_id'] = message.audio.file_id
    elif message.video:
        announcement_data['type'] = 'video'
        announcement_data['file_id'] = message.video.file_id
    
    # Handle media groups
    if message.media_group_id:
        announcement_data['media_group_id'] = message.media_group_id
    
    # Save announcement
    await AnnouncementManager.create_announcement(announcement_id, announcement_data)
    
    # Create inline button
    keyboard = [[
        InlineKeyboardButton("تم الاستلام ✅", callback_data=f"read_{announcement_id}")
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Broadcast to all subscribers using batches for better performance
    successful_sends = 0
    failed_sends = []
    
    # Batch size for parallel sending - reduced for safety
    BATCH_SIZE = 20
    
    for i in range(0, len(subscribers), BATCH_SIZE):
        batch = subscribers[i:i + BATCH_SIZE]
        tasks = []
        
        for subscriber_id in batch:
            task = send_message_to_subscriber(context, subscriber_id, announcement_data, reply_markup)
            tasks.append(task)
        
        # Send batch in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for subscriber_id, result in zip(batch, results):
            if result is True:
                successful_sends += 1
            else:
                failed_sends.append(subscriber_id)
        
        # Increased delay between batches to avoid rate limiting
        if i + BATCH_SIZE < len(subscribers):
            await asyncio.sleep(1.0)
    
    # Send report to admin
    report = (
        f"📊 **تقرير البث:**\n\n"
        f"• رقم الإعلان: `{announcement_id}`\n"
        f"• النوع: {announcement_data.get('type', 'نص')}\n"
        f"• تم الإرسال بنجاح: {successful_sends} طالب\n"
        f"• إجمالي المشتركين: {len(subscribers)}"
    )
    
    if failed_sends:
        report += f"\n• فشل الإرسال لـ: {len(failed_sends)} طالب"
    
    if announcement_data.get('content'):
        preview = announcement_data['content'][:50] + "..." if len(announcement_data['content']) > 50 else announcement_data['content']
        report += f"\n\n📝 المعاينة: {preview}"
    
    await message.reply_text(report, parse_mode=ParseMode.MARKDOWN)

async def handle_read_receipt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle 'تم الاستلام' button clicks with security validation."""
    query = update.callback_query
    user_id = update.effective_user.id
    
    # Extract announcement ID from callback data
    callback_data = query.data
    if not callback_data.startswith("read_"):
        logger.warning(f"Invalid callback data: {callback_data}")
        await query.answer("❌ بيانات غير صالحة")
        return
    
    announcement_id = callback_data[5:]  # Remove "read_" prefix
    
    # Validate announcement exists
    if not await AnnouncementManager.announcement_exists(announcement_id):
        logger.warning(f"Invalid announcement_id in callback: {announcement_id}")
        await query.answer("❌ الإعلان غير موجود")
        return
    
    # Validate user is a subscriber
    subscribers = await SubscriberManager.get_all_subscribers()
    if user_id not in subscribers and user_id != ADMIN_ID:
        logger.warning(f"Non-subscriber tried to mark as read: {user_id}")
        await query.answer("❌ يجب الاشتراك أولاً")
        return
    
    # Mark as read with atomic operation
    success, is_duplicate = await ReadReceiptManager.mark_as_read(announcement_id, user_id)
    
    if success:
        # Get read count for feedback
        read_count = await ReadReceiptManager.get_read_count(announcement_id)
        total_students = await SubscriberManager.count_subscribers()
        
        # Update button text to show current count
        try:
            keyboard = [[
                InlineKeyboardButton(f"✅ تم الاستلام ({read_count}/{total_students})", callback_data=f"read_{announcement_id}")
            ]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            # Try to edit the message to update the button
            await query.message.edit_reply_markup(reply_markup=reply_markup)
        except Exception as e:
            logger.error(f"Could not update button: {e}")
        
        feedback = (
            f"✅ تم تسجيل استلامك للإعلان\n"
            f"📊 {read_count}/{total_students} طالب قاموا بالتأكيد"
        )
        await query.answer(feedback, show_alert=True)
        
    elif is_duplicate:
        # Student already clicked
        read_count = await ReadReceiptManager.get_read_count(announcement_id)
        total_students = await SubscriberManager.count_subscribers()
        
        feedback = (
            f"⏳ لقد سبق وتسجيل استلامك لهذا الإعلان\n"
            f"📊 {read_count}/{total_students} طالب قاموا بالتأكيد"
        )
        await query.answer(feedback, show_alert=False)  # Show as toast notification
        
    else:
        # Error occurred
        await query.answer("❌ حدث خطأ في التسجيل، حاول لاحقاً")

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /stats command for admin - SECURE VERSION."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    # تنظيف الإعلانات القديمة قبل عرض الإحصائيات
    deleted_count = await cleanup_old_announcements()
    if deleted_count > 0:
        await update.message.reply_text(
            f"🧹 تم تنظيف {deleted_count} إعلان قديم (أقدم من {ANNOUNCEMENT_RETENTION_DAYS} يوم)",
            parse_mode=ParseMode.MARKDOWN
        )
    
    # Get all data (sorted by timestamp)
    announcements = await AnnouncementManager.get_all_announcements()
    receipts = await ReadReceiptManager.get_all_receipts()
    total_students = await SubscriberManager.count_subscribers()
    
    if not announcements:
        await update.message.reply_text("📭 لا توجد إعلانات حتى الآن.", parse_mode=ParseMode.MARKDOWN)
        return
    
    # Prepare detailed statistics report (without sensitive user data)
    report_lines = ["📊 **إحصائيات تفصيلية**\n"]
    
    for i, (ann_id, ann_data) in enumerate(announcements.items(), 1):
        read_count = len(receipts.get(ann_id, []))
        
        # Type emoji mapping
        type_emojis = {
            'text': '📝',
            'photo': '🖼️',
            'document': '📄',
            'pdf': '📕',
            'audio': '🎵',
            'video': '🎬'
        }
        
        emoji = type_emojis.get(ann_data.get('type', 'text'), '📌')
        
        # Format timestamp
        try:
            timestamp = datetime.fromisoformat(ann_data.get('timestamp', ''))
            time_str = timestamp.strftime("%Y/%m/%d %H:%M")
            
            # Calculate days since announcement
            days_ago = (datetime.now() - timestamp).days
            days_info = f" (منذ {days_ago} يوم)" if days_ago > 0 else " (اليوم)"
            time_str += days_info
        except:
            time_str = "تاريخ غير معروف"
        
        # Get content preview (sanitized)
        content = ann_data.get('content', ann_data.get('caption', 'لا يوجد نص'))
        preview = content[:40] + "..." if len(content) > 40 else content
        
        # Calculate percentage
        percentage = (read_count / total_students * 100) if total_students > 0 else 0
        
        # Progress bar
        bars = int(percentage / 10)
        progress_bar = "▓" * bars + "░" * (10 - bars)
        
        report_lines.append(
            f"\n{i}. {emoji} **الإعلان #{ann_id[:6]}** ({time_str})\n"
            f"   📋 {preview}\n"
            f"   {progress_bar} {read_count}/{total_students} ({percentage:.1f}%)"
        )
    
    # Summary
    total_announcements = len(announcements)
    total_reads = sum(len(v) for v in receipts.values())
    
    # Calculate average read rate
    if total_announcements > 0 and total_students > 0:
        avg_read_rate = (total_reads / (total_announcements * total_students)) * 100
    else:
        avg_read_rate = 0
    
    report_lines.append(f"\n{'='*30}")
    report_lines.append(f"📈 **ملخص عام:**")
    report_lines.append(f"• إجمالي الإعلانات: {total_announcements}")
    report_lines.append(f"• إجمالي المشتركين: {total_students}")
    report_lines.append(f"• إجمالي التأكيدات: {total_reads}")
    report_lines.append(f"• متوسط نسبة القراءة: {avg_read_rate:.1f}%")
    
    # Add cleanup info
    report_lines.append(f"\n🗑️ **سياسة التنظيف:**")
    report_lines.append(f"• يتم حذف الإعلانات تلقائياً بعد {ANNOUNCEMENT_RETENTION_DAYS} يوم")
    
    # Send report (split if too long)
    full_report = "\n".join(report_lines)
    
    if len(full_report) > 4000:
        # Split into chunks
        chunks = [full_report[i:i+4000] for i in range(0, len(full_report), 4000)]
        for chunk in chunks:
            await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(full_report, parse_mode=ParseMode.MARKDOWN)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    user_id = update.effective_user.id
    
    total_students = await SubscriberManager.count_subscribers()
    total_announcements = await AnnouncementManager.get_announcements_count()
    
    if user_id == ADMIN_ID:
        help_text = (
            "👨‍🏫 **أوامر الأستاذ:**\n\n"
            "📨 **إرسال إعلانات:**\n"
            "• أرسل أي رسالة (نص، صورة، ملف PDF، صوت، فيديو)\n"
            "• وسيتم بثها تلقائياً لجميع الطلاب\n\n"
            "🔒 **الملفات المسموح بها:**\n"
            "• PDF، صور، مستندات Office\n"
            "• ملفات ZIP، MP3، MP4\n"
            "• **غير مسموح:** EXE، JS، PY، BAT\n\n"
            "📊 **الأوامر:**\n"
            "• /stats - عرض إحصائيات مفصلة عن جميع الإعلانات\n"
            "• /help - عرض هذه الرسالة\n"
            "• /broadcast - بث رسالة نصية\n"
            "• /cleanup - تنظيف الإعلانات القديمة\n"
            "• /delete - حذف إعلان محدد\n"
            "• /subscribers - عرض قائمة المشتركين\n"
            "• /remove - إزالة طالب من الاشتراك\n"
            "• /add - إضافة طالب يدويًا\n"
            "• /read - تفاصيل قراءة إعلان محدد\n"
            "• /read_all - تقرير كامل لقراءة جميع الإعلانات\n\n"
            f"📈 **المعلومات الحالية:**\n"
            f"• عدد الطلاب: {total_students}\n"
            f"• عدد الإعلانات: {total_announcements}\n\n"
            f"🗑️ **سياسة التنظيف:**\n"
            f"• يتم حذف الإعلانات القديمة تلقائياً بعد {ANNOUNCEMENT_RETENTION_DAYS} يوم"
        )
    else:
        help_text = (
            "👨‍🎓 **تعليمات الطالب:**\n\n"
            "📥 **الاشتراك:**\n"
            "• /start - الاشتراك في قناة الإعلانات\n\n"
            "✅ **تأكيد الاستلام:**\n"
            "• اضغط على زر 'تم الاستلام ✅' تحت كل إعلان\n"
            "• لتسجيل استلامك للإعلان\n\n"
            "⚠️ **ملاحظة مهمة:**\n"
            "هذا البوت مخصص فقط لاستقبال الإعلانات الدراسية من الأستاذ.\n"
            "لا يمكنك إرسال أي رسائل أو ملفات هنا."
        )
    
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manual broadcast command for admin with security checks."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        return
    
    if not context.args:
        await update.message.reply_text(
            "📢 استخدام الأمر:\n"
            "/broadcast <الرسالة>\n\n"
            "مثال:\n"
            "/broadcast اختبار غداً الساعة 10 صباحاً",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    # تنظيف الإعلانات القديمة قبل إنشاء إعلان جديد
    await cleanup_before_new_announcement()
    
    message_text = " ".join(context.args)
    subscribers = await SubscriberManager.get_all_subscribers()
    
    if not subscribers:
        await update.message.reply_text("⚠️ لا يوجد طلاب مشتركين بعد.", parse_mode=ParseMode.MARKDOWN)
        return
    
    # Generate unique announcement ID
    announcement_id = str(uuid4())[:8]
    
    # Prepare announcement data
    announcement_data = {
        'type': 'text',
        'content': message_text,
        'sender_id': user_id,
        'message_id': update.message.message_id
    }
    
    # Save announcement
    await AnnouncementManager.create_announcement(announcement_id, announcement_data)
    
    # Create inline button
    keyboard = [[
        InlineKeyboardButton("تم الاستلام ✅", callback_data=f"read_{announcement_id}")
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Broadcast to all subscribers using batches for better performance
    successful_sends = 0
    failed_sends = []
    
    # Batch size for parallel sending - reduced for safety
    BATCH_SIZE = 20
    
    for i in range(0, len(subscribers), BATCH_SIZE):
        batch = subscribers[i:i + BATCH_SIZE]
        tasks = []
        
        for subscriber_id in batch:
            task = context.bot.send_message(
                chat_id=subscriber_id,
                text=message_text,
                reply_markup=reply_markup,
                parse_mode=ParseMode.MARKDOWN
            )
            tasks.append(task)
        
        # Send batch in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for subscriber_id, result in zip(batch, results):
            if not isinstance(result, Exception):
                successful_sends += 1
            else:
                failed_sends.append(subscriber_id)
        
        # Increased delay between batches to avoid rate limiting
        if i + BATCH_SIZE < len(subscribers):
            await asyncio.sleep(1.0)
    
    # Send report to admin
    report = (
        f"📊 **تقرير البث:**\n\n"
        f"• رقم الإعلان: `{announcement_id}`\n"
        f"• النوع: نص\n"
        f"• تم الإرسال بنجاح: {successful_sends} طالب\n"
        f"• إجمالي المشتركين: {len(subscribers)}"
    )
    
    if failed_sends:
        report += f"\n• فشل الإرسال لـ: {len(failed_sends)} طالب"
    
    preview = message_text[:50] + "..." if len(message_text) > 50 else message_text
    report += f"\n\n📝 المعاينة: {preview}"
    
    await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN)

async def cleanup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manual cleanup command for admin."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    # Ask for confirmation
    keyboard = [
        [InlineKeyboardButton("✅ نعم، احذف الإعلانات القديمة", callback_data="cleanup_confirm")],
        [InlineKeyboardButton("❌ إلغاء", callback_data="cleanup_cancel")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f"🗑️ **تنظيف الإعلانات القديمة**\n\n"
        f"هل تريد حذف الإعلانات الأقدم من {ANNOUNCEMENT_RETENTION_DAYS} يوم؟\n\n"
        f"⚠️ **تحذير:** هذا الإجراء لا يمكن التراجع عنه.",
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN
    )

async def handle_cleanup_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle cleanup confirmation callback."""
    query = update.callback_query
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await query.answer("⛔ هذا الأمر متاح فقط للأستاذ.")
        return
    
    if query.data == "cleanup_cancel":
        await query.message.edit_text("❌ تم إلغاء عملية التنظيف.")
        await query.answer()
        return
    
    if query.data == "cleanup_confirm":
        await query.answer("🔄 جاري التنظيف...")
        
        # Perform cleanup
        deleted_count = await cleanup_old_announcements()
        
        if deleted_count > 0:
            await query.message.edit_text(
                f"✅ تم تنظيف {deleted_count} إعلان قديم (أقدم من {ANNOUNCEMENT_RETENTION_DAYS} يوم)\n\n"
                f"📊 تم تحرير مساحة في ملف JSON.",
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await query.message.edit_text(
                "ℹ️ لم يتم العثور على إعلانات قديمة للتنظيف.\n\n"
                f"جميع الإعلانات أحدث من {ANNOUNCEMENT_RETENTION_DAYS} يوم.",
                parse_mode=ParseMode.MARKDOWN
            )

# ========== NEW ADMIN COMMANDS ==========

async def delete_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Delete a specific announcement by ID."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    if not context.args:
        await update.message.reply_text(
            "🗑️ استخدام الأمر:\n"
            "/delete <معرف_الإعلان>\n\n"
            "مثال:\n"
            "/delete abc123\n\n"
            "📝 لمعرفة معرفات الإعلانات استخدم /stats",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    announcement_id = context.args[0].strip()
    
    # Validate announcement exists
    announcements = await load_json(ANNOUNCEMENTS_FILE, {})
    receipts = await load_json(READ_RECEIPTS_FILE, {})
    
    if announcement_id not in announcements:
        await update.message.reply_text(
            f"❌ الإعلان `{announcement_id}` غير موجود.\n"
            f"استخدم /stats لرؤية قائمة الإعلانات ومعرفاتها.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    # Get announcement info before deleting
    announcement_data = announcements.get(announcement_id, {})
    announcement_type = announcement_data.get('type', 'نص')
    content_preview = announcement_data.get('content', '')[:50]
    read_count = len(receipts.get(announcement_id, []))
    
    # Delete announcement
    del announcements[announcement_id]
    
    # Delete corresponding receipts if they exist
    if announcement_id in receipts:
        del receipts[announcement_id]
    
    # Save changes
    success1 = await save_json(ANNOUNCEMENTS_FILE, announcements)
    success2 = await save_json(READ_RECEIPTS_FILE, receipts)
    
    if success1 and success2:
        await update.message.reply_text(
            f"✅ تم حذف الإعلان بنجاح!\n\n"
            f"• المعرف: `{announcement_id}`\n"
            f"• النوع: {announcement_type}\n"
            f"• المحتوى: {content_preview}...\n"
            f"• عدد التأكيدات: {read_count}\n\n"
            f"📊 تم تنظيف الملفات بنجاح.",
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await update.message.reply_text(
            "❌ حدث خطأ أثناء حذف الإعلان. حاول مرة أخرى.",
            parse_mode=ParseMode.MARKDOWN
        )

async def subscribers_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show list of all subscribers and their count."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    subscribers = await SubscriberManager.get_all_subscribers()
    total_count = len(subscribers)
    
    if total_count == 0:
        await update.message.reply_text("📭 لا يوجد طلاب مشتركين حتى الآن.", parse_mode=ParseMode.MARKDOWN)
        return
    
    # Create formatted list
    report_lines = [f"👥 **قائمة الطلاب المشتركين**\n"]
    report_lines.append(f"• العدد الإجمالي: {total_count} طالب\n")
    report_lines.append("📋 **المعرفات:**\n")
    
    # Group subscribers for better display
    for i in range(0, total_count, 10):
        batch = subscribers[i:i+10]
        batch_line = ", ".join([f"`{user_id}`" for user_id in batch])
        report_lines.append(f"{batch_line}\n")
    
    full_report = "".join(report_lines)
    
    if len(full_report) > 4000:
        # Split into chunks
        chunks = [full_report[i:i+4000] for i in range(0, len(full_report), 4000)]
        for chunk in chunks:
            await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(full_report, parse_mode=ParseMode.MARKDOWN)

async def remove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Remove a student from subscribers list."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    if not context.args:
        await update.message.reply_text(
            "❌ استخدام الأمر:\n"
            "/remove <معرف_الطالب>\n\n"
            "مثال:\n"
            "/remove 123456789\n\n"
            "📝 لرؤية قائمة المشتركين استخدم /subscribers",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    try:
        student_id = int(context.args[0].strip())
    except ValueError:
        await update.message.reply_text(
            "❌ معرف الطالب يجب أن يكون رقماً صحيحاً.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    # Remove student with atomic operation
    success = await SubscriberManager.remove_subscriber(student_id)
    
    if success:
        total_count = await SubscriberManager.count_subscribers()
        await update.message.reply_text(
            f"✅ تم إزالة الطالب بنجاح!\n\n"
            f"• المعرف: `{student_id}`\n"
            f"• العدد الحالي للمشتركين: {total_count}",
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await update.message.reply_text(
            "❌ حدث خطأ أثناء إزالة الطالب. حاول مرة أخرى.",
            parse_mode=ParseMode.MARKDOWN
        )

async def add_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manually add a student to subscribers list."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    if not context.args:
        await update.message.reply_text(
            "➕ استخدام الأمر:\n"
            "/add <معرف_الطالب>\n\n"
            "مثال:\n"
            "/add 123456789\n\n"
            "📝 هذه العملية تضيف الطالب يدوياً إذا لم يستخدم /start",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    try:
        student_id = int(context.args[0].strip())
    except ValueError:
        await update.message.reply_text(
            "❌ معرف الطالب يجب أن يكون رقماً صحيحاً.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    # Validate student ID
    if student_id <= 0:
        await update.message.reply_text(
            "❌ معرف الطالب غير صالح.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    # Add student manually with atomic operation
    success = await SubscriberManager.add_subscriber(student_id)
    
    if success:
        total_count = await SubscriberManager.count_subscribers()
        await update.message.reply_text(
            f"✅ تم إضافة الطالب بنجاح!\n\n"
            f"• المعرف: `{student_id}`\n"
            f"• تمت الإضافة يدوياً\n"
            f"• العدد الإجمالي للمشتركين: {total_count}\n\n"
            f"📝 يمكن للطالب الآن استقبال الإعلانات دون استخدام /start",
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await update.message.reply_text(
            "❌ حدث خطأ أثناء إضافة الطالب. حاول مرة أخرى.",
            parse_mode=ParseMode.MARKDOWN
        )

async def read_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show read count for a specific announcement."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    if not context.args:
        await update.message.reply_text(
            "📖 استخدام الأمر:\n"
            "/read <معرف_الإعلان>\n\n"
            "مثال:\n"
            "/read abc123\n\n"
            "📝 لمعرفة معرفات الإعلانات استخدم /stats",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    announcement_id = context.args[0].strip()
    
    # Validate announcement exists
    announcement = await AnnouncementManager.get_announcement(announcement_id)
    
    if not announcement:
        await update.message.reply_text(
            f"❌ الإعلان `{announcement_id}` غير موجود.\n"
            f"استخدم /stats لرؤية قائمة الإعلانات ومعرفاتها.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    # Get read count and users
    read_count = await ReadReceiptManager.get_read_count(announcement_id)
    read_users = await ReadReceiptManager.get_read_users(announcement_id)
    total_students = await SubscriberManager.count_subscribers()
    
    # Get announcement details
    announcement_type = announcement.get('type', 'نص')
    content_preview = announcement.get('content', '')[:100]
    try:
        timestamp = datetime.fromisoformat(announcement.get('timestamp', ''))
        time_str = timestamp.strftime("%Y/%m/%d %H:%M")
    except:
        time_str = "تاريخ غير معروف"
    
    # Calculate percentage
    percentage = (read_count / total_students * 100) if total_students > 0 else 0
    
    # Create progress bar
    bars = int(percentage / 10)
    progress_bar = "▓" * bars + "░" * (10 - bars)
    
    # Build report
    report = (
        f"📊 **تفاصيل قراءة الإعلان**\n\n"
        f"• المعرف: `{announcement_id}`\n"
        f"• النوع: {announcement_type}\n"
        f"• الوقت: {time_str}\n"
        f"• المحتوى: {content_preview}\n\n"
        f"📈 **إحصائيات القراءة:**\n"
        f"{progress_bar} {read_count}/{total_students} ({percentage:.1f}%)\n\n"
    )
    
    # Add read users if any
    if read_users:
        report += f"👥 **الطلاب الذين أكدوا الاستلام ({len(read_users)}):**\n"
        
        # Group users for better display
        for i in range(0, len(read_users), 10):
            batch = read_users[i:i+10]
            batch_line = ", ".join([f"`{user_id}`" for user_id in batch])
            report += f"{batch_line}\n"
    else:
        report += "📭 لم يقم أي طالب بتأكيد استلام هذا الإعلان بعد.\n"
    
    # Add unread users if any
    if total_students > read_count:
        all_subscribers = await SubscriberManager.get_all_subscribers()
        unread_users = [uid for uid in all_subscribers if uid not in read_users]
        
        if unread_users:
            report += f"\n📭 **الطلاب الذين لم يؤكدوا ({len(unread_users)}):**\n"
            
            # Show only first 20 unread users to avoid long message
            if len(unread_users) > 20:
                batch_line = ", ".join([f"`{user_id}`" for user_id in unread_users[:20]])
                report += f"{batch_line}\n"
                report += f"و {len(unread_users) - 20} طالب آخرين..."
            else:
                batch_line = ", ".join([f"`{user_id}`" for user_id in unread_users])
                report += f"{batch_line}\n"
    
    await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN)

async def read_all_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show comprehensive report of all announcements with read rates."""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("⛔ هذا الأمر متاح فقط للأستاذ.", parse_mode=ParseMode.MARKDOWN)
        return
    
    # Get all data
    announcements = await AnnouncementManager.get_all_announcements()
    receipts = await ReadReceiptManager.get_all_receipts()
    total_students = await SubscriberManager.count_subscribers()
    
    if not announcements:
        await update.message.reply_text("📭 لا توجد إعلانات حتى الآن.", parse_mode=ParseMode.MARKDOWN)
        return
    
    # Prepare comprehensive report
    report_lines = ["📊 **تقرير كامل لقراءة الإعلانات**\n"]
    report_lines.append(f"👥 إجمالي الطلاب: {total_students}\n")
    report_lines.append(f"📨 إجمالي الإعلانات: {len(announcements)}\n")
    
    total_reads = 0
    announcement_details = []
    
    # Process each announcement
    for ann_id, ann_data in announcements.items():
        read_count = len(receipts.get(ann_id, []))
        total_reads += read_count
        
        # Type emoji mapping
        type_emojis = {
            'text': '📝',
            'photo': '🖼️',
            'document': '📄',
            'pdf': '📕',
            'audio': '🎵',
            'video': '🎬'
        }
        
        emoji = type_emojis.get(ann_data.get('type', 'text'), '📌')
        
        # Format timestamp
        try:
            timestamp = datetime.fromisoformat(ann_data.get('timestamp', ''))
            time_str = timestamp.strftime("%Y/%m/%d")
        except:
            time_str = "تاريخ غير معروف"
        
        # Calculate percentage
        percentage = (read_count / total_students * 100) if total_students > 0 else 0
        
        # Store details for sorting
        announcement_details.append({
            'id': ann_id,
            'emoji': emoji,
            'time': time_str,
            'read_count': read_count,
            'percentage': percentage
        })
    
    # Sort by read percentage (highest first)
    announcement_details.sort(key=lambda x: x['percentage'], reverse=True)
    
    # Add detailed list
    report_lines.append("\n🏆 **تصنيف الإعلانات حسب نسبة القراءة:**\n")
    
    for i, detail in enumerate(announcement_details, 1):
        # Progress bar
        bars = int(detail['percentage'] / 10)
        progress_bar = "▓" * bars + "░" * (10 - bars)
        
        report_lines.append(
            f"{i}. {detail['emoji']} **#{detail['id'][:6]}** ({detail['time']})\n"
            f"   {progress_bar} {detail['read_count']}/{total_students} ({detail['percentage']:.1f}%)\n"
        )
    
    # Calculate overall statistics
    if len(announcements) > 0 and total_students > 0:
        avg_read_rate = (total_reads / (len(announcements) * total_students)) * 100
    else:
        avg_read_rate = 0
    
    # Best and worst performing announcements
    if announcement_details:
        best = announcement_details[0]
        worst = announcement_details[-1]
        
        report_lines.append(f"\n{'='*30}")
        report_lines.append("📈 **ملخص الأداء:**\n")
        report_lines.append(f"• متوسط نسبة القراءة: {avg_read_rate:.1f}%\n")
        report_lines.append(f"• أفضل إعلان: #{best['id'][:6]} ({best['percentage']:.1f}%)\n")
        report_lines.append(f"• أسوأ إعلان: #{worst['id'][:6]} ({worst['percentage']:.1f}%)\n")
    
    # Add recommendations based on read rates
    report_lines.append(f"\n💡 **توصيات:**\n")
    if avg_read_rate >= 80:
        report_lines.append("• 📊 أداء ممتاز! الطلاب متفاعلون جداً.\n")
    elif avg_read_rate >= 60:
        report_lines.append("• 👍 أداء جيد. استمر في التواصل مع الطلاب.\n")
    elif avg_read_rate >= 40:
        report_lines.append("• ⚠️ أداء متوسط. حاول تنويع توقيت الإعلانات.\n")
    else:
        report_lines.append("• ❌ أداء ضعيف. راجع محتوى وتوقيت الإعلانات.\n")
    
    # Send report
    full_report = "".join(report_lines)
    
    if len(full_report) > 4000:
        # Split into chunks
        chunks = [full_report[i:i+4000] for i in range(0, len(full_report), 4000)]
        for chunk in chunks:
            await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(full_report, parse_mode=ParseMode.MARKDOWN)

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors and notify admin with sanitized data."""
    error_message = str(context.error)[:200] if context.error else "Unknown error"
    error_type = type(context.error).__name__ if context.error else "Unknown"
    
    # Sanitize logs
    sanitized_error = error_message.replace(TOKEN, "[TOKEN_REMOVED]")
    
    logger.error(f"Exception while handling an update: {sanitized_error}")
    
    # Send error message to admin (with sanitized data)
    try:
        error_msg = (
            f"⚠️ **خطأ في البوت**\n\n"
            f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🔄 {update.update_id if update else 'N/A'}\n"
            f"❌ {error_type}: {sanitized_error[:100]}"
        )
        
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=error_msg,
            parse_mode=ParseMode.MARKDOWN
        )
    except Exception as e:
        logger.error(f"Failed to send error notification: {e}")

# ========== INITIALIZATION & UTILITIES ==========
async def initialize_data_files():
    """Initialize JSON files if they don't exist."""
    files_to_init = [
        (SUBSCRIBERS_FILE, []),
        (ANNOUNCEMENTS_FILE, {}),
        (READ_RECEIPTS_FILE, {})
    ]
    
    for file_path, default_data in files_to_init:
        if not os.path.exists(file_path):
            await save_json(file_path, default_data)
            logger.info(f"Initialized {file_path}")

async def setup_bot_commands(application):
    """Set up bot commands menu."""
    commands = [
        BotCommand("start", "الاشتراك في الإعلانات"),
        BotCommand("stats", "عرض الإحصائيات (للأستاذ)"),
        BotCommand("help", "عرض التعليمات"),
        BotCommand("broadcast", "بث رسالة نصية (للأستاذ)"),
        BotCommand("cleanup", "تنظيف الإعلانات القديمة (للأستاذ)"),
        BotCommand("delete", "حذف إعلان محدد (للأستاذ)"),
        BotCommand("subscribers", "عرض قائمة المشتركين (للأستاذ)"),
        BotCommand("remove", "إزالة طالب من الاشتراك (للأستاذ)"),
        BotCommand("add", "إضافة طالب يدويًا (للأستاذ)"),
        BotCommand("read", "عرض تفاصيل قراءة إعلان (للأستاذ)"),
        BotCommand("read_all", "تقرير كامل لقراءة الإعلانات (للأستاذ)")
    ]
    
    await application.bot.set_my_commands(commands)
    logger.info("Bot commands set up successfully")

# ========== MAIN APPLICATION ==========
def main():
    """Initialize and run the bot with security checks."""
    try:
        # Verify environment variables
        if not TOKEN:
            logger.error("BOT_TOKEN environment variable is required!")
            print("❌ خطأ: متغير البيئة BOT_TOKEN مطلوب!")
            print("📝 كيفية التشغيل:")
            print("   export BOT_TOKEN='توكن_البوت'")
            print("   export ADMIN_ID='معرف_الأستاذ'")
            print("   python bot.py")
            return
        
        # Create application
        application = Application.builder().token(TOKEN).build()
        
        # Initialize data files
        asyncio.run(initialize_data_files())
        
        # Add handlers with proper order
        application.add_handler(CommandHandler("start", start_command))
        application.add_handler(CommandHandler("stats", stats_command))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("broadcast", broadcast_command))
        application.add_handler(CommandHandler("cleanup", cleanup_command))
        
        # Add new admin command handlers
        application.add_handler(CommandHandler("delete", delete_command))
        application.add_handler(CommandHandler("subscribers", subscribers_command))
        application.add_handler(CommandHandler("remove", remove_command))
        application.add_handler(CommandHandler("add", add_command))
        application.add_handler(CommandHandler("read", read_command))
        application.add_handler(CommandHandler("read_all", read_all_command))
        
        # Handle cleanup callback
        application.add_handler(CallbackQueryHandler(handle_cleanup_callback, pattern="^cleanup_"))
        
        # Handle read receipt button clicks (must be before MessageHandler)
        application.add_handler(CallbackQueryHandler(handle_read_receipt))
        
        # Handle admin messages (broadcast to all)
        admin_filter = filters.User(user_id=ADMIN_ID) & ~filters.COMMAND
        application.add_handler(MessageHandler(admin_filter, handle_admin_message))
        
        # Handle student messages (reject with polite message)
        student_filter = ~filters.User(user_id=ADMIN_ID) & ~filters.COMMAND
        application.add_handler(MessageHandler(student_filter, handle_student_message))
        
        # Error handler
        application.add_error_handler(error_handler)
        
        # Setup bot commands on startup
        application.post_init = setup_bot_commands
        
        # Start polling
        print("=" * 60)
        print("🤖 بدء تشغيل بوت الإعلانات الدراسية - النسخة الآمنة المصححة")
        print("=" * 60)
        print(f"✅ البوت يعمل الآن...")
        print(f"👨‍🏫 معرف الأستاذ: {ADMIN_ID}")
        print(f"🔒 Token: [محمي]")
        print(f"🗑️ تنظيف الإعلانات: بعد {ANNOUNCEMENT_RETENTION_DAYS} يوم")
        print("=" * 60)
        print("📝 الملفات المسموح بها:")
        print("  • PDF، صور، مستندات Office")
        print("  • ملفات ZIP، MP3، MP4")
        print("  • ❌ غير مسموح: EXE، JS، PY، BAT")
        print("=" * 60)
        print("🛡️ **تحسينات الأمان المضافة:**")
        print("  • ✅ Atomic Read-Modify-Write لعمليات الملفات")
        print("  • ✅ منع Race Condition وحالة السباق")
        print("  • ✅ نقل عمليات I/O لـ Thread Pool لمنع Blocking")
        print("  • ✅ حماية البيانات من الفقدان عند الضغط المتزامن")
        print("=" * 60)
        print("🎯 **الأوامر الإدارية:**")
        print("  • /delete - حذف إعلان محدد")
        print("  • /subscribers - عرض قائمة المشتركين")
        print("  • /remove - إزالة طالب من الاشتراك")
        print("  • /add - إضافة طالب يدويًا")
        print("  • /read - تفاصيل قراءة إعلان")
        print("  • /read_all - تقرير كامل للقراءة")
        print("=" * 60)
        
        # Run the bot
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True
        )
        
    except KeyError as e:
        logger.error(f"Missing environment variable: {e}")
        print(f"❌ خطأ: متغير البيئة {e} مفقود!")
        print("📝 كيفية التشغيل:")
        print("   export BOT_TOKEN='توكن_البوت'")
        print("   export ADMIN_ID='معرف_الأستاذ'")
        print("   python bot.py")
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        print(f"❌ فشل تشغيل البوت: {e}")

if __name__ == "__main__":
    main()
