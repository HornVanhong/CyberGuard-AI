"""CyberGuard AI - Persistent Reply Keyboard Menus.

Provides mobile-friendly bottom keyboards (ReplyKeyboardMarkup)
for instant, thumb-friendly navigation across bot capabilities.
"""

from __future__ import annotations

from telegram import KeyboardButton, ReplyKeyboardMarkup


def get_main_reply_keyboard(lang: str = "km") -> ReplyKeyboardMarkup:
    """Returns the persistent bottom reply keyboard menu for mobile and desktop."""
    if lang == "km":
        keyboard = [
            [KeyboardButton("🔍 ស្កេនឯកសារ"), KeyboardButton("💬 សួរ AI Security")],
            [KeyboardButton("⚙️ ស្ថានភាពម៉ាស៊ីន"), KeyboardButton("🔬 Ghidra Decompiler")],
            [KeyboardButton("📋 ប្រវត្តិស្កេន"), KeyboardButton("🌐 ផ្លាស់ប្តូរភាសា")],
            [KeyboardButton("🔐 គោលការណ៍ឯកជនភាព"), KeyboardButton("📚 ការណែនាំ & ជំនួយ")],
        ]
        placeholder = "សូមជ្រើសរើសមុខងារ ឬផ្ញើឯកសារស្កេន..."
    else:
        keyboard = [
            [KeyboardButton("🔍 Scan File"), KeyboardButton("💬 Ask AI Security")],
            [KeyboardButton("⚙️ System Status"), KeyboardButton("🔬 Ghidra Decompiler")],
            [KeyboardButton("📋 Scan History"), KeyboardButton("🌐 Switch Language")],
            [KeyboardButton("🔐 Privacy Policy"), KeyboardButton("📚 Help & Guide")],
        ]
        placeholder = "Select an option or send a file to scan..."

    return ReplyKeyboardMarkup(
        keyboard=keyboard,
        resize_keyboard=True,
        is_persistent=True,
        input_field_placeholder=placeholder,
    )
