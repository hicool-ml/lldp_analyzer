#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internationalization support for LLDP/CDP Protocol Analyzer."""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, Any, Optional


class Translator:
    """Multi-language translation manager."""
    
    def __init__(self):
        self._current_lang = "en"
        self._translations: Dict[str, Dict[str, str]] = {}
        self._fallback_lang = "en"
    
    def load_translations(self, lang_dir: str = None) -> None:
        """Load translation files from the locales directory."""
        if lang_dir is None:
            lang_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")
        
        if not os.path.isdir(lang_dir):
            return
        
        for filename in os.listdir(lang_dir):
            if filename.endswith(".json"):
                lang_code = filename[:-5]  # Remove .json
                filepath = os.path.join(lang_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        self._translations[lang_code] = json.load(f)
                except Exception as e:
                    print(f"Error loading translation file {filename}: {e}")
    
    def set_language(self, lang_code: str) -> bool:
        """Set the current language. Returns True if successful."""
        if lang_code in self._translations:
            self._current_lang = lang_code
            return True
        return False
    
    def get_language(self) -> str:
        """Get the current language code."""
        return self._current_lang
    
    def get_language_name(self, lang_code: Optional[str] = None) -> str:
        """Get the display name for a language code."""
        names = {
            "en": "English",
            "zh": "中文",
            "fr": "Français",
            "es": "Español",
            "ru": "Русский",
            "ja": "日本語",
            "ko": "한국어",
        }
        return names.get(lang_code or self._current_lang, lang_code or self._current_lang)
    
    def get_available_languages(self) -> list[str]:
        """Get list of available language codes."""
        return list(self._translations.keys()) or ["en"]
    
    def translate(self, key: str, **kwargs) -> str:
        """Translate a key to the current language.
        
        Args:
            key: Translation key
            **kwargs: Optional placeholders for substitution
        
        Returns:
            Translated string, or the key itself if not found.
        """
        # Try current language
        if self._current_lang in self._translations:
            if key in self._translations[self._current_lang]:
                text = self._translations[self._current_lang][key]
                if kwargs:
                    try:
                        return text.format(**kwargs)
                    except KeyError:
                        pass
                return text
        
        # Fallback to default language
        if self._fallback_lang in self._translations and key in self._translations[self._fallback_lang]:
            text = self._translations[self._fallback_lang][key]
            if kwargs:
                try:
                    return text.format(**kwargs)
                except KeyError:
                    pass
            return text
        
        # Return key if not found
        return key


def get_system_language() -> str:
    """Detect the system language and return a language code."""
    if sys.platform == "win32":
        try:
            import ctypes
            user32 = ctypes.windll.user32
            lang_id = user32.GetSystemDefaultUILanguage()
            primary_lang = lang_id & 0xFFF
            lang_map = {
                0x0409: "en",  # English (US)
                0x0809: "en",  # English (UK)
                0x0C09: "en",  # English (Australian)
                0x1009: "en",  # English (Canadian)
                0x0404: "zh",  # Chinese (Traditional)
                0x0804: "zh",  # Chinese (Simplified)
                0x0C04: "zh",  # Chinese (Singapore)
                0x1004: "zh",  # Chinese (Malaysia)
                0x0411: "ja",  # Japanese
                0x0412: "ko",  # Korean
                0x0407: "de",  # German
                0x040C: "fr",  # French
                0x0410: "it",  # Italian
                0x0416: "pt",  # Portuguese (Brazil)
                0x0816: "pt",  # Portuguese (Portugal)
                0x040A: "es",  # Spanish (Spain)
                0x080A: "es",  # Spanish (Mexico)
            }
            if primary_lang in lang_map:
                return lang_map[primary_lang]
        except Exception:
            pass
        
        try:
            import locale
            default_locale = locale.getdefaultlocale()
            if default_locale:
                lang_code = default_locale[0]
                if lang_code.startswith("zh"):
                    return "zh"
                elif lang_code.startswith("ja"):
                    return "ja"
                elif lang_code.startswith("ko"):
                    return "ko"
                else:
                    return "en"
        except Exception:
            pass
        
        try:
            lang_env = os.environ.get("LANG", os.environ.get("LC_ALL", "")
).split("_")[0]
            if lang_env.startswith("zh"):
                return "zh"
            elif lang_env.startswith("ja"):
                return "ja"
            elif lang_env.startswith("ko"):
                return "ko"
            else:
                return "en"
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            import subprocess
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleLanguages"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                lang_code = result.stdout.strip().split()[0].strip('()",')
                if lang_code.startswith("zh"):
                    return "zh"
                elif lang_code.startswith("ja"):
                    return "ja"
                elif lang_code.startswith("ko"):
                    return "ko"
                else:
                    return "en"
        except Exception:
            pass
    elif sys.platform.startswith("linux"):
        try:
            lang_env = os.environ.get("LANG", "").split("_")[0]
            if lang_env.startswith("zh"):
                return "zh"
            elif lang_env.startswith("ja"):
                return "ja"
            elif lang_env.startswith("ko"):
                return "ko"
            else:
                return "en"
        except Exception:
            pass
    
    return "zh"


# Global translator instance
_translator = Translator()


def init_translations() -> None:
    """Initialize translations with system language."""
    _translator.load_translations()
    system_lang = get_system_language()
    _translator.set_language(system_lang)


def _(key: str, **kwargs) -> str:
    """Translate a key using the global translator."""
    return _translator.translate(key, **kwargs)


def get_translator() -> Translator:
    """Get the global translator instance."""
    return _translator