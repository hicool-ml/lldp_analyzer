#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Language configuration management using INI format."""

import configparser
import os
import sys
from typing import Optional


class LanguageConfig:
    """Manages language configuration persistence using INI file."""
    
    def __init__(self):
        self._config_path = self._get_config_path()
        self._config = configparser.ConfigParser()
        self._load_config()
    
    def _get_config_path(self) -> str:
        """Get the path to the INI config file."""
        if getattr(sys, 'frozen', False):
            return os.path.join(os.path.dirname(sys.executable), "lldp.ini")
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lldp.ini")
    
    def _load_config(self) -> None:
        """Load configuration from INI file."""
        if os.path.isfile(self._config_path):
            try:
                self._config.read(self._config_path, encoding='utf-8')
            except Exception:
                pass
        if 'Settings' not in self._config:
            self._config['Settings'] = {}
    
    def _save_config(self) -> None:
        """Save configuration to INI file."""
        try:
            with open(self._config_path, 'w', encoding='utf-8') as f:
                self._config.write(f)
        except Exception:
            pass
    
    def get_language(self) -> Optional[str]:
        """Get the saved language preference."""
        return self._config['Settings'].get('language')
    
    def set_language(self, lang_code: str) -> None:
        """Set and save the language preference."""
        self._config['Settings']['language'] = lang_code
        self._save_config()