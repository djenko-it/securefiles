"""
Patch Redis et Flask-Limiter AVANT tout import de l'application,
pour éviter toute tentative de connexion réseau pendant les tests.
"""
import sys
from unittest.mock import MagicMock

sys.modules['redis'] = MagicMock()
sys.modules['flask_limiter'] = MagicMock()
sys.modules['flask_limiter.util'] = MagicMock()
