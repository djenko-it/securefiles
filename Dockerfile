# Image slim pour réduire la surface d'attaque et la taille de l'image
FROM python:3.11-slim

# Installer Node.js et npm (sans paquets recommandés inutiles)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /app

# Copier et installer les dépendances Python en couche séparée (cache Docker optimal)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Installer les dépendances Node.js
COPY package*.json ./
RUN npm install

# Copier le reste de l'application
COPY . /app

# Construire le CSS avec Tailwind
RUN npm run build:css

# Script d'entrée et permissions
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Créer un utilisateur non-root pour l'exécution (principe du moindre privilège)
RUN useradd -r -s /bin/false -d /app appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app /entrypoint.sh

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000", "app:app"]
