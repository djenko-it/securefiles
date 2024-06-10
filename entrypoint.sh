#!/bin/sh
# Entrypoint script to build CSS and start the Flask application

# Build the Tailwind CSS
npm run build:css

# Create the data directory if it doesn't exist
if [ ! -d "/app/data" ]; then
  mkdir -p /app/data
fi

# Initialiser la base de données uniquement si elle n'existe pas
if [ ! -f "/app/messages.db" ]; then
    python -c "from app import init_db; init_db()"
fi

# Start the Flask application
exec "$@"
