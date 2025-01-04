from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# List of allowed IP addresses
allowed_ips = [
    '192.168.0.103'
]

BOT_TOKEN = '7217660908:AAHzZNo0AhHvA1a0kJ8ifY5S91lYN_XeHok'
TELEGRAM_API_URL = f'https://api.telegram.org/bot{7217660908:AAHzZNo0AhHvA1a0kJ8ifY5S91lYN_XeHok}/'


@app.route('/<path:path>', methods=['POST'])
def proxy(path):
    user_ip = request.remote_addr
    if user_ip not in allowed_ips:
        return jsonify({'error': 'Your IP address is not authorized to use this bot.'}), 403

    # Forward the request to the Telegram bot
    response = requests.post(TELEGRAM_API_URL + path, json=request.json)
    return jsonify(response.json())


if __name__ == '__main__':
    app.run(port=5000)
