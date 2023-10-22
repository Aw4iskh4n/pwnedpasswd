import hashlib
import requests
from flask import Flask, render_template, request, jsonify, send_from_directory


app = Flask(__name__)

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again.')
    return response

def check_password_leak(pwd):
    sha1pwd = hashlib.sha1(pwd.encode()).hexdigest().upper()
    first5_char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_api_data(first5_char)
    
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return count
    return 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/Images/<filename>')
def serve_image(filename):
    return send_from_directory('Images', filename)

@app.route('/check', methods=['POST'])
def check_passwords():
    passwords = request.form.get('passwords').splitlines()
    results = [(pwd, check_password_leak(pwd)) for pwd in passwords]
    return jsonify({'results': results})

if __name__ == "__main__":
    app.run(debug=True)
    app.run(port=8080)
