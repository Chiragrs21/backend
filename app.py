from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from pymongo import MongoClient
import asyncio
import bcrypt
import jwt
import json
from functools import wraps
from datetime import datetime
from api4 import ipv6_location
from api5 import certificates
from api6 import check_domain
from read import url_results
import pandas as pd
from api7 import email_reader
from api8 import email_social_media
from api9 import email_verification
from api10 import ip_verification
from api11 import domain_search
from api12 import domain_email_search
from api13 import ip4_geolocator
from api14 import phone_lookup
from invincible_ocean import AadhartoPan
from vehicle_num import vehicle_num_out
from Pan import pan_details
from UPI import upi_details
from UPItoBANK import upitobank
from Breached import breaches
import ipaddress
from bson import Binary
import base64

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'wedbjviu2e'
client = MongoClient('mongodb://localhost:27017/')
db = client['mydatabase2']
ADMIN_USERNAME = "admin_user"


async def scan_url_async(url):
    return await url_results(url)

current_datetime = datetime.now()
formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")


def update_credits1(username, amount):
    user = db.users.find_one({'username': username})
    if user and 'credits' in user:
        new_credits = int(user['credits']) + amount
        db.users.update_one({'username': username}, {
                            '$set': {'credits': new_credits}})
        return new_credits
    return None


@app.route('/search', methods=['POST'])
def search_query():
    data = request.get_json()
    user_query = data.get('query')

    if not user_query:
        return jsonify({"found": False, "message": "No query provided"}), 400

    results_list = []

    # Iterate over all collections in the database
    for collection_name in db.list_collection_names():
        collection = db[collection_name]

        # Search for documents where the "query" field matches the user's query
        results = collection.find({"query": user_query})

        for result in results:
            document_info = {
                "name": result.get("name", "N/A"),
                "query": result.get("query", "N/A"),
                "date": result.get("date", "N/A"),
                "collection": collection_name
            }

            # Search for user details in the 'users' collection of the current collection
            user_details = db.users.find_one(
                {"username": collection_name})

            if user_details:
                document_info['user_details'] = {
                    "username": user_details.get("username", "N/A"),
                    "role": user_details.get("role", "N/A"),
                    "phone_number": user_details.get("phone_number", "N/A"),
                    "station_name": user_details.get("station_name", "N/A"),
                }
            else:
                document_info['user_details'] = {
                    "username": "N/A",
                    "role": "N/A",
                    "phone_number": result.get("N/A"),
                    "station_name": result.get("N/A"),
                    "message": "User details not found"
                }

            results_list.append(document_info)

    if results_list:
        return jsonify({"found": True, "results": results_list})
    else:
        return jsonify({"found": False, "message": "No matching documents found"})


def specific_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 403

        # Assuming verify_token returns the username
        username = verify_token(token)

        if not username:
            return jsonify({"message": "Invalid token!"}), 403

        # Check if the username is the specific admin
        if username != ADMIN_USERNAME:
            return jsonify({"message": "Access restricted to admin only!"}), 403

        return f(*args, **kwargs)
    return decorated_function


@app.route('/get_total_queries', methods=['GET'])
def get_total_queries():
    try:
        # Extract token and verify the username
        token = request.headers.get('Authorization')
        username = verify_token(token)

        if not username:
            return jsonify({'error': 'Invalid token'}), 403

        # Get the user's collection
        user_collection = db[username]

        # Count the number of documents in the collection
        total_queries = user_collection.count_documents({})

        return jsonify({'total_queries': total_queries}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_credit_balance', methods=['GET'])
def get_credit_balance():
    try:
        # Extract token and verify the username
        token = request.headers.get('Authorization')
        username = verify_token(token)

        if not username:
            return jsonify({'error': 'Invalid token'}), 403

        # Fetch the user's document from the `users` collection
        user_doc = db['users'].find_one({'username': username})

        if not user_doc:
            return jsonify({'error': 'User not found'}), 404

        # Get the credit balance
        credit_balance = user_doc.get('credits', 0)

        return jsonify({'credits': credit_balance}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/verify_admin', methods=['GET'])
def verify_admin():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if username == ADMIN_USERNAME:
        return jsonify({"isAdmin": True})
    return jsonify({"isAdmin": False}), 403


@app.route('/export_data', methods=['GET'])
def export_data():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    data = list(db[username].find({}, {'_id': 0}))

    if not data:
        return jsonify({'error': 'No data found'}), 404

    df = pd.DataFrame(data)
    csv_data = df.to_csv(index=False)

    response = Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=data.csv"}
    )

    return response


@app.route('/api/users', methods=['GET'])
@specific_admin_required
def get_users():
    try:
        users = list(db.users.find({}, {'_id': 0, 'password': 0}))
        return jsonify({'users': users})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<username>', methods=['GET'])
@specific_admin_required
def get_user(username):
    try:
        # Fetch user information from 'users' collection
        user = db.users.find_one({'username': username}, {
                                 '_id': 0, 'password': 0})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Decode the BinData password if it exists
        if 'password' in user and isinstance(user['password'], Binary):
            user['password'] = base64.b64encode(
                user['password']).decode('utf-8')

        return jsonify(user)
    except Exception as e:
        print(str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/user_collection_lengths', methods=['GET'])
@specific_admin_required
def get_user_collection_lengths():
    collections = db.list_collection_names()
    collection_lengths = []

    for collection_name in collections:
        collection = db[collection_name]
        length = collection.count_documents({})
        collection_lengths.append({
            'collection_name': collection_name,
            'length': length
        })

    return jsonify({'data': collection_lengths})


@app.route('/api/user_details/<username>', methods=['GET'])
@specific_admin_required
def get_user_details(username):
    try:
        # Fetch all user details from collection named after username
        # Convert cursor to list and exclude '_id'
        user_details = list(db[username].find({}, {'_id': 0}))
        if not user_details:
            return jsonify({'error': 'User details not found'}), 200
        return jsonify(user_details)  # Return all user details as a JSON array
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/change_password', methods=['POST'])
@specific_admin_required
def change_password():
    try:
        data = request.json
        username = data.get('username')
        new_password = data.get('newPassword')

        if not username or not new_password:
            return jsonify({'error': 'Username and new password are required'}), 400

        # Hash the new password
        hashed_password = bcrypt.hashpw(
            new_password.encode(), bcrypt.gensalt())

        # Update the password in the 'users' collection
        result = db.users.update_one({'username': username}, {
                                     '$set': {'password': hashed_password}})
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404

        # Optionally, create a collection named after the username if it doesn't exist
        if username not in db.list_collection_names():
            db.create_collection(username)

        return jsonify({'message': 'Password updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/update_credits', methods=['POST'])
@specific_admin_required
def update_credits():
    data = request.get_json()
    username = data.get('username')
    new_credits = data.get('newCredits')

    if not username or new_credits is None:
        return jsonify({'error': 'Username and new credits are required'}), 400

    try:
        # Find the user and update their credits
        result = db['users'].update_one(
            {'username': username},
            {'$set': {'credits': new_credits}}
        )

        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'message': 'Credits updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/user_collections', methods=['GET'])
@specific_admin_required
def get_user_collections():
    try:
        # List all collections
        collections = db.list_collection_names()

        # Initialize a list to store all data
        all_data = []

        for collection in collections:
            # Skip the "users" collection
            if collection == "users":
                continue

            # Fetch data from each collection
            data = list(db[collection].find({}, {'_id': 0}))
            for item in data:
                item['collection_name'] = collection
                all_data.append(item)

        # Return all data
        return jsonify({
            'data': all_data
        })
    except Exception as e:
        # Return detailed error message
        print(str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/total_users', methods=['GET'])
@specific_admin_required
def get_total_users():
    user_collections = db.list_collection_names()  # List all collections
    total_users = len(user_collections)
    return jsonify({"total_users": total_users})


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Extracting required fields from the request body
    username = data.get('username')
    role = data.get('role')
    station_name = data.get('station_name')
    phone_number = data.get('phone_number')
    address = data.get('address')
    password = data.get('password')
    credits = data.get('credits')

    # Ensure required fields are provided
    if not username or not password or credits is None:
        return jsonify({'error': 'Username, password, and credits are required'}), 400

    # Validate credits

    # Check if the username already exists
    if db.users.find_one({'username': username}):
        return jsonify({'error': 'User already exists'}), 400

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Get current date and time
    current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Insert new user data into the 'users' collection
    db.users.insert_one({
        'username': username,
        'password': hashed_password,
        'role': role,
        'station_name': station_name,
        'phone_number': phone_number,
        'address': address,
        'credits': credits,
        'date': current_date
    })

    # Create a new collection with the user's username
    db.create_collection(username)

    return jsonify({'message': 'User created successfully'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = db.users.find_one({'username': username})
    if not user or not bcrypt.checkpw(password.encode(), user['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    token = jwt.encode({'username': username},
                       app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token}), 200


def verify_token(token):
    try:
        data = jwt.decode(
            token.split()[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        return data.get('username')
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except (jwt.InvalidTokenError, IndexError):
        return None


@app.route('/url_scanner', methods=['POST'])
def scan_url():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -2)

    data = request.get_json()
    url = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    results = asyncio.run(scan_url_async(url))
    results2 = certificates(url)
    results3 = check_domain(url)
    results4 = domain_search(url)
    # with open('output6.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')
    # results2 = output_data.get('certificates')
    # results3 = output_data.get('check')
    # results4 = output_data.get('domain_search')
    form_data = {
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'certificates': results2,
        "check": results3,
        "domain_search": results4,
        "option": option
    }
    db[username].insert_one(form_data)
    return jsonify({
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'certificates': results2,
        "check": results3,
        "domain_search": results4,
        "option": option
    })


# Email
@app.route('/email', methods=['POST'])
def Email_id():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -4)

    data = request.get_json()
    email = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not email:
        return jsonify({'error': 'No email provided'}), 400

    results = email_reader(email)
    results2 = email_social_media(email)
    result3 = email_verification(email)
    result4 = domain_email_search(email)
    result5 = breaches(email)

    # with open('output.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')
    # results2 = output_data.get('social_media')
    # result3 = output_data.get('verification')
    # result4 = output_data.get('domains')
    # result5 = output_data.get('breaches')

    form_data = {
        'name': name,
        'query': email,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'social_media': results2,
        'verification': result3,
        'domains': result4,
        'breaches': result5,
        'option': option
    }

    db[username].insert_one(form_data)

    return jsonify({
        'name': name,
        'query': email,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'social_media': results2,
        'verification': result3,
        'domains': result4,
        'breaches': result5,
        'option': option
    })


@app.route('/ip6_location', methods=['POST'])
def ipv6_location1():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -3)

    data = request.get_json()
    url = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    is_ipv4 = ipaddress.ip_address(url).version == 4 if '.' in url else False
    is_ipv6 = ipaddress.ip_address(url).version == 6 if ':' in url else False

    if (is_ipv6):
        results = ipv6_location(url)
        results1 = ip_verification(url)
    else:
        results = ip4_geolocator(url)
        results1 = ip_verification(url)

    # with open('output7.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')
    # results1 = output_data.get('verify')

    form_data = {
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'verify': results1,
        'option': option
    }

    db[username].insert_one(form_data)
    return jsonify({
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'verify': results1,
        'option': option
    })


@app.route('/phn_location', methods=['POST'])
def phn_location1():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -2)

    data = request.get_json()
    url = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    results = phone_lookup(url)
    upi = upi_details(url)

    # with open('output1.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')

    # upi = output_data.get('upi_details')

    form_data = {
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'upi_details': upi,
        'option': option
    }

    db[username].insert_one(form_data)
    return jsonify({
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'upi_details': upi,
        'option': option
    })


@app.route('/vehiclenumber', methods=['POST'])
def vehicle_num():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -2)

    data = request.get_json()
    url = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # with open('output5.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')

    results = vehicle_num_out(url)

    form_data = {
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    }

    db[username].insert_one(form_data)
    return jsonify({
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    })


@app.route('/upi', methods=['POST'])
def upi_details_check():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -3)

    data = request.get_json()
    url = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # with open('output2.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')

    results = upitobank(url)

    form_data = {
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    }

    db[username].insert_one(form_data)

    return jsonify({
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    })


@app.route('/aadharnumber', methods=['POST'])
def aadhar_num():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -4)

    data = request.get_json()
    url = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    results = AadhartoPan(url)
    # with open('output4.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')

    form_data = {
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    }

    db[username].insert_one(form_data)
    return jsonify({
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    })


@app.route('/pancard', methods=['POST'])
def pan_card():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    user = db.users.find_one({'username': username})
    if not user or int(user.get('credits', 0)) < 2:
        return jsonify({'error': 'Insufficient credits'}), 403

    # Deduct credits
    update_credits1(username, -3)

    data = request.get_json()
    url = data.get('url')
    name = data.get('name')
    option = data.get('selectedOption')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # with open('output3.json', 'r') as json_file:
    #     output_data = json.load(json_file)

    # # Assuming you have structured data in the JSON file
    # # Extract results based on your keys
    # results = output_data.get('json_data')

    results = pan_details(url)
    form_data = {
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    }

    db[username].insert_one(form_data)
    return jsonify({
        'name': name,
        'query': url,
        'status': 'completed',
        "date": formatted_datetime,
        'json_data': results,
        'option': option
    }
    )


@app.route('/get_data', methods=['GET'])
def get_data():
    token = request.headers.get('Authorization')
    username = verify_token(token)
    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    data = list(db[username].find({}, {'_id': 0}))
    return jsonify(data)


# @app.route('/get_data_by_name/<name>', methods=['GET'])
# def get_data_by_name(name):
#     token = request.headers.get('Authorization')
#     username = verify_token(token)
#     if not username:
#         return jsonify({'error': 'Invalid or expired token'}), 401

#     data = db[username].find_one({'name': name}, {'_id': 0})

#     if not data:
#         return jsonify({'error': 'Data not found'}), 404

#     # Define the file path
#     file_path = f"output7.json"

#     # Write the data to a JSON file
#     with open(file_path, 'w') as json_file:
#         json.dump(data, json_file, indent=4)

#     return jsonify({'message': f'Data saved to {file_path}'}), 200

@app.route('/get_data_by_name/<name>', methods=['GET'])
def get_data_by_name(name):
    token = request.headers.get('Authorization')
    username = verify_token(token)

    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    data = db[username].find_one({'name': name}, {'_id': 0})

    if not data:
        return jsonify({'error': 'Name not found in the database'}), 404

    return jsonify(data)


@app.route('/get_data_by_query/<name>', methods=['GET'])
def get_data_by_query(name):
    token = request.headers.get('Authorization')
    username = verify_token(token)

    if not username:
        return jsonify({'error': 'Invalid or expired token'}), 401

    data = db[username].find_one({'query': name}, {'_id': 0})

    if not data:
        return jsonify({'error': 'Name not found in the database'}), 404

    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True)
