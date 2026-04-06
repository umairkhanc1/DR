from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
import random
import datetime

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MONGO_URI'] = 'mongodb://localhost:27017/eaton_portal'
app.config['JWT_SECRET_KEY'] = 'eaton-secret-key-2024'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'YOUR_EMAIL@gmail.com'  # CHANGE THIS
app.config['MAIL_PASSWORD'] = 'YOUR_APP_PASSWORD'     # CHANGE THIS

mongo = PyMongo(app)
mail = Mail(app)
jwt = JWTManager(app)

# Temporary storage for verification codes
verification_codes = {}

def send_verification_email(email, code):
    try:
        msg = Message('Eaton Portal - Verification Code',
                      sender='YOUR_EMAIL@gmail.com',
                      recipients=[email])
        msg.body = f'Your verification code is: {code}\n\nThis code expires in 10 minutes.'
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

# ========== AUTH ENDPOINTS ==========

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    # Check if user exists
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'error': 'Email already registered'}), 400
    
    # Hash password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Generate verification code
    code = str(random.randint(100000, 999999))
    verification_codes[email] = {'code': code, 'expires': datetime.datetime.now() + datetime.timedelta(minutes=10)}
    
    # Send email
    if send_verification_email(email, code):
        # Store user temporarily
        mongo.db.temp_users.insert_one({
            'email': email,
            'password': hashed,
            'created_at': datetime.datetime.now()
        })
        return jsonify({'message': 'Verification code sent to your email'})
    else:
        return jsonify({'error': 'Failed to send email'}), 500

@app.route('/api/verify-signup', methods=['POST'])
def verify_signup():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    
    # Verify code
    if email not in verification_codes:
        return jsonify({'error': 'No verification request found'}), 400
    
    stored = verification_codes[email]
    if stored['code'] != code:
        return jsonify({'error': 'Invalid code'}), 400
    
    if datetime.datetime.now() > stored['expires']:
        return jsonify({'error': 'Code expired'}), 400
    
    # Get temp user
    temp_user = mongo.db.temp_users.find_one({'email': email})
    if not temp_user:
        return jsonify({'error': 'User not found'}), 400
    
    # Create permanent user
    mongo.db.users.insert_one({
        'email': email,
        'password': temp_user['password'],
        'created_at': datetime.datetime.now()
    })
    
    # Clean up
    mongo.db.temp_users.delete_one({'email': email})
    del verification_codes[email]
    
    # Create token
    access_token = create_access_token(identity=email)
    return jsonify({'token': access_token, 'email': email})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401
    
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Generate and send verification code
    code = str(random.randint(100000, 999999))
    verification_codes[email] = {'code': code, 'expires': datetime.datetime.now() + datetime.timedelta(minutes=10)}
    
    if send_verification_email(email, code):
        return jsonify({'message': 'Verification code sent to your email'})
    else:
        return jsonify({'error': 'Failed to send email'}), 500

@app.route('/api/verify-login', methods=['POST'])
def verify_login():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    
    if email not in verification_codes:
        return jsonify({'error': 'No verification request found'}), 400
    
    stored = verification_codes[email]
    if stored['code'] != code:
        return jsonify({'error': 'Invalid code'}), 400
    
    if datetime.datetime.now() > stored['expires']:
        return jsonify({'error': 'Code expired'}), 400
    
    del verification_codes[email]
    
    access_token = create_access_token(identity=email)
    return jsonify({'token': access_token, 'email': email})

@app.route('/api/verify-token', methods=['POST'])
@jwt_required()
def verify_token():
    current_user = get_jwt_identity()
    return jsonify({'valid': True, 'email': current_user})

# ========== DEAL ENDPOINTS (Protected) ==========

@app.route('/api/deals', methods=['GET'])
@jwt_required()
def get_deals():
    current_user = get_jwt_identity()
    deals = list(mongo.db.deals.find({'user': current_user}))
    for deal in deals:
        deal['_id'] = str(deal['_id'])
    return jsonify(deals)

@app.route('/api/deals', methods=['POST'])
@jwt_required()
def add_deal():
    current_user = get_jwt_identity()
    data = request.json
    data['user'] = current_user
    result = mongo.db.deals.insert_one(data)
    return jsonify({'_id': str(result.inserted_id)})

@app.route('/api/deals/<deal_id>', methods=['PUT'])
@jwt_required()
def update_deal(deal_id):
    from bson.objectid import ObjectId
    current_user = get_jwt_identity()
    data = request.json
    mongo.db.deals.update_one(
        {'_id': ObjectId(deal_id), 'user': current_user},
        {'$set': data}
    )
    return jsonify({'message': 'Updated'})

@app.route('/api/deals/<deal_id>', methods=['DELETE'])
@jwt_required()
def delete_deal(deal_id):
    from bson.objectid import ObjectId
    current_user = get_jwt_identity()
    mongo.db.deals.delete_one({'_id': ObjectId(deal_id), 'user': current_user})
    return jsonify({'message': 'Deleted'})

@app.route('/api/upload/deal-reg', methods=['POST'])
@jwt_required()
def upload_deal_reg():
    current_user = get_jwt_identity()
    data = request.json.get('data', [])
    for row in data:
        mongo.db.deals.update_one(
            {'sku': row.get('sku'), 'user': current_user},
            {'$set': {**row, 'user': current_user}},
            upsert=True
        )
    return jsonify({'message': f'{len(data)} deals uploaded'})

@app.route('/api/upload/keepa', methods=['POST'])
@jwt_required()
def upload_keepa():
    current_user = get_jwt_identity()
    data = request.json.get('data', [])
    for row in data:
        mongo.db.deals.update_one(
            {'Asin': row.get('Asin'), 'user': current_user},
            {'$set': {
                'Rating': str(row.get('Ratings', '')),
                'BB': str(row.get('Buybox', '')),
                'Review': str(row.get('Reviews', '')),
                'user': current_user
            }}
        )
    return jsonify({'message': f'{len(data)} keepa records uploaded'})

@app.route('/api/upload/stock', methods=['POST'])
@jwt_required()
def upload_stock():
    current_user = get_jwt_identity()
    data = request.json.get('data', [])
    for row in data:
        disti = str(row.get('disti', '')).upper()
        sku = row.get('sku')
        quantity = str(row.get('quantity', '0'))
        
        field_map = {'IG': 'IG_Stock', 'SS': 'SS_Stock', 'DS': 'DS_Stock'}
        field = field_map.get(disti)
        
        if field and sku:
            mongo.db.deals.update_one(
                {'sku': sku, 'user': current_user},
                {'$set': {field: quantity}}
            )
    return jsonify({'message': f'{len(data)} stock updates processed'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)