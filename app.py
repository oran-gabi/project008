from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

# Initialize the Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'media')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max file size

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5500"}}, supports_credentials=True)

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if a file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Define the models
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    genre = db.Column(db.String(50))
    published_date = db.Column(db.String(20))
    total_copies = db.Column(db.Integer, nullable=False)
    available_copies = db.Column(db.Integer, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(255))

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20))
    email = db.Column(db.String(100))
    address = db.Column(db.String(200))
    is_deleted = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('customer', uselist=False))

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    loan_date = db.Column(db.String(20))
    return_date = db.Column(db.String(20))
    due_date = db.Column(db.String(20))
    returned = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Helper method to convert model instances to dictionary
def as_dict(self):
    return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# Add as_dict method to models
Book.as_dict = as_dict
Customer.as_dict = as_dict
Loan.as_dict = as_dict
User.as_dict = as_dict

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'customer')

    if User.query.filter_by(username=username).first():
        return jsonify(message="Username already exists"), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    if role == 'customer':
        new_customer = Customer(
            user_id=new_user.id,
            name=data.get('name'),
            phone_number=data.get('phone_number'),
            email=data.get('email'),
            address=data.get('address')
        )
        db.session.add(new_customer)
        db.session.commit()

    return jsonify(message="User registered successfully"), 201

# Registration endpoint for admin
@app.route('/register_admin', methods=['POST'])
def register_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify(message="Username already exists"), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role='admin')
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message="Admin registered successfully"), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify(message="Invalid credentials"), 401

    access_token = create_access_token(identity={'username': user.username, 'role': user.role})
    return jsonify(access_token=access_token)

# Role-based access control decorator
def role_required(role):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt_identity()
            if claims['role'] != role:
                return jsonify(message="You are not authorized to access this resource"), 403
            return fn(*args, **kwargs)
        decorator.__name__ = fn.__name__
        return decorator
    return wrapper

# CRUD operations for Books
@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    books = Book.query.filter_by(is_deleted=False).all()
    return jsonify([book.as_dict() for book in books])

@app.route('/books/<int:id>', methods=['GET'])
@jwt_required()
def get_book(id):
    book = Book.query.get_or_404(id)
    if book.is_deleted:
        return jsonify(error="Book not found"), 404
    return jsonify(book.as_dict())

@app.route('/books', methods=['POST'])
@role_required('admin')
def add_book():
    data = request.get_json()

    # Validate request data
    required_fields = ['title', 'author', 'total_copies', 'available_copies']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify(message=f"'{field}' is required and cannot be empty"), 422

    try:
        total_copies = int(data['total_copies'])
        available_copies = int(data['available_copies'])
    except ValueError:
        return jsonify(message="'total_copies' and 'available_copies' must be integers"), 422

    new_book = Book(
        title=data['title'],
        author=data['author'],
        genre=data.get('genre'),
        published_date=data.get('published_date'),
        total_copies=total_copies,
        available_copies=available_copies
    )
    db.session.add(new_book)
    db.session.commit()

    return jsonify(message="Book added successfully"), 201

@app.route('/books/<int:id>', methods=['PUT'])
@role_required('admin')
def update_book(id):
    book = Book.query.get_or_404(id)
    if book.is_deleted:
        return jsonify(error="Book not found"), 404

    data = request.get_json()
    book.title = data.get('title', book.title)
    book.author = data.get('author', book.author)
    book.genre = data.get('genre', book.genre)
    book.published_date = data.get('published_date', book.published_date)
    book.total_copies = data.get('total_copies', book.total_copies)
    book.available_copies = data.get('available_copies', book.available_copies)

    db.session.commit()
    return jsonify(message="Book updated successfully")

@app.route('/books/<int:id>', methods=['DELETE'])
@role_required('admin')
def delete_book(id):
    book = Book.query.get_or_404(id)
    if book.is_deleted:
        return jsonify(error="Book not found"), 404

    book.is_deleted = True
    db.session.commit()
    return jsonify(message="Book deleted successfully")

# CRUD operations for Customers
@app.route('/customers', methods=['GET'])
@role_required('admin')
def get_customers():
    customers = Customer.query.filter_by(is_deleted=False).all()
    return jsonify([customer.as_dict() for customer in customers])

@app.route('/customers/<int:id>', methods=['GET'])
@jwt_required()
def get_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.is_deleted:
        return jsonify(error="Customer not found"), 404
    return jsonify(customer.as_dict())

@app.route('/customers', methods=['POST'])
@role_required('admin')
def add_customer():
    data = request.get_json()

    # Validate request data
    required_fields = ['name', 'user_id']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify(message=f"'{field}' is required and cannot be empty"), 422

    new_customer = Customer(
        user_id=data['user_id'],
        name=data['name'],
        phone_number=data.get('phone_number'),
        email=data.get('email'),
        address=data.get('address')
    )
    db.session.add(new_customer)
    db.session.commit()

    return jsonify(message="Customer added successfully"), 201

@app.route('/customers/<int:id>', methods=['PUT'])
@role_required('admin')
def update_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.is_deleted:
        return jsonify(error="Customer not found"), 404

    data = request.get_json()
    customer.name = data.get('name', customer.name)
    customer.phone_number = data.get('phone_number', customer.phone_number)
    customer.email = data.get('email', customer.email)
    customer.address = data.get('address', customer.address)

    db.session.commit()
    return jsonify(message="Customer updated successfully")

@app.route('/customers/<int:id>', methods=['DELETE'])
@role_required('admin')
def delete_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.is_deleted:
        return jsonify(error="Customer not found"), 404

    customer.is_deleted = True
    db.session.commit()
    return jsonify(message="Customer deleted successfully")

# CRUD operations for Loans
@app.route('/loans', methods=['GET'])
@jwt_required()
def get_loans():
    loans = Loan.query.filter_by(is_deleted=False).all()
    return jsonify([loan.as_dict() for loan in loans])

@app.route('/loans/<int:id>', methods=['GET'])
@jwt_required()
def get_loan(id):
    loan = Loan.query.get_or_404(id)
    if loan.is_deleted:
        return jsonify(error="Loan not found"), 404
    return jsonify(loan.as_dict())

@app.route('/loans', methods=['POST'])
@jwt_required()
def add_loan():
    data = request.get_json()

    # Validate request data
    required_fields = ['book_id', 'customer_id', 'loan_date', 'due_date']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify(message=f"'{field}' is required and cannot be empty"), 422

    new_loan = Loan(
        book_id=data['book_id'],
        customer_id=data['customer_id'],
        loan_date=data['loan_date'],
        due_date=data['due_date']
    )
    db.session.add(new_loan)
    db.session.commit()

    return jsonify(message="Loan added successfully"), 201

@app.route('/loans/<int:id>', methods=['PUT'])
@jwt_required()
def update_loan(id):
    loan = Loan.query.get_or_404(id)
    if loan.is_deleted:
        return jsonify(error="Loan not found"), 404

    data = request.get_json()
    loan.book_id = data.get('book_id', loan.book_id)
    loan.customer_id = data.get('customer_id', loan.customer_id)
    loan.loan_date = data.get('loan_date', loan.loan_date)
    loan.return_date = data.get('return_date', loan.return_date)
    loan.due_date = data.get('due_date', loan.due_date)
    loan.returned = data.get('returned', loan.returned)

    db.session.commit()
    return jsonify(message="Loan updated successfully")

@app.route('/loans/<int:id>', methods=['DELETE'])
@role_required('admin')
def delete_loan(id):
    loan = Loan.query.get_or_404(id)
    if loan.is_deleted:
        return jsonify(error="Loan not found"), 404

    loan.is_deleted = True
    db.session.commit()
    return jsonify(message="Loan deleted successfully")

# Return a book
@app.route('/loans/<int:id>/return', methods=['PUT'])
@jwt_required()
def return_book(id):
    loan = Loan.query.get_or_404(id)
    if loan.is_deleted:
        return jsonify(error="Loan not found"), 404

    data = request.get_json()
    loan.return_date = data.get('return_date', loan.return_date)
    loan.returned = True

    # Update the availability of the book
    book = Book.query.get(loan.book_id)
    if book:
        book.available_copies += 1

    db.session.commit()
    return jsonify(message="Book returned successfully")

# Upload an image for a book
@app.route('/upload/<int:book_id>', methods=['POST'])
@role_required('admin')
def upload_image(book_id):
    if 'file' not in request.files:
        return jsonify(message="No file part"), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify(message="No selected file"), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        book = Book.query.get_or_404(book_id)
        book.image_filename = filename
        db.session.commit()

        return jsonify(message="Image uploaded successfully", filename=filename), 201
    return jsonify(message="File not allowed"), 400

# Serve uploaded images
@app.route('/media/<filename>')
def serve_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Main block to run the app
if __name__ == '__main__':
    app.run(debug=True)
