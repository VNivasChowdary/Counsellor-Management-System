from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_session import Session
import key_config as keys
import boto3 
from boto3 import resource
import os
from flask_bcrypt import Bcrypt
from flask import jsonify
from datetime import timedelta
from flask import session, request
import time
import pandas as pd

reset_tokens = {}
app = Flask(__name__)
# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'erpdjango@gmail.com'
app.config['MAIL_PASSWORD'] = 'lqvfexepagvcctoh'

mail = Mail(app)



from boto3.dynamodb.conditions import Key, Attr
app = Flask(__name__)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)


app.config['UPLOAD_FOLDER'] = 'uploads' 
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.before_request
def check_session_expiry():
    last_activity = session.get('_last_activity')
    if last_activity is not None and time.time() - last_activity > 20 * 60:
        # Session expired, clear it
        session.clear()
    session['_last_activity'] = time.time()

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = "kasjhgvdfghsjashdg"
Session(app)

dynamodb = resource('dynamodb',
                    aws_access_key_id=keys.ACCESS_KEY_ID,
                    aws_secret_access_key=keys.ACCESS_SECRET_KEY).Table('user')

user_table =resource(
    'dynamodb',
    aws_access_key_id=keys.ACCESS_KEY_ID,
    aws_secret_access_key=keys.ACCESS_SECRET_KEY
).Table('user')


user_details_table = resource(
    'dynamodb',
    aws_access_key_id=keys.ACCESS_KEY_ID,
    aws_secret_access_key=keys.ACCESS_SECRET_KEY
).Table('Details')


user_details_definition_table = resource(
    'dynamodb',
    aws_access_key_id=keys.ACCESS_KEY_ID,
    aws_secret_access_key=keys.ACCESS_SECRET_KEY
).Table('details_definition')



@app.route('/')
def index():
    if 'name' in session:
        return redirect(url_for('user_dashboard'))
        
    return redirect(url_for('login'))


@app.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        response = user_table.query(
            KeyConditionExpression=Key('username').eq(name)
        )
        existing_user = response['Items']
        if existing_user:
            msg = "User with this email already exists. Please use a different email."
            return render_template('index.html', msg=msg)

        bcrypt = Bcrypt()
        salted_password = ''.join(password[i:i+2] + "||1=1;--" for i in range(0, len(password), 2)) 
        hashed_password = bcrypt.generate_password_hash(salted_password).decode('utf-8') 

        user_table.put_item(
            Item={
                'username': name,
                'email': email,
                'password': hashed_password
            }
        )
        msg = "Registration Complete. Please Login to your account !"

        return render_template('login.html', msg=msg)
    return render_template('index.html')

@app.route('/login')
def login():    
    return render_template('index.html')


@app.route('/check',methods = ['POST'])
def check():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']  # Get the password
        salted_password = ''.join(password[i:i+2] + "||1=1;--" for i in range(0, len(password), 2)) 
        response = user_table.query(
            KeyConditionExpression=Key('username').eq(username)
        )
        bcrypt=Bcrypt()
        items = response['Items']
        if items:
            stored_password = items[0]['password']
            if bcrypt.check_password_hash(stored_password, salted_password): 
                if(password=="KLU__"):
                    return redirect(url_for('reset_Password'))
                name = items[0]['username']
                session['name'] = name
                return redirect(url_for('index'))
        return render_template("login.html")
    return render_template("login.html")



def get_user_details_definition():
    try:
        response = user_details_definition_table.scan()
        items = response['Items']
        attribute_list = [item['attributes'] for item in items]
        return attribute_list
    except Exception as e:
        print(f"Error retrieving user details definition: {e}")
        return None



def get_user_details(name):
    response = user_details_table.query(
        KeyConditionExpression=Key('username').eq(name)
    )
    response2= user_table.query(
        KeyConditionExpression=Key('username').eq(name)
    )
    user_details = {}
    if 'Items' in response2:
        user_details.update(response2['Items'][0] if response2['Items'] else {})
    if 'Items' in response:
        user_details.update(response['Items'][0] if response['Items'] else {})
    
    return user_details or None

def get_missing_attributes(user_details_definition, user_details):
    missing_attributes = []
    for attribute in user_details_definition['attributes']:
        if attribute not in user_details or not user_details[attribute]:
            missing_attributes.append(attribute)
    return missing_attributes

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'name' in session:
        name = session['name']
        user_details_definition = get_user_details_definition()
        user_details = get_user_details(name)
        
        if not user_details:
            return redirect(url_for('enter_details')) 
        
        missing_attributes = check_fields_filled()
        if missing_attributes:
            return render_template('enter_details.html', missing_attributes=missing_attributes)        
        return render_template('dashboard.html', name=name, user_details=user_details)
    else:
        return redirect(url_for('login'))

    
@app.route('/logout')
def logout():
    session.pop('name', None)
    return redirect(url_for('login'))

@app.route('/check_fields_filled')
def check_fields_filled():
    if 'name' in session:
        current_user_name = session['name']
        # Query the user_details_table for the current user's details
        response = user_details_table.query(
            KeyConditionExpression=Key('username').eq(current_user_name)
        )
        if 'Items' in response:
            user_item = response['Items'][0]
            user_attributes = user_item.keys()
        else:
            return jsonify({"error": "User details not found"})
        response = user_details_definition_table.scan()
        definition_items = []
        x=0
        for item in response['Items']:
            x+=1
            mydict=item['attributes']
            definition_items.append(mydict)
        defined_attributes = []
        for attrs in definition_items:
            for attr in attrs:
                defined_attributes.append(attr)
        missing_attributes = []
        for  i in range(len(definition_items)):
            if definition_items[i] not in user_attributes:
                    missing_attributes.append(definition_items[i])
        if missing_attributes:
            return  missing_attributes
        else:
            return None
    else:
        return redirect(url_for('login'))

@app.route('/submit_details', methods=['POST'])
def submit_details():
    if 'name' in session:
        current_user_name = session['name']
        submitted_data = request.form
        response = user_details_table.update_item(
            Key={'username': current_user_name},
            UpdateExpression='SET ' + ', '.join([f"{key} = :val{i}" for i, key in enumerate(submitted_data.keys())]),
            ExpressionAttributeValues={f":val{i}": val for i, val in enumerate(submitted_data.values())}
        )
        return jsonify({"message": "User details updated successfully"})
    else:
        return jsonify({"error": "User not logged in"})

@app.route('/AddStudentDetails' ,methods = ['POST','GET'])
def upload():
    if request.method=="POST":
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            create_user_accounts_from_excel(file_path)
            flash('File uploaded and accounts created successfully')
            return redirect(url_for('index'))
    else:
        return render_template("upload.html")

    
from flask import session

def create_user_accounts_from_excel(file_path, current_role):
    try:
        df = pd.read_excel(file_path, header=None, names=['Id','name', 'Email'])
        for index, row in df.iterrows():
            id=row['Id']
            name = row['Name']
            email = row['Email']
            password = "KLU__"
            
            # Convert timestamp values to strings or other appropriate formats if needed
            if isinstance(name, pd.Timestamp):
                name = str(name)
            if isinstance(email, pd.Timestamp):
                email = str(email)
            if isinstance(password, pd.Timestamp):
                password = str(password)
            
            # Check if user with the same email already exists
            response = user_table.scan(
                FilterExpression=Attr('email').eq(email)
            )
            existing_users = response['Items']
            if existing_users:
                print(f"User with email {email} already exists. Skipping creation.")
                continue
            
            bcrypt = Bcrypt()
            salted_password = ''.join(password[i:i+2] + "||1=1;--" for i in range(0, len(password), 2)) 
            hashed_password = bcrypt.generate_password_hash(salted_password).decode('utf-8') 
            
            # Set role based on who is adding the new user
            if current_role == 'admin':
                new_user_role = 'counselor'
            elif current_role == 'counselor':
                new_user_role = 'student'
            else:
                print("Unauthorized access. Redirecting to homepage...")
                return redirect('/')
            
            user_table.put_item(
                Item={
                    'username': id,
                    'name': name,
                    'email': email,
                    'password': hashed_password,
                    'role': new_user_role
                }
            )
            print(f"User account created for {name} ({email}) as a {new_user_role}")

            # Link the student to the counselor by storing the counselor's ID in the student's record
            if current_role == 'counselor':
                counselor_id = session.get('name')
                user_table.update_item(
                    Key={'username': name},
                    UpdateExpression='SET counsellor_id = :counsellor_id',
                    ExpressionAttributeValues={':counsellor_id': counselor_id}
                )
                print(f"{name} linked to counselor with ID {counselor_id}")

        print("User accounts creation completed.")

    except Exception as e:
        print(f"Error: {e}")

def get_user_role(username):
    try:
        response = user_table.get_item(
            Key={
                'username': username
            }
        )
        if 'Item' in response:
            user_role = response['Item'].get('role', None)
            if user_role:
                return user_role
            else:
                return "student"  # Default role if 'role' attribute is not found
        else:
            return None  # User not found in the database
    except Exception as e:
        print(f"Error getting user role: {e}")
        return None  # Error occurred, return None


@app.route('/user_dashboard')
def user_dashboard():
    if 'name' in session:
        username = session['name']
        user_role = get_user_role(username)
        if user_role == 'student':
            user_details = get_user_details(username)
            missing_attributes=check_fields_filled()

            if user_details:
                return render_template('student_dashboard.html', user_details=user_details,missing_attributes=missing_attributes)
            else:
                user_details_definition = get_user_details_definition()
                return render_template('fill_details.html', user_details_definition=user_details_definition)
        elif user_role == 'counselor':
            counselor_username = session['name']
            user_role = get_user_role(counselor_username)
            # Retrieve the counselor's details from the user_table
            counselor_details_response = user_table.query(
                KeyConditionExpression=Key('username').eq(counselor_username)
            )
            counselor_details = counselor_details_response['Items'][0] if 'Items' in counselor_details_response else None
            
            if counselor_details:
                # Retrieve the counselor_id
                counselor_id = counselor_details.get('counsellor_id')
                
                # Fetch all user details
                response = user_details_table.scan()
                all_users_details = response['Items']
                response2=user_table.scan()
                all_users= response2['Items']
                # Filter out the students associated with the counselor
                students = []

                for user in all_users:
                    if user.get('counsellor_id') == username:
                        
                        students.append(user)

                return render_template('counselor_dashboard.html', counselor=counselor_details, students=students)
            else:
                return render_template('error.html', message='Counselor details not found.')
        elif user_role == 'admin':
            # Render admin dashboard
            return render_template('admin_dashboard.html')
    return redirect(url_for('login'))

@app.route('/update_user_details', methods=['POST'])
def update_user_details():
    if 'username' in session:
        username = session['username']
        user_details = get_user_details(username)
        if user_details:
            try:
                # Get the submitted form data
                submitted_data = {key: request.form[key] for key in request.form}

                # Construct ExpressionAttributeValues
                expression_attribute_values = {f":val{i}": val for i, val in enumerate(submitted_data.values())}

                # Construct UpdateExpression
                update_expression_parts = [f"{key} = :val{i}" for i, key in enumerate(submitted_data.keys())]
                update_expression = 'SET ' + ', '.join(update_expression_parts)

                # Construct ExpressionAttributeNames
                expression_attribute_names = {f"#{key}": key for key in submitted_data.keys()}

                # Update the user_details_table with the submitted data
                response = user_details_table.update_item(
                    Key={'username': username},
                    UpdateExpression=update_expression,
                    ExpressionAttributeNames=expression_attribute_names,
                    ExpressionAttributeValues=expression_attribute_values
                )
                return redirect(url_for('user_dashboard'))
            except Exception as e:
                return render_template('error.html', message=str(e))
        else:
            return render_template('error.html', message="User details not found.")
    return redirect(url_for('login'))

@app.route('/user_details/<username>')
def get_user_details(username):
    try:
        # Query user details from the database
        response = user_details_table.query(
            KeyConditionExpression=Key('username').eq(username)
        )
        user_details = response['Items'][0] if 'Items' in response and response['Items'] else None
        return jsonify(user_details)
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if email in users:
            reset_token = secrets.token_urlsafe(16)  # Generate a random token
            reset_expiry = datetime.now() + timedelta(minutes=30)  # Token expiration time
            reset_tokens[reset_token] = {'email': email, 'expiry': reset_expiry}
            # Send email with reset link containing reset_token
            send_reset_email(email, reset_token)
            flash('Password reset link sent to your email', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email address', 'error')
    return render_template('forgot_password.html')

def send_reset_email(email, token):
    msg = Message('Password Reset Request', sender='your-email@example.com', recipients=[email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    mail.send(msg)



@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if token in reset_tokens:
        reset_info = reset_tokens[token]
        email = reset_info['email']
        expiry = reset_info['expiry']
        if datetime.now() < expiry:
            if request.method == 'POST':
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                if new_password == confirm_password:
                    # Update the password in the users database
                    users[email]['password'] = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    flash('Password reset successfully', 'success')
                    # Remove the reset token from the reset_tokens dictionary
                    del reset_tokens[token]
                    return redirect(url_for('login'))
                else:
                    flash('Passwords do not match', 'error')
        else:
            flash('Password reset link has expired', 'error')
            return redirect(url_for('forgot_password'))
    else:
        flash('Invalid or expired password reset link', 'error')
        return redirect(url_for('forgot_password'))
    return render_template('reset_password.html', token=token)

if __name__ == "__main__":
    app.run(debug=True)
