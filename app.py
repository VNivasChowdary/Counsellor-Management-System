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
    return render_template('login.html')

@app.route('/login')
def login():    
    return render_template('login.html')


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
                name = items[0]['username']
                session['name'] = name
                return redirect(url_for('index'))
        return render_template("login.html")
    return render_template("login.html")



def get_user_details_definition():
    response = user_details_definition_table.scan()
    return response['Items'][0]


def get_user_details(name):
    response = user_details_table.query(
        KeyConditionExpression=Key('username').eq(name)
    )
    return response['Items'][0] if response['Items'] else None

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
        print(missing_attributes)
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
        print("________")
        return render_template("upload.html")

    
from flask import session

def create_user_accounts_from_excel(file_path):
    print("___________________________________________")
    try:
        df = pd.read_excel(file_path, header=None, names=['Name', 'Email', 'Password'])
        for index, row in df.iterrows():
            name = row['Name']
            email = row['Email']
            password = row['Password']
            
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
            
            user_table.put_item(
                Item={
                    'username': name,
                    'email': email,
                    'password': hashed_password,
                    'role': 'student'  # Assume all users created from Excel are students
                }
            )
            print(f"User account created for {name} ({email}) as a student")

            # Retrieve the username of the currently logged-in counselor
            counselor_id = session.get('name')

            # Link the student to the counselor by storing the counselor's ID in the student's record
            user_table.update_item(
                Key={'username': name},
                UpdateExpression='SET counselor_id = :counselor_id',
                ExpressionAttributeValues={':counselor_id': counselor_id}
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
            if user_details:
                return render_template('student_dashboard.html', user_details=user_details)
            else:
                return render_template('error.html', message='User details not found.')
        elif user_role == 'counselor':
            # Render counselor dashboard
            return render_template('counselor_dashboard.html')
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
                updated_details = {}
                for attribute in user_details_definition_table['attributes']:
                    updated_details[attribute] = request.form.get(attribute)

                # Update the user_details_table with the submitted data
                response = user_details_table.update_item(
                    Key={'username': username},
                    UpdateExpression='SET ' + ', '.join([f"{key} = :val{i}" for i, key in enumerate(updated_details.keys())]),
                    ExpressionAttributeValues={f":val{i}": val for i, val in enumerate(updated_details.values())}
                )
                return redirect(url_for('user_dashboard'))
            except Exception as e:
                return render_template('error.html', message=str(e))
        else:
            return render_template('error.html', message="User details not found.")
    return redirect(url_for('login'))



if __name__ == "__main__":
    app.run(debug=True)
