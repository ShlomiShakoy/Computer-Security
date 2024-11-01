from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymysql
import hashlib
import hmac
import os
import bleach
from datetime import datetime
from flask_mail import Mail, Message
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import jsonify
import random
import string
import passwordRules
import mailtrap as mt
from passwordRules import parse_ini_file
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
load_dotenv()

#a global var which will be set after login passed
global_username=None
#a global hashed_key to be saved and get compared after hashed_key was sent to user's email
hashed_key=None
#global email to store email of user. when user asks for key, we have to remember his email for future changes in database when he wants to change password
global_email=None

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management and flashing messages

# Database connection details
db_config = {
    'user': 'root',
    'password': '123456',
    'host': 'localhost',
    'database': 'computersecurity'
}

def get_db_connection():
    return pymysql.connect(**db_config)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Establish a connection to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,)) #using parameters query
        user_exists = cursor.fetchone()[0] > 0 #fetch one and not fetch all since it's not-vulnerable

        if user_exists:
            flash('Username already exists. Please choose a different username.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('add_user'))

        # Query to check if the email already exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE email = %s', (email,))
        email_exists = cursor.fetchone()[0] > 0
        if email_exists:
            flash('Email already exists. Please choose a different email.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('add_user'))


        #check password is valid and fills all passwords requirements
        if not passwordRules.validate_password(password):
            message = (
                f"Password is invalid. Not fulfilling all requirements! "
                f"Password length={passwordRules.password_length}. "
                f"Complex password: {', '.join(map(str, passwordRules.complexed_password))}. "
                f"Forbidden words: {', '.join(passwordRules.dictionary)}."
            )
            flash(message, 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('add_user'))

        # Step 1: Generate a salt
        salt = os.urandom(16)  # 16 bytes of random salt

        # Step 2: Create HMAC hash using the salt and the password
        hashed_password = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()

        # Combine the salt and the hashed password for storage
        salt_and_hashed_password = f'{salt.hex()}${hashed_password}'


        # Insert the user into the `users` table
        cursor.execute('INSERT INTO users (username, password, email, salt) VALUES (%s, %s, %s, %s)',
                       (username, salt_and_hashed_password, email, salt))
        conn.commit()

        # Retrieve the `userid` of the newly inserted user
        userid = cursor.lastrowid

        # Insert the hashed password into the `passwords` table
        current_timestamp = datetime.now()
        cursor.execute(
            'INSERT INTO passwords (id, password, timeStamp) VALUES (%s, %s, %s)',
            (userid, salt_and_hashed_password, current_timestamp)
        )
        # login tries which starts with 0
        cursor.execute(
            'INSERT INTO logintries (id, loginCounter) VALUES (%s, %s)',
            (userid, 0)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash('User added successfully.','success')
        return redirect(url_for('home'))

    return render_template('add_user.html')

#recreate the hash using the stored salt and the provided password, then compare it to the stored hash
def verify_password(stored_hash, password):
    # Split the stored hash into the salt and the actual hash
    salt, actual_stored_hash = stored_hash.split('$')

    # Convert the salt back to bytes (if it was stored as hex)
    salt = bytes.fromhex(salt)

    # Generate the hash with the provided password and extracted salt
    generated_hash = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()

    # Compare the generated hash with the stored hash
    return generated_hash == actual_stored_hash


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        global global_username
        conn = get_db_connection()
        cursor = conn.cursor()

        #A query that retreives the password only from users table
        cursor.execute(
            'SELECT id, password FROM users WHERE username = %s;',
            (username,))
        #cursor.execute('SELECT password, salt FROM users WHERE username = %s', (username,))
        result = cursor.fetchone()
        # Check if the user exists
        if result:
            passwordFromDataBase = result[1]  # Getting the password from the database
            user_id = result[0]

            if verify_password(passwordFromDataBase, password):
                flash('Login successful!', 'success')
                # Store the user ID in the session
                session['user_id'] = user_id
                #save to global variable because it needs to be used in add_customer page as part of the query. Also, to enter username again is superfluous, therefore we store the var here
                global_username=username
                cursor.execute(
                    'UPDATE logintries SET loginCounter = %s WHERE id = %s',
                    (0, user_id)
                )
                conn.commit()  # Commit the transaction to save the update
                #if login successfully, we close the database connection
                cursor.close()
                conn.close()
                return redirect(url_for('add_customer'))
            else:
                #must retrieve the number of login tries in data base
                #check if user left with more tries
                #to change number of tries to login- index incrementation
               # session['user_id'] = user_id
                cursor.execute('SELECT loginCounter FROM logintries WHERE id = %s;', (user_id,))
                resultOfLoginCounter = cursor.fetchone()
                if resultOfLoginCounter:
                    # result[0] extracts the logincounter value
                    logincounter = resultOfLoginCounter[0] + 1
                    cursor.execute(
                        'UPDATE logintries SET loginCounter = %s WHERE id = %s',
                        (logincounter, user_id)
                    )
                    conn.commit()  # Commit the transaction to save the update
                    if logincounter>=passwordRules.login_tries:#to cover cases of user goes back to login page and tries to login again. if it's set to == it will go to the else statement
                        #must change the password in both tables-passwords and users and therefore we hash it and add random to make it encreyped
                        default_password = os.getenv('DEFAULT_PASSWORD')#from .env file
                        random_number = str(random.randint(1, 100000))#from .env file
                        default_password_concatenated=default_password+random_number
                        # Step 1: Generate a salt
                        salt = os.urandom(16)  # 16 bytes of random salt
                        # Step 2: Create HMAC hash using the salt and the password
                        hashed_password = hmac.new(salt, default_password_concatenated.encode(), hashlib.sha256).hexdigest()
                        # Combine the salt and the hashed password for storage
                        salt_and_hashed_password = f'{salt.hex()}${hashed_password}'
                        cursor.execute(
                            'UPDATE users SET password = %s WHERE id = %s',
                            (salt_and_hashed_password, user_id)
                        )
                        conn.commit()  # Commit the transaction to save the update

                        # Insert the hashed password into the `passwords` table
                        current_timestamp = datetime.now()
                        cursor.execute(
                            'INSERT INTO passwords (id, password, timeStamp) VALUES (%s, %s, %s)',
                            (user_id, salt_and_hashed_password, current_timestamp)
                        )
                        conn.commit()  # Commit the transaction to save the update
                        flash('Maximum login tries reached to its limit!! Account blocked!! reset your password using email!', 'danger')
                        return redirect(url_for('forgot_password'))
                    else:
                        flash('Invalid username or password. Pay attention, there are ' + str(
                            passwordRules.login_tries-logincounter) + ' login tries left!', 'danger')

                #if we have arrived to max login tries we must close database before:
                cursor.close()
                conn.close()
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        current_password=request.form['current_password']
        new_password = request.form['new_password']
        conn = get_db_connection()
        cursor = conn.cursor()
        global global_username#will use us for extracting the user_id from table
        if global_username==None:
            #should never arrive here!!!!
            flash('Login process was not done properly, please try again!', 'danger')
            return redirect(url_for('login'))
        # retreive the current passowrd of the user
        cursor.execute('SELECT password FROM users WHERE username = %s', (global_username,))
        result = cursor.fetchone()
        # verify the query committed successfully
        if result:
            passwordFromDataBase = result[0]  # Getting the password from the database
            #user_id = result[2]
            # verify the entered password is similar to the stored one
            if not verify_password(passwordFromDataBase, current_password):
                flash('Current Password is incorrect.', 'danger')
                return redirect(url_for('change_password'))

            #if we got here, it means the user enters the correct current password

        else: #should never arrive here!!! since query should be executed successfully
            flash('Could not change password, please try again!', 'danger')
            return redirect(url_for('change_password'))

        #a query that retreives the user_id
        cursor.execute('SELECT id FROM users WHERE username = %s', (global_username,))
        user_id = cursor.fetchone()

        # Check password history, order by DESC and limited to history from .ini file
        cursor.execute('SELECT password FROM passwords WHERE id = %s ORDER BY timeStamp DESC LIMIT %s;', (user_id, passwordRules.history))

        result = cursor.fetchall()
        if not result:
            flash('User name does not exist.', 'danger')
            return redirect(url_for('change_password'))
        else:

            # Iterate through the last X passwords
            print(result) #test- check output
            for item in result:#iterate through all user's last passwords
                password = item[0]
                if verify_password(password,
                                   new_password):  # Assuming verify_password checks if new_password matches the existing password
                    flash(f'This password was used in your last {passwordRules.history} passwords, try another one.',
                          'danger')
                    print(password)
                    return redirect(url_for('change_password'))

            # check if new password is valid and fills all passwords requirements
            if not passwordRules.validate_password(new_password):
                message = (
                            f"Password is invalid. Not fulfilling all requirements! "
                            f"Password length={passwordRules.password_length}. "
                            f"Complex password: {', '.join(map(str, passwordRules.complexed_password))}. "
                            f"Forbidden words: {', '.join(passwordRules.dictionary)}."
                            )
                flash(message, 'error')
                cursor.close()
                conn.close()
                return redirect(url_for('change_password'))

            # Step 1: Generate a salt
            salt = os.urandom(16)  # 16 bytes of random salt

            # Step 2: Create HMAC hash using the salt and the password
            hashed_password = hmac.new(salt, new_password.encode(), hashlib.sha256).hexdigest()

            # Combine the salt and the hashed password for storage
            salt_and_hashed_password = f'{salt.hex()}${hashed_password}'

            #update the password in passwords table where user_id=passwords.id
            # Execute the INSERT statement
            current_timestamp = datetime.now()
            cursor.execute(
                'INSERT INTO passwords (id, password, timeStamp) VALUES (%s, %s, %s);',
                (user_id, salt_and_hashed_password, current_timestamp))

            # Update the password in users table
            cursor.execute(
                'UPDATE users SET password = %s WHERE id = %s',
                (salt_and_hashed_password, user_id)
            )

            conn.commit()
            cursor.close()
            conn.close()

            flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('change_password.html')


@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        user_id = session['user_id']
        if 'delete_all_customers' in request.form:
            # Handle deleting all customers
            try:
                cursor.execute('DELETE FROM customers WHERE user_id = %s', (user_id,))
                conn.commit()
                flash('All customers have been deleted successfully.', 'success')
            except Exception as e:
                print(f"An error occurred: {e}")
                flash('An error occurred while deleting all customers. Please try again later.', 'error')
        else:
            # Handle adding a new customer
            customer_name = request.form['customer_name']
            if len(customer_name) >= 1:#input has at least one char
                try:
                    safe_input = bleach.clean(customer_name)
                    cursor.execute('INSERT INTO customers (customer_name, user_id) VALUES (%s, %s)',
                                   (safe_input, user_id,))
                    conn.commit()
                    flash('Customer ' + safe_input +" added successfully!", 'success')
                except Exception as e:
                    print(f"An error occurred: {e}")
                    flash('An error occurred while adding the customer. Please try again later.', 'error')
            else:
                flash('Customer name must be more than 1 character long.', 'warning')
            return redirect(url_for('add_customer'))
    # display all current customers of the current user
    try:
        # Execute a query to get the user ID first and then retrieve the current customers by the user ID
        global global_username
        cursor.execute('SELECT id FROM users WHERE username = %s', (global_username,))
        user_id = cursor.fetchone()
        cursor.execute('SELECT customer_name FROM customers WHERE user_id = %s', (user_id,))
        customers = cursor.fetchall()
    except Exception as e:
        print(f"An error occurred: {e}")
        flash('An error occurred while retrieving customers. Please try again later.', 'error')
        customers = []

    cursor.close()
    conn.close()

    return render_template('add_customer.html', customers=customers)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()
        #write a query to verify user's email exists
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        # Close the database connection
        cursor.close()
        conn.close()
        #check if email doesn't exist then return the same page and a suitable message
        if not user:
            flash('Email does not exist. Please sign up.', 'error')
            return redirect(url_for('forgot_password'))

        key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        # Hash the key using SHA-1
        global hashed_key #store the hashed key as global since we have to verify it in verify key page
        hashed_key = hashlib.sha1(key.encode()).hexdigest()

        # Store the key in the session
        session['reset_key'] = key
        session['email'] = email

        # Send the key via email
        try:
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            msg = MIMEText('Your secret key is: ' + hashed_key)
            msg['Subject'] = "Secret key request for changing password"
            msg['From'] = os.getenv('MAIL_USERNAME')
            msg['To'] = email
            global global_email
            global_email=email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(msg['From'], os.getenv('MAIL_TOKEN'))
            server.send_message(msg)
            server.quit()

            flash('A reset key has been sent to your email address.', 'success')
            return redirect(url_for('verify_key'))
        except Exception as e:
            print(f"An error occurred: {e}")
            flash('An error occurred while sending the email. Please try again later.', 'error')

        flash('A reset key has been sent to your email address.', 'success')
        return redirect(url_for('verify_key'))

    return render_template('forgot_password.html')


@app.route('/verify_key', methods=['GET', 'POST'])
def verify_key():
    if request.method == 'POST':
        global hashed_key
        key = request.form['key']#get the user's input key
        stored_key = hashed_key #assign the hsahed_key that was sent on email to the user

        if key == stored_key:#if user entered the correct key that was sent to him on email
            return redirect(url_for('change_password_after_verify_key'))
        else:
            flash('Invalid key. Please try again.', 'error')
            return redirect(url_for('verify_key'))

    return render_template('verify_key.html')


@app.route('/change_password_after_verify_key', methods=['GET', 'POST'])
def change_password_after_verify_key():
    if request.method == 'POST':
        new_password = request.form['new_password_after_verify_key']
        global global_email
        if global_email==None:
            #should never arrive here!!!!
            flash('Verify key process was not done properly, please try again!', 'danger')
            return redirect(url_for('home'))

        # continue process
        conn = get_db_connection()
        cursor = conn.cursor()
        # execute a query to get the user ID based on the email to work with the existed functions in change_password and committing the least possible changes
        cursor.execute('SELECT id FROM users WHERE email = %s', (global_email,))
        user = cursor.fetchone()

        #if user id found
        if user:
            user_id = user[0]  # Extract the ID from the result

            # Check password history
            cursor.execute('SELECT password FROM passwords WHERE id = %s ORDER BY timeStamp DESC LIMIT %s;',
                           (user_id, passwordRules.history))

            result = cursor.fetchall()
            if not result:
                flash('User name does not exist.', 'danger')
                return redirect(url_for('change_password_after_verify_key'))
            else:

                # Iterate through the last X passwords
                print(result)  # test- check output
                for item in result:  #iterate through all last x password (check history)
                    password = item[0]
                    if verify_password(password,
                                       new_password):  # Assuming verify_password checks if new_password matches the existing password
                        flash(
                            f'This password was used in your last {passwordRules.history} passwords, try another one.',
                            'danger')
                        print(password)
                        return redirect(url_for('change_password_after_verify_key'))

                # check if new password is valid and fills all passwords requirements
                if not passwordRules.validate_password(new_password):
                    message = (
                        f"Password is invalid. Not fulfilling all requirements! "
                        f"Password length={passwordRules.password_length}. "
                        f"Complex password: {', '.join(map(str, passwordRules.complexed_password))}. "
                        f"Forbidden words: {', '.join(passwordRules.dictionary)}."
                    )
                    flash(message, 'error')
                    cursor.close()
                    conn.close()
                    return redirect(url_for('change_password_after_verify_key'))
                #if entered password was done successfully
                # Step 1: Generate a salt
                salt = os.urandom(16)  # 16 bytes of random salt

                # Step 2: Create HMAC hash using the salt and the password
                hashed_password = hmac.new(salt, new_password.encode(), hashlib.sha256).hexdigest()

                # Combine the salt and the hashed password for storage
                salt_and_hashed_password = f'{salt.hex()}${hashed_password}'

                # Execute the INSERT statement
                current_timestamp = datetime.now()
                cursor.execute('INSERT INTO passwords (id, password, timeStamp) VALUES (%s, %s, %s);',
                    (user_id, salt_and_hashed_password, current_timestamp))

                # Update the password in users table
                cursor.execute(
                    'UPDATE users SET password = %s WHERE id = %s',
                    (salt_and_hashed_password, user_id)
                )
                #reset the loginCounter to be 0 since user successfully updated his password
                cursor.execute(
                    'UPDATE logintries SET loginCounter = %s WHERE id = %s',
                    (0, user_id)
                )

                conn.commit()
                cursor.close()
                conn.close()

                flash('Password updated successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error! Should never arrive here', 'danger')
            return redirect(url_for('change_password_after_verify_key'))
        return redirect(url_for('change_password_after_verify_key'))

    return render_template('change_password_after_verify_key.html')



if __name__ == '__main__':
    app.run(debug=True)
