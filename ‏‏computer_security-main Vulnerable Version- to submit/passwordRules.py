import os
import re

smallLetter=r'[a-z]'
capitalLetter=r'[A-Z]'
digit=r'[0-9]'
special=r'[!@#$%^&*()_+={}\[\]|\\:;\"\'<>,.?/]'

#a function that initializes the parameters of the ini file
def parse_ini_file():
    passwordLength: int = None
    complexedPassword: list = None
    history: int = None
    dictionary: list = None
    loginTries: int = None

    ini_file_path = "PasswordRules.ini"

    with open(ini_file_path, 'r') as file:
        for line in file:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == "passwordLength":
                    passwordLength = int(value)
                elif key == "complexedPassword":
                    complexedPassword = value[1:-1].split(',')
                    complexedPassword = [item.strip() for item in complexedPassword]
                elif key == "history":
                    history = int(value)
                elif key == "dictionary":
                    dictionary = value[1:-1].split(',')
                    dictionary = [item.strip().strip('"') for item in dictionary]
                elif key == "loginTries":
                    loginTries = int(value)

    return passwordLength, complexedPassword, history, dictionary, loginTries


# Example usage:
password_length, complexed_password, history, dictionary, login_tries = parse_ini_file()

print("Password Length:", password_length)
print("Complexed Password:", complexed_password)
print("History:", history)
print("Dictionary:", dictionary)
print("Login Tries:", login_tries)

def contains_special(password):
    # Use re.search to check if there is at least one special letter
    return bool(re.search(special, password))

def contains_digit(password):
    # Use re.search to check if there is at least one digit letter
    return bool(re.search(digit, password))

def contains_capital_letter(password):
    # Use re.search to check if there is at least one capital letter
    return bool(re.search(capitalLetter, password))

def contains_small_letter(password):
    # Use re.search to check if there is at least one lowercase letter
    return bool(re.search(smallLetter, password))

# function that verify the entered passwords fill the required conditions
def validate_password(password):
    # Check if the password length is at least password_length
    if len(password) < password_length:
        return False
    #check if the password appears in the dictionary (banned words) including lower cases
    if any(word.lower() in password.lower() for word in dictionary):
        return False
    #in case the complex password in .ini file contains smallLetter, capitalLetter, digit, special we call the function that checks if it fills the condition.
    #if it returns false, we return false. otherwise we continue checking
    if 'smallLetter' in complexed_password:
        if contains_small_letter(password)==False:
            return False
        if 'capitalLetter' in complexed_password:
            if contains_capital_letter(password) == False:
                return False
        if 'digit' in complexed_password:
            if contains_digit(password)==False:
                return False
        if 'special' in complexed_password:
            if contains_special(password)==False:
                return False
    return True






