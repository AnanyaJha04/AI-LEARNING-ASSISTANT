import hashlib
import secrets
import random

class AuthenticationTool:
    def __init__(self):
        self.users = {}
        self.security_questions = {
            "pet": "What was your first pet's name?",
            "fruit": "What is your favorite fruit?",
            "color": "What is your favorite color?",
            "city": "In what city were you born?"
        }
        self.authenticated_users = set() # To track users authenticated in the first stage

    def generate_salt(self):
        return secrets.token_hex(16)

    def hash_password(self, password, salt):
        salted_password = salt.encode('utf-8') + password.encode('utf-8')
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        return hashed_password

    def register_user(self, name, designation, password, security_question, security_answer):
        if name in self.users and self.users[name]['designation'] == designation:
            return "User with this name and designation already exists."
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        self.users[name] = {
            'designation': designation,
            'salt': salt,
            'hashed_password': hashed_password,
            'security_question': security_question,
            'security_answer_hash': self.hash_password(security_answer.lower(), salt)
        }
        return "Registration successful."

    def verify_password(self, name, designation, password):
        if name not in self.users or self.users[name]['designation'] != designation:
            return False, "Invalid name or designation."

        user_data = self.users[name]
        salt = user_data['salt']
        hashed_attempt = self.hash_password(password, salt)

        if hashed_attempt == user_data['hashed_password']:
            return True, "Password authentication successful."
        else:
            return False, "Incorrect password."

    def verify_security_answer(self, name, designation, security_answer):
        if name not in self.users or self.users[name]['designation'] != designation:
            return False, "Invalid name or designation."

        user_data = self.users[name]
        hashed_answer_attempt = self.hash_password(security_answer.lower(), user_data['salt'])

        if hashed_answer_attempt == user_data['security_answer_hash']:
            return True, "Security question authentication successful."
        else:
            return False, "Incorrect security answer."

def registration_process(auth_tool):
    print("\n--- Registration ---")
    name = input("Enter your name: ")
    designation = input("Enter your designation (student/teacher): ").lower()
    password = input("Enter your password: ")

    question_key, question_text = random.choice(list(auth_tool.security_questions.items()))
    print(f"Security Question: {question_text}")
    security_answer = input("Your answer: ")

    result = auth_tool.register_user(name, designation, password, question_key, security_answer)
    print(result)
    return name, designation

def first_login(auth_tool):
    print("\n--- First Login Attempt (Password) ---")
    name = input("Enter your name: ")
    designation = input("Enter your designation (student/teacher): ").lower()
    password = input("Enter your password: ")

    success, message = auth_tool.verify_password(name, designation, password)
    print(message)
    if success:
        auth_tool.authenticated_users.add((name, designation))
        return True, name, designation
    else:
        return False, None, None

def second_login(auth_tool, name, designation):
    print("\n--- Second Login Attempt (Security Question) ---")
    if (name, designation) not in auth_tool.authenticated_users:
        print("You need to successfully complete the first login attempt first.")
        return False

    user_data = auth_tool.users.get(name)
    if user_data and user_data['designation'] == designation:
        question_key = user_data['security_question']
        if question_key and question_key in auth_tool.security_questions:
            print(f"Security Question: {auth_tool.security_questions[question_key]}")
            security_answer = input("Your answer: ")
            success, message = auth_tool.verify_security_answer(name, designation, security_answer)
            print(message)
            if success:
                return True
            else:
                return False
        else:
            print("Error: Security question not found for this user.")
            return False
    else:
        print("Error: User not found or designation mismatch.")
        return False

if __name__ == "__main__":
    auth_tool = AuthenticationTool()

    # Registration
    registered_name, registered_designation = registration_process(auth_tool)

    if registered_name:
        # First Login Attempt (Password)
        first_login_success, logged_in_name, logged_in_designation = first_login(auth_tool)

        if first_login_success:
            # Second Login Attempt (Security Question)
            access_granted = second_login(auth_tool, logged_in_name, logged_in_designation)

            if access_granted:
                print("\n--- Access Granted ---")
                # Proceed with the application logic here
                auth_tool.authenticated_users.remove((logged_in_name, logged_in_designation)) # Clear the authenticated status after full login
            else:
                print("\n--- Access Denied (Security Question Failed) ---")
                if (logged_in_name, logged_in_designation) in auth_tool.authenticated_users:
                    auth_tool.authenticated_users.remove((logged_in_name, logged_in_designation)) # Clear if second stage fails
        else:
            print("\n--- Access Denied (Password Failed) ---")
