import math
import random
import secrets
import string
import hashlib
import json
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), "accounts.json")

ANCHORS = [
    ("Blue umbrella in rain","Think about staying dry.","A traveler smiles as the rain falls."),
    ("Golden compass on a stone map","Think about finding the right direction.","An explorer follows an ancient route."),
    ("Black cat sitting on books","Think about curiosity and learning.","A quiet visitor explores a library."),
    ("Yellow sunflower in a garden","Think about sunshine helping something bloom.","A flower grows brighter every morning."),
    ("Orange fox near a waterfall","Think about a clever journey.","A fox discovers a peaceful stream."),
    ("Silver owl on a snowy fence","Think about wisdom at night.","An owl watches silently."),
    ("White horse near a windmill","Think about freedom and wind.","A horse runs through open fields."),
    ("Purple crystal inside a cave","Think about hidden treasures.","A cave protects a glowing crystal."),
    ("Red bicycle beside a lighthouse","Think about a safe journey.","A cyclist reaches the coast.")
]

COMMON = ["password","admin","welcome","qwerty","123456","abc123","123","abc"]


def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def load_accounts():

    if not os.path.exists(DATA_FILE):
        return []

    with open(DATA_FILE, "r") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return []
        
def save_accounts(accounts):

    with open(DATA_FILE, "w") as file:
        json.dump(accounts, file, indent=4)


COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty",
    "abc123", "password123", "admin",
    "welcome", "letmein", "111111", "123", "abc"
}


def calculate_entropy(password):
    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26

    if any(c.isupper() for c in password):
        charset_size += 26

    if any(c.isdigit() for c in password):
        charset_size += 10

    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)

    if charset_size == 0:
        return 0

    return round(len(password) * math.log2(charset_size), 2)


def check_patterns(password):
    issues = []

    sequences = [
        "123456789",
        "987654321",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "qwertyuiop",
        "asdfghjkl"
    ]

    lower_pw = password.lower()

    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in lower_pw:
                issues.append("Sequential pattern detected")
                break

    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            issues.append("Repeated characters detected")
            break

    return list(set(issues))


def strength_score(password):
    score = 0

    if len(password) >= 8:
        score += 20

    if len(password) >= 12:
        score += 20

    if any(c.islower() for c in password):
        score += 15

    if any(c.isupper() for c in password):
        score += 15

    if any(c.isdigit() for c in password):
        score += 15

    if any(c in string.punctuation for c in password):
        score += 15

    if password.lower() in COMMON_PASSWORDS:
        score -= 40

    return max(0, min(score, 100))


def classify_strength(score):
    if score < 40:
        return "Weak"
    elif score < 70:
        return "Medium"
    else:
        return "Strong"


def estimate_crack_time(entropy):

    guesses_per_second = 10_000_000_000
    total_guesses = 2 ** entropy
    seconds = total_guesses / (2 * guesses_per_second)

    minute = 60
    hour = minute * 60
    day = hour * 24
    year = day * 365

    if seconds < 1:
        return "Less than 1 second"
    elif seconds < minute:
        return f"{seconds:.2f} seconds"
    elif seconds < hour:
        return f"{seconds/minute:.2f} minutes"
    elif seconds < day:
        return f"{seconds/hour:.2f} hours"
    elif seconds < year:
        return f"{seconds/day:.2f} days"
    elif seconds < 1000 * year:
        return f"{seconds/year:.2f} years"
    else:
        return f"{seconds/(1000*year):.2f} thousand years"


def analyze_password(password):

    score = strength_score(password)
    entropy = calculate_entropy(password)
    strength = classify_strength(score)
    crack_time = estimate_crack_time(entropy)
    issues = check_patterns(password)

    print("\n====== PASSWORD ANALYSIS ======")
    print(f"Password Length : {len(password)}")
    print(f"Strength Score  : {score}/100")
    print(f"Classification  : {strength}")
    print(f"Entropy         : {entropy} bits")
    print(f"Crack Time      : {crack_time}")

    if password.lower() in COMMON_PASSWORDS:
        print("\nWARNING: Common password detected!")

    if issues:
        print("\nIssues Found:")
        for issue in issues:
            print("-", issue)

    recommendations = []

    if len(password) < 12:
        recommendations.append("- Use at least 12 characters")

    if not any(c.isupper() for c in password):
        recommendations.append("- Add uppercase letters")

    if not any(c.islower() for c in password):
        recommendations.append("- Add lowercase letters")

    if not any(c.isdigit() for c in password):
        recommendations.append("- Add numbers")

    if not any(c in string.punctuation for c in password):
        recommendations.append("- Add special characters")

    if recommendations:
        print("Recommendations : ")
        for rec in recommendations:
            print(f" {rec}")

    else:
        print("Recommendations : NIL!")


def generate_random_password(length=16):

    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]

    chars = string.ascii_letters + string.digits + string.punctuation

    password.extend(
        secrets.choice(chars)
        for _ in range(length - 4)
    )

    random.shuffle(password)

    return ''.join(password)

def validate_password(password, level):
    issues = []

    length = len(password)

    uppercase = any(c.isupper() for c in password)
    lowercase = any(c.islower() for c in password)
    digits = sum(c.isdigit() for c in password)
    special = sum(c in string.punctuation for c in password)

    accepted = True

    score = strength_score(password)

    if level == "Medium":

        if length < 10:
            accepted = False
            issues.append("Password must contain at least 10 characters.")

        if not uppercase:
            accepted = False
            issues.append("Add at least one uppercase letter.")

        if not lowercase:
            accepted = False
            issues.append("Add at least one lowercase letter.")

        if digits < 1:
            accepted = False
            issues.append("Add at least one digit.")

    elif level == "Strong":

        if length < 12:
            accepted = False
            issues.append("Password must contain at least 12 characters.")

        if not uppercase:
            accepted = False
            issues.append("Add at least one uppercase letter.")

        if not lowercase:
            accepted = False
            issues.append("Add at least one lowercase letter.")

        if digits < 1:
            accepted = False
            issues.append("Add at least one digit.")

        if special < 1:
            accepted = False
            issues.append("Add at least one special character.")

    elif level == "Very Strong":

        if length < 14:
            accepted = False
            issues.append("Password must contain at least 14 characters.")

        if not uppercase:
            accepted = False
            issues.append("Add at least one uppercase letter.")

        if not lowercase:
            accepted = False
            issues.append("Add at least one lowercase letter.")

        if digits < 2:
            accepted = False
            issues.append("Add at least two digits.")

        if special < 1:
            accepted = False
            issues.append("Add at least one special character.")

    if password.lower() in COMMON_PASSWORDS:
        accepted = False
        issues.append("Common passwords are not allowed.")

    for issue in check_patterns(password):
        accepted = False
        issues.append(issue)

    return accepted, score, issues

def smart_leetspeak(word):

    replacements = {
        "a": "@",
        "e": "3",
        "i": "1",
        "o": "0",
        "s": "$",
        "t": "7"
    }

    result = ""

    for char in word:
        result += replacements.get(char.lower(), char)

    return result


def trainer():
    username = input("Username: ").strip()
    website = input("Website/Application: ").strip()
    if not username or not website:
        print("Username and Website cannot be empty.")
        return

    print("\nChoose a Visual Anchor which will help you to recollect you password\n")
    idxs=random.sample(range(len(ANCHORS)),9)
    selected_list=[ANCHORS[i] for i in idxs]
    for i,(a,_,_) in enumerate(selected_list,1):
        print(f"{i}. {a}")
    while True:
        try:
            ch=int(input("Choice: "))
            if 1<=ch<=len(selected_list): 
                break
            else:
                print("Invalid Choice!")
        except ValueError:
            print("Please enter a number")

           
    anchor,hint,story=selected_list[ch-1]
    while True:
        print("\nSecurity Level")
        print("1. Medium")
        print("2. Strong")
        print("3. Very Strong")

        lv = input("Choice (1-3): ").strip()

        if lv == "1":
            level = "Medium"
            break

        elif lv == "2":
            level = "Strong"
            break

        elif lv == "3":
            level = "Very Strong"
            break

        else:
            print("\nInvalid choice! Please enter only 1, 2, or 3.")

    print("\n===================================")
    print(f"Selected Security Level : {level}")
    print("===================================")

    if level == "Medium":

        print("""
    Password Requirements

    - At least 10 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    """)

    elif level == "Strong":

        print("""
    Password Requirements

    - At least 12 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
    """)

    elif level == "Very Strong":

        print("""
    Password Requirements

    - At least 14 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 2 numbers
    - At least 1 special character
    """)
    print("\nMemory Hint:",hint)
    print("Mnemonic Story:",story)
    while True:
        
        pwd=input("\nCreate password (Related to the Visual Anchor): ").strip()
        if pwd=="":
            print("Password cannot be empty.")
            continue
        ok, score, issues = validate_password(pwd, level)

        if ok:
            print("\nPassword Accepted")
            analyze_password(pwd)
            print("Score:", score)
            break

        print("\nPassword does not meet the recommended requirements.")
        print("\nSuggestions:")
        for x in issues:
            print("-", x)

        while True:
            choice = input(
                "\nDo you want to:\n"
                "1. Improve the password\n"
                "2. Continue with this password anyway\n"
                "Choice (1/2): "
            ).strip()

            if choice == "1":
                # Go back and enter another password
                break

            elif choice == "2":
                print("\nProceeding with your current password...")
                analyze_password(pwd)
                print("Score:", score)
                ok = True
                break

            else:
                print("Invalid choice.")

        if ok:
            break
    count=0
    while count<3:
        print(f"\nPractice {count+1}/3")
        x=input("Type password: ").strip()
        if x==pwd:
            count+=1
            print("Correct")
        else:
            count=0
            print("Incorrect. Counter reset.")
    print("Now you can go ahead and use this password in the website/application\n" \
    "Hope you will be able to recollect it easily!")
    salt = secrets.token_hex(16)

    stored_hash = hashlib.sha256(
        (pwd + salt).encode()
    ).hexdigest()

    accounts = load_accounts()

    account = {
        "username": username,
        "website": website,
        "anchor": anchor,
        "salt": salt,
        "password_hash": stored_hash
    }

    accounts.append(account)

    save_accounts(accounts)
    
  
def recall():

    accounts = load_accounts()

    if len(accounts) == 0:
        print("\nNo saved accounts.")
        return

    while True:

        print("\n\nFollowing details are required : ")
        print("(Type 'q' at any time to return to the menu)")

        username = input("\nUsername: ").strip()

        if username.lower() == "q":
            print("\nReturning to menu...")
            return

        website = input("Website/Application: ").strip()

        if website.lower() == "q":
            print("\nReturning to menu...")
            return

        if not username or not website:
            print("Username and Website cannot be empty.")
            continue

        account = None

        for item in accounts:

            if (
                item["username"].strip().lower() ==
                username.lower()
                and
                item["website"].strip().lower() ==
                website.lower()
            ):
                account = item
                break

        if account:
            print("\nAccount Found")
            break
        else:
            print("No matching account details found.")
            retry = input(
                "Press Enter to try again or type 'q' to return to the menu: "
            ).strip().lower()

            if retry == "q":
                print("\nReturning to menu...")
                return

    while True:

        distractors = ANCHORS[:]
        random.shuffle(distractors)

        print("\nRecall Stage")

        for i, (a, _, _) in enumerate(distractors, 1):
            print(f"{i}. {a}")

        while True:

            try:

                sel = int(input("Select Anchor: "))

                if 1 <= sel <= len(distractors):
                    break

                print("Invalid choice.")

            except ValueError:

                print("Enter a number.")

        entered = input("Enter Password: ").strip()

        anchor_ok = (
            distractors[sel - 1][0] ==
            account["anchor"]
        )

        entered_hash = hashlib.sha256(
            (entered + account["salt"]).encode()
        ).hexdigest()

        password_ok = (
            entered_hash ==
            account["password_hash"]
        )

        print("\n========== RESULT ==========")

        if anchor_ok and password_ok:
            print("Correct Anchor + Correct Password")
            break

        elif anchor_ok:
            print("Correct Anchor + Wrong Password")

        elif password_ok:
            print("Wrong Anchor + Correct Password")

        else:
            print("Wrong Anchor + Wrong Password")

        while True:
            retry = input(
                "\nPress Enter to try again or type 'q' to return to the menu: "
            ).strip().lower()

            if retry == "":
                break          # Retry Recall Stage

            elif retry == "q":
                print("\nReturning to menu...")
                return         # Exit recall()

            else:
                print("Invalid input. Please press Enter or type 'q'.")


def improve_password(password):

    improved = password

    # Add uppercase
    if not any(c.isupper() for c in improved):
        improved = improved.capitalize()

    # Add lowercase
    if not any(c.islower() for c in improved):
        improved += "abc"

    # Add numbers
    if not any(c.isdigit() for c in improved):
        improved += str(random.randint(100, 999))

    # Add symbols
    if not any(c in string.punctuation for c in improved):
        improved += "@#$"

    # Increase length
    if len(improved) < 12:
        improved += secrets.choice([
            "Tiger",
            "Dragon",
            "Phoenix",
            "Cyber",
            "Secure"
        ])

    return improved


def main():

    while True:

        print("___________________________________________________________________________")
        print("\n****Disclaimer:This is a beginner-level prototype for educational purpose. " \
        "\nIt does not store, transmit, or save passwords!****" \
        "\n___________________________________________________________________________" \
        "\n\n=============== PASSWORD STRENGTH AND MEMORABILITY ASSISTANT ==============")
        print("\n1. Analyze Strength of any Password")
        print("2. Generate a Random Password of Desired Strength(Computer generated)")
        print("3. Improve Existing Password")
        print("4. Generate Password with Visual Anchor and Recall Trainer")
        print("5. Recall Password using Visual Anchor")
        print("6. Exit")
        print("___________________________________________________________________________")       

        choice = input("\nSelect Option: ")

        if choice == "1":

            password = input("Enter Password: ")
            analyze_password(password)

        elif choice == "2":

            while True:
                try:
                    length = int(input("Password Length (minimum 8): "))
                    if length >= 8:
                        break
                    print("Password length must be at least 8.")
                except ValueError:
                    print("Please enter a valid number.")
                    
            generated = generate_random_password(length)

            print("\nGenerated Password:")
            print(generated)

            analyze_password(generated)
            
        elif choice == "3":

            init_password = input("Enter Password: ")
           
            improved = improve_password(init_password)

            print("\nInitial Password : ", init_password)
            analyze_password(init_password)

            if not strength_score(init_password) == 100:
                
                print("\nImproved Password : ", improved)
                analyze_password(improved)
            
        elif choice == "4":

            trainer()

        elif choice == "5":

            recall()

        elif choice == "6":

            print("Goodbye!")
            break

        else:

            print("Invalid Choice")


if __name__ == "__main__":
    main()
