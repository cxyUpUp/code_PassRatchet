import secrets
import string


def generate_password_file():
    # Define the required password length
    lengths = [8, 16, 32, 64, 128]

    # Character set
    chars = string.ascii_letters + string.digits + "!@#$%^&*"

    # Generate password dictionary
    passwords = {}
    for length in lengths:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        passwords[length] = password

    # Save to a single file
    with open('passwords.txt', 'w', encoding='utf-8') as f:
        f.write("Password database - Sorted by length\n")
        f.write("=" * 40 + "\n\n")

        for length in lengths:
            f.write(f"LENGTH_{length}: {passwords[length]}\n")

    print("The password file has been generated.: passwords.txt")
    print("\nThe length of the generated password:")
    for length in lengths:
        print(f"  {length}Characters: {passwords[length]}")

    return passwords


# Generate password file
passwords_dict = generate_password_file()