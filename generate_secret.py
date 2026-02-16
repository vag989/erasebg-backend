import sys
import random
import string

def generate_random_secret(length):
    characters = string.ascii_lowercase[:6] + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


if __name__ == "__main__":
    # Example usage
    secret_length = int(sys.argv[1])  # Change this value as needed

    print(secret_length)
    random_secret = generate_random_secret(secret_length)
    print(f'Random secret: {random_secret}')
