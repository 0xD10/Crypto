from Crypto.Cipher import AES
from Crypto.Util.number import *
import time
import hashlib
import random

FLAG = b'HTB{???????????????????????????}'

def options():
    print("\n[0] Tell me the secret")
    print("[1] <-- Press this if you need a hint!")
    print("[99] Exit\n")

def pad(x):
    while(len(x)<16):
        x+=b'\x00'
    return x

def generate_key():
    keys = []
    for i in range(0x7a120):
        if(isPrime(i)):
            keys.append(hashlib.md5(pad(long_to_bytes(i))).digest())
    return random.choice(keys)

def encrypt(secret,flag):
    cipher = AES.new(secret, AES.MODE_ECB)
    return cipher.encrypt(FLAG)

def decrypt(secret,ciphertext):
    cipher = AES.new(secret, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def menu():
    print("\nWelcome to the Guessing Game!\n")
    print("Can you guess the Secret?\nY (Yes) or N (No)")
    option = input("> ")
    if option=="Y" or option=="y":
        print("\nPlease wait as I carefully craft the keys...\n")
        key = generate_key()
        ciphertext = encrypt(key,FLAG)
        plaintext = decrypt(key,ciphertext)
        while True:
            print(f"\nEncrypted_flag : {hex(bytes_to_long(ciphertext))}")
            print("\n[0] Tell me the secret")
            print("[1] <-- Press this if you need a hint!")
            print("[99] Exit\n")
            choice = int(input("> "))
            if choice == 0:
                guess = input("Put here your guess: ")
                if guess == key:
                    print("\nWHAT?! Impossible\n")
                    print(f"Anyways I guess you are lucky... here is your flag: {plaintext}")
            elif choice == 1:
                print("\nOf course I know that guessing is hard!\n")
                time.sleep(1)
                print("I hope the first 2 bytes of the key will help you")
                time.sleep(1)
                print(f"\nkey_sample : {key[0:2]}")
                time.sleep(1)
            elif choice == 99:
                print("\nPlease stay, don't leave here...\n")
                time.sleep(2)
                exit(1)
    else:
        print("\nWell... I guessed that you wanted to leave :(\n")
        exit(1)

menu()
