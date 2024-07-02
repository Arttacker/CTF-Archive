from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad


def encrypt(msg1, key, secret):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    secret = pad(secret, 128)
    msg1 = pad(msg1, 128)
    c0 = cipher.encrypt(secret)
    c1 = strxor(c0, msg1)

    return c1


def main():
    FLAG = b"EGCTF{FAKE_FLAAAAAAAAAAAAG}"

    # shared data between Alice and Bob
    secret = "[PRIVATE]"
    key = "[PRIVATE]"

    print(f"Alice: Hi Bob, what do you want to share today?")

    print(f"Bob: Hi Alice, I believe we're being monitored. I'll encrypt my message before sending it to you.")

    print(f"Alice: Sure, use our custom encryption method.")

    msg = "[Bob's Secret Message]"
    cipher = encrypt(msg, key, secret).hex()
    print(f"Bob: Here we go. {cipher}")

    FLAG_ENC = encrypt(FLAG, key, secret).hex()
    print(f"Alice: thanks for your message, this gift for you ;) {FLAG_ENC}")

    print(f"Bob: thanks for your gift, see you soon ISA")

    print(f"Alice: Good Bye")


if __name__ == '__main__':
    main()
