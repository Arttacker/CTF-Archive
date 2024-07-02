
## Introduction

Greetings, my name is **Saleh Adel**, also known as **Artacker**. Today, I am excited to present my solution to the **Custom Communication** CTF cryptography challenge, which was featured in the prestigious Cyber Security Competition (CSC-2024) at the 8th International Competition of the Military Technical College (ICMTC 2024).

## Challenge Description
We've implemented a secure system for communication. Attackers can't get our messages now.

`nc challenge-ip port`

**Challenge files:**  
 [challenge.py](https://github.com/Arttacker/CTF-Archive/tree/main/Cryptography/ICMTC-2024/Custom%20Communication/challenge.py)


## Notifications & Analysis 🔍

### The Encryption Function 🔒

Here is the function in `challenge.py` that is used to encrypt the messages:
```python
def encrypt(msg1, key, secret):  
    cipher = AES.new(key=key, mode=AES.MODE_ECB)  
    secret = pad(secret, 128)  
    msg1 = pad(msg1, 128)   
    c0 = cipher.encrypt(secret)    
    c1 = strxor(c0, msg1)  
    return c1
```

1. The function takes three arguments: `(msg1, key, secret)`:
	- `msg1`: The message to be encrypted.
	- `key`: The key used in the AES cipher.
	- `secret`: The secret is encrypted with the key using AES, then the resulted ciphertext is used to encrypt `msg1` using XOR.

2. AES block cipher is used in **ECB (Electronic Code Book) mode**: 
> In ECB mode, each block of plaintext is encrypted independently with the same key, Since each block is encrypted independently, patterns in the plaintext can persist in the ciphertext.

3. `msg1` and `secret`, are padded using the `pad()` function from `Crypto.Util.Padding` module, the padding extends the length of both `msg1` and `secret` to be $128-bytes$ length, and according to the `pad()` function's documentation, the default padding algorithm used is `pkcs7`, which calculates the number of required padding bytes, and pad with bytes that each have the value of the **hex** representation of this number; e.g. if the number of required padding bytes are $4-bytes$, then the padding bytes will be `0x04 0x04 0x04 0x04`.

I did a design diagram for this encryption algorithm as follows:
![image](https://github.com/Arttacker/CTF-Archive/assets/99927650/36af5402-53c9-40dd-a98c-e79452b7002e)


We can conclude that **$C0$** can be considered the key used to encrypt `msg` by using XOR, and given these facts about XOR:
```
A ⊕ B = C
A ⊕ C = B
B ⊕ C = A
```
By reflecting this to our case, we can say that:
```
C0 ⊕ msg = C1
C0 ⊕ C1 = msg
msg ⊕ C1 = C0
```

---
---
## Start Hacking 💀🔐
I started to test connecting to the server using `nc challenge-ip port`, and this was the output:
```
Alice: Hi Bob, what do you want to share today?
Bob: Hi Alice, I believe we're being monitored. I'll encrypt my message before sending it to you.
Alice: Sure, use our custom encryption method.
Bob: Here we go. 98c48b567cb66b4289bafe06c60b8494d486d6b4f392bb4db713ef1330cac9bec38197a9f192bb5db646bb0c3c99d6f1c582d397d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3
Alice: thanks for your message, this gift for you ;) 84ecbd2257b879049ebcad1f8b55d1d6d1d980ebf5c7f855eb52f95d6e8091e3d78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fe
```

As we see there are two encrypted messages from Bob to Alice, and its obvious that the second one is the FLAG.

By trying to connect for another time, in order to test if the `key` and `secret` are regenerated on every connection or remain the same, and as I expected, the value of encrypted flag in the second session is different form the first one, and given that the flag for the challenge is constant, so that means that the used `key` and `secret`  changes for each session, and they are not constantly established.

---
### Stages 📈
#### First Stage 🧩
According `encrypt()` function naming conventions, lets say that:
- The key used to encrypt the **$1^{st}$** and **$2^{nd}$** messages from Bob to Alice is: **$C0$** 
- The first encrypted message from Bob will be: **$C1_1$**
- The second encrypted message from Bob **(FLAG)** will be: **$C1_2$**

First thing came to my mind is that I already know know the first $6-bytes$ of the plaintext flag, as the flag format is given as `EGCTF{}`, so the first $6-bytes$ are `EGCTF{`,
and with this information, and given the ciphered flag **$C1_2$**, I can leverage the XOR properties and reveal the first $6-bytes$ of the **$C0$**. and this by doing XOR between the first $6-bytes$ of **$C1_2$** and the known first $6-bytes$ of the plaintext flag.

What we can do after this, is to use this recovered part of **$C0$** to decrypt the corresponding first $6-bytes$ of the first encrypted message sent by Bob (**$C1_1$**), as both **$C1_1$** and **$C1_2$** are encrypted using **$C0$**.

After running the following script:
```python
recovered_first_6_bytes_c0 = strxor(bytes.fromhex(ciphered_flag[:12]), b'EGCTF{').hex()  
print(recovered_first_6_bytes_c0)  
revealed_first_6_bytes_msg = strxor(bytes.fromhex(ciphered_msg1[:12]), bytes.fromhex(recovered_first_6_bytes_c0)).hex()  
print(hex_decode(revealed_first_6_bytes_msg))
```
- The recovered first $6-bytes$ of **$C0$** are:
`c1abfe7611c3`
- The revealed first $6-bytes$ of **$C1_1$**:
`You mu`

This is great but how to reveal the remaining $122-bytes$ ?! 🙂

---
#### Second Stage 🧠
Now lets analyze **$C1_1$** and **$C1_2$**, and split them into blocks of $16-bytes-(128-bit)$ each.

- Why specifically $128-bit$ ?
>As AES splits the given plaintext to block each of $128-bit$ length, and encrypts them block by block then append them together to form the final ciphertext, this will help us, as **$C0$** that is used to encrypt the flag, is itself an AES ciphered text.

 Splitted **$C1_1$** in $16-bytes-(128-bit)$ blocks
```
98c48b567cb66b4289bafe06c60b8494
d486d6b4f392bb4db713ef1330cac9be
c38197a9f192bb5db646bb0c3c99d6f1
c582d397d9bad679952b822914f4ecd3
faa3fa97d9bad679952b822914f4ecd3
faa3fa97d9bad679952b822914f4ecd3
faa3fa97d9bad679952b822914f4ecd3
faa3fa97d9bad679952b822914f4ecd3
```
 Splitted **$C1_2$** in $16-bytes-(128-bit)$ blocks
```
84ecbd2257b879049ebcad1f8b55d1d6
d1d980ebf5c7f855eb52f95d6e8091e3
d78ed7baf497fb54b806af0439d9c1fe
d78ed7baf497fb54b806af0439d9c1fe
d78ed7baf497fb54b806af0439d9c1fe
d78ed7baf497fb54b806af0439d9c1fe
d78ed7baf497fb54b806af0439d9c1fe
d78ed7baf497fb54b806af0439d9c1fe
```

We can notice that when splitting these encrypted data, there are some repeated $16-bytes$ blocks from the end of the ciphertexts, which represent the padding in the plaintext before encryption, as the message is padded to be $128-bytes$ length when encrypted using the discussed `encrypt()` function above.

In the ciphered flag (**$C1_2$**), we will notice that the last  $6 × 16-bytes$ blocks are the same which, are $96-bytes$ total. 

Now we realize a very important piece of information, which is: both the `msg` and `secret` are padded with **(AT LEAST)** $96-bytes$ before any encryption. And here is why:
1. Padding the secret before encrypting with **ECB-AES** will produce **$C0$** with number of $128-bit$ blocks are repeated in the end it.
2. This padded **$C0$** when XORed with the padded messages, there will be multiple XORs with the same inputs, producing a result that also has number of $128-bit$ blocks are repeated in the end it; And that is what we are facing now.

We can say that there are two main possibilities of padding:
1. The `msg`  **(FLAG in this case)** is padded with exactly $96-bytes$, and `secret` is padded with $≥ 96-bytes$
2. The `secret` is padded with exactly $96-bytes$, and `msg` **(FLAG in this case)** is padded with $≥ 96-bytes$

If we assumed that the first assumption is true, we can say that: as the there are $96-bytes$ of padding in the Flag, and according to the used `pkcs7` padding algorithm discussed above, we can deduce that the flag is padded with $96$ bytes of values `hex(96)` which is `0x60`.

Wow! this means that we can now recover the last $96-bytes$ of **$C0$**, and reveal the last $96-bytes$ of the first message sent by Bob, as we done with the first $6-bytes$.

Also we shouldn't forget that we know an additional byte in the plaintext flag before padding with the $96-bytes$, which is `}`, that closes the flag!

Another thing was observed when I analyzed another responses from another sessions, that the padding in the ciphered flag is always constant, and this is normal as the flag is constant, but the strange thing is that the first encrypted message have different padding bytes every time I try to connect to the server, and this has one meaning, that is the first message sent by Bob, isn't the same in all connections. 

But, let's keep this for later analysis, and now we can focus on how to exploit our knowledge of the flag padding.

So, for now we have a total of $97-bytes$ are known from the end of the plaintext flag, so lets try to recover the last $97-bytes$ of **$C0$.**

 After running the following script:
```python
recovered_last_97_bytes_c0 = strxor(bytes.fromhex(ciphered_flag[-194:]), bytes.fromhex("7d" + "60" * 96)).hex()  
print(recovered_last_97_bytes_c0)  
revealed_last_97_bytes_msg = strxor(bytes.fromhex(ciphered_msg1[-194:]), bytes.fromhex(recovered_last_97_bytes_c0)).hex()  
print(hex_decode(revealed_last_97_bytes_msg))
```

- The recovered last $97-bytes$ of **$C0$** are:
```
9eb7eeb7da94f79b34d866cf6459b9a19eb7eeb7da94f79b34d866cf6459b9a19eb7eeb7da94f79b34d866cf6459b9a19eb7eeb7da94f79b34d866cf6459b9a19eb7eeb7da94f79b34d866cf6459b9a19eb7eeb7da94f79b34d866cf6459b9a19e
```

- The revealed last $97-bytes$ of the first message are:
` to see in the worldMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM`

My assumption was true and we now we can read the last $97-bytes$ of the first message sent by Bob.

---
#### Third Stage 💡
- Now if we did the same thing we did with the retrieved **$C1_1$** and **$C1_2$** from connecting to the server, which is to split it into blocks $16-bytes-(128-bit)$ :
```
9e
b7eeb7da94f79b34d866cf6459b9a19e
b7eeb7da94f79b34d866cf6459b9a19e
b7eeb7da94f79b34d866cf6459b9a19e
b7eeb7da94f79b34d866cf6459b9a19e
b7eeb7da94f79b34d866cf6459b9a19e
b7eeb7da94f79b34d866cf6459b9a19e
```

As expected, the last $96-bytes$ are representing the ciphered padding, and according to our true assumption that is the Flag is padded with exactly $96-bytes$, and `secret` is padded with $≥ 96-bytes$, and by analyzing this recovered part of **$C0$**, we can say that it may be padded more!, and what makes this assumption strong, that the first lonely byte in the in the splitted **$C0$** is the same as the last byte. and this means that there might be a remaining part of padding with `b7eeb7da94f79b34d866cf6459b9a1`, And now we have the last  $112-bytes$ of **$C0$**. 

After trying this, It worked! and after revealing the last $112-bytes$ of **$C1_1$** , this is the plaintext content:
`change you wish to see in the worldMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM`

And don't forget that we already know the first $6-bytes$ of **$C0$** so, we know a total of $118-bytes$ of **$C0$**, and there only missing $10-bytes$ after the first $6-bytes$.

Let's try to use what we got till now, and connect the revealed data about the first message, to see that the content is:
`You mu**********change you wish to see in the worldMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM`

I've replaced the unknown $10-bytes$ with `*`.

---
#### Final Stage 🗝️
I think we can now easily guess the missing 10 characters (bytes) of the message to be:
`You must be the change you wish to see in the worldMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM`

Now by XORing this message with its encryption (**$C1_1$**), to get the complete $128-bytes$ of **$C0$** and then decrypt the ciphered flag (**$C1_2$**) to be:
`EGCTF{a27d69960bf771a0ca3469790}`

---


## Conclusion

You can visit my [GitHub repository](https://github.com/Arttacker/CTF-Archive/tree/main/Cryptography/ICMTC-2024/Custom%20Communication), to learn more about how I did an extensive analysis for the intercepted messages between Alice and Bob, and how employed Python and creating a [script](https://github.com/Arttacker/CTF-Archive/tree/main/Cryptography/ICMTC-2024/Custom%20Communication/hack.py) to automate the process of connecting to the server and getting multiple intercepted messages and decrypting it, to know about the different messages sent by Bob before the flag as I said above.

I would like to extend my heartfelt gratitude to the organizers and creators of the Cyber Security Competition (CSC-2) at the 8th International Competition of the Military Technical College (ICMTC 2024). Their dedication and hard work made this competition an outstanding and enriching experience.

For more insights and to connect with me, please visit my [GitHub](https://github.com/Arttacker) and follow me on [LinkedIn](https://linkedin.com/in/salehadel).

Thank you for your attention, and I look forward to engaging with you further.
