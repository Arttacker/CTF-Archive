import socket
from Crypto.Util.strxor import strxor
from encoding.hex_encoding import hex_decode, hex_encode


def connect_and_get_data():
    # Connect to the service
    host = '164.92.192.140'
    port = 1336
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Read the data from the service
    data = s.recv(4096).decode()
    s.close()

    # Extract the ciphertexts
    bob_msg_start = data.find("Bob: Here we go. ") + len("Bob: Here we go. ")
    bob_msg_end = data.find("\nAlice: thanks for your message")
    bob_cipher = data[bob_msg_start:bob_msg_end].strip()
    flag_msg_start = data.find("Alice: thanks for your message, this gift for you ;) ") + len(
        "Alice: thanks for your message, this gift for you ;) ")
    flag_msg_end = data.find("\nBob: thanks for your gift")
    flag_cipher = data[flag_msg_start:flag_msg_end].strip()
    print("The first encrypted message from Bob: ", bob_cipher)
    print("The second encrypted message from Bob: ", flag_cipher)
    return bob_cipher, flag_cipher


def reveal_118_bytes_of_first_message(cipher, FLAG_ENC):
    first_6_byts_of_flag = b'EGCTF{'
    first_6_byts_of_flag_cipher = FLAG_ENC[:12]
    first_6_byts_of_C0 = strxor(first_6_byts_of_flag, bytes.fromhex(first_6_byts_of_flag_cipher)).hex()

    first_6_byts_of_cipher = cipher[:12]
    first_6_bytes_of_msg1 = strxor(bytes.fromhex(first_6_byts_of_C0), bytes.fromhex(first_6_byts_of_cipher)).hex()

    padding_of_flag = b'}' + bytes.fromhex('0x60') * 96
    last_97_bytes_of_FLAG_ENC = FLAG_ENC[-194:]
    last_97_bytes_of_C0 = strxor(padding_of_flag, bytes.fromhex(last_97_bytes_of_FLAG_ENC)).hex()

    last_112_bytes_of_C0 = last_97_bytes_of_C0[2:32] + last_97_bytes_of_C0
    last_112_bytes_of_cipher = cipher[-224:]
    last_112_bytes_of_msg1 = strxor(bytes.fromhex(last_112_bytes_of_C0), bytes.fromhex(last_112_bytes_of_cipher)).hex()

    first_6_bytes_of_msg1 = hex_decode(first_6_bytes_of_msg1)
    last_112_bytes_of_msg1 = hex_decode(last_112_bytes_of_msg1)
    return first_6_bytes_of_msg1 + "**********" + last_112_bytes_of_msg1


def compute_c0(msg, c1):
    hex_msg = hex_encode(msg)
    return strxor(bytes.fromhex(hex_msg), bytes.fromhex(c1))


def analyse_messages():
    for i in range(10):
        bob_cipher, flag_cipher = connect_and_get_data()
        print("The revealed part of the first message: ", reveal_118_bytes_of_first_message(bob_cipher, flag_cipher))


if __name__ == '__main__':
    # analyse_messages()
    msg = "You must be the change you wish to see in the worldMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
    c1 = "581fc0530f322a4b00b29159ec003bf2260d9f554b804c2e650fc79fac90a315310ade4849804c3e645a9380a0c3bc5a37099a7661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae8678"
    encrypted_flag = "4437f627243c380d17b4c240a15e6eb02352c90a4dd50f36394ed1d1f2dafb4825059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab55"
    c0 = compute_c0(msg, c1)

    # decrypting the ciphered flag with C0
    flag = strxor(c0, bytes.fromhex(encrypted_flag))
    print(flag)
    # b'EGCTF{a27d69960bf771a0ca3469790}````````````````````````````````````````````````````````````````````````````````````````````````'

""" Output for the analyse_messages() function
The first encrypted message from Bob:  b130bf3d569f2706ffa306456819a203f102e6c2a6af49aec21b1bcde9bc0d90ec03cabc8c99769ebc3220ffdbc220afdb39cabc8c99769ebc3220ffdbc220afdb39cabc8c99769ebc3220ffdbc220afdb39cabc8c99769ebc3220ffdbc220afdb39cabc8c99769ebc3220ffdbc220afdb39cabc8c99769ebc3220ffdbc220af
The second encrypted message from Bob:  a31290053080295aade7590f714df715e350a3d3b3f74ba1d1584898b2a54e8ce507f482b2a748a0820c1ec1e5fc1e91e507f482b2a748a0820c1ec1e5fc1e91e507f482b2a748a0820c1ec1e5fc1e91e507f482b2a748a0820c1ec1e5fc1e91e507f482b2a748a0820c1ec1e5fc1e91e507f482b2a748a0820c1ec1e5fc1e91
The revealed part of the first message:  Well d**********ter than well said^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first encrypted message from Bob:  581fc0530f322a4b00b29159ec003bf2260d9f554b804c2e650fc79fac90a315310ade4849804c3e645a9380a0c3bc5a37099a7661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae86780828b37661a8211a4737aaa588ae8678
The second encrypted message from Bob:  4437f627243c380d17b4c240a15e6eb02352c90a4dd50f36394ed1d1f2dafb4825059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab5525059e5b4c850c376a1a8788a583ab55
The revealed part of the first message:  You mu**********change you wish to see in the worldMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM

The first encrypted message from Bob:  7a7b2f4444cfed5f8a4f1986e45e6267bbe8bc5667d48e34a60f837c3115545bace2bc4b69d8f41a9434ad06182c6f7393cbc6685cf7f41a9434ad06182c6f7393cbc6685cf7f41a9434ad06182c6f7393cbc6685cf7f41a9434ad06182c6f7393cbc6685cf7f41a9434ad06182c6f7393cbc6685cf7f41a9434ad06182c6f73
The second encrypted message from Bob:  7b534c7f6cd1ac19d54241d8fd0d2460afa6ab03679dcd21fd5ac165754f0554a9f1fc5266cdce20ae0e973c22165549a9f1fc5266cdce20ae0e973c22165549a9f1fc5266cdce20ae0e973c22165549a9f1fc5266cdce20ae0e973c22165549a9f1fc5266cdce20ae0e973c22165549a9f1fc5266cdce20ae0e973c22165549
The revealed part of the first message:  Do one**********ry day that scares youZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ

The first encrypted message from Bob:  2a1ee245d4f706a04ea6bc5f09b87bd2cd4b878463579025bfb6536640d914bbda4187996d5bea0b8d8d7d1c69e02f93e568fdba5874ea0b8d8d7d1c69e02f93e568fdba5874ea0b8d8d7d1c69e02f93e568fdba5874ea0b8d8d7d1c69e02f93e568fdba5874ea0b8d8d7d1c69e02f93e568fdba5874ea0b8d8d7d1c69e02f93
The second encrypted message from Bob:  2b36817efce947e611abe40110eb3dd5d90590d1631ed330e4e3117f048345b4df52c780624ed031b7b7472653da15a9df52c780624ed031b7b7472653da15a9df52c780624ed031b7b7472653da15a9df52c780624ed031b7b7472653da15a9df52c780624ed031b7b7472653da15a9df52c780624ed031b7b7472653da15a9
The revealed part of the first message:  Do one**********ry day that scares youZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ

The first encrypted message from Bob:  3d9426ffa1a46b771a8148d8f8364f5dcd50306e6a5287c9f84850df6ef0a3e6db503e6a7d4587d4e31b53d669d1d0dcfb230b5c4f64f4eec43b65e95cd1d0dcfb230b5c4f64f4eec43b65e95cd1d0dcfb230b5c4f64f4eec43b65e95cd1d0dcfb230b5c4f64f4eec43b65e95cd1d0dcfb230b5c4f64f4eec43b65e95cd1d0dc
The second encrypted message from Bob:  2cbb008b88b1663c0d911688af675f48ce476f3e7d07c4dca45c008338bbb3f2c810386f7c57c7ddf70856da6fe2e3efc810386f7c57c7ddf70856da6fe2e3efc810386f7c57c7ddf70856da6fe2e3efc810386f7c57c7ddf70856da6fe2e3efc810386f7c57c7ddf70856da6fe2e3efc810386f7c57c7ddf70856da6fe2e3ef
The revealed part of the first message:  The on**********e have to fear is fear itselfSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS

The first encrypted message from Bob:  8e0e8e3964fa1a989169c1ea79480e2d598183eca8dd011fc43efa19481ec41b4f818de8bfca0102df6df9104f3fb7216ff2b8de8deb7238f84dcf2f7a3fb7216ff2b8de8deb7238f84dcf2f7a3fb7216ff2b8de8deb7238f84dcf2f7a3fb7216ff2b8de8deb7238f84dcf2f7a3fb7216ff2b8de8deb7238f84dcf2f7a3fb721
The second encrypted message from Bob:  9f21a84d4def17d386799fba2e191e385a96dcbcbf88420a982aaa451e55d40f5cc18bedbed8410bcb7efc1c490c84125cc18bedbed8410bcb7efc1c490c84125cc18bedbed8410bcb7efc1c490c84125cc18bedbed8410bcb7efc1c490c84125cc18bedbed8410bcb7efc1c490c84125cc18bedbed8410bcb7efc1c490c8412
The revealed part of the first message:  The on**********e have to fear is fear itselfSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS

The first encrypted message from Bob:  59dea2530be4ad7ee81962f20a42ff47d95cb1acc9d6e4726e8e382b686396cfc45d9dd2e3e0db4210a703195a1dbbf0f3679dd2e3e0db4210a703195a1dbbf0f3679dd2e3e0db4210a703195a1dbbf0f3679dd2e3e0db4210a703195a1dbbf0f3679dd2e3e0db4210a703195a1dbbf0f3679dd2e3e0db4210a703195a1dbbf0
The second encrypted message from Bob:  4bfc8d6b6dfba322ba5d3db81316aa51cb0ef4bddc8ee67d7dcd6b7e337ad5d3cd59a3ecdddee57c2e993d27642385cecd59a3ecdddee57c2e993d27642385cecd59a3ecdddee57c2e993d27642385cecd59a3ecdddee57c2e993d27642385cecd59a3ecdddee57c2e993d27642385cecd59a3ecdddee57c2e993d27642385ce
The revealed part of the first message:  Well d**********ter than well said^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first encrypted message from Bob:  f87cfa8eaf110b4554bc24fe1be785ee4bd6421731499fcf68236892e31897145cdc420a3f45e5e15a1846e8ca21ac3c63f538290a6ae5e15a1846e8ca21ac3c63f538290a6ae5e15a1846e8ca21ac3c63f538290a6ae5e15a1846e8ca21ac3c63f538290a6ae5e15a1846e8ca21ac3c63f538290a6ae5e15a1846e8ca21ac3c
The second encrypted message from Bob:  f95499b5870f4a030bb17ca002b4c3e95f9855423100dcda33762a8ba742c61b59cf02133050dfdb60227cd2f01b960659cf02133050dfdb60227cd2f01b960659cf02133050dfdb60227cd2f01b960659cf02133050dfdb60227cd2f01b960659cf02133050dfdb60227cd2f01b960659cf02133050dfdb60227cd2f01b9606
The revealed part of the first message:  Do one**********ry day that scares youZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ

The first encrypted message from Bob:  98c48b567cb66b4289bafe06c60b8494d486d6b4f392bb4db713ef1330cac9bec38197a9f192bb5db646bb0c3c99d6f1c582d397d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3faa3fa97d9bad679952b822914f4ecd3
The second encrypted message from Bob:  84ecbd2257b879049ebcad1f8b55d1d6d1d980ebf5c7f855eb52f95d6e8091e3d78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fed78ed7baf497fb54b806af0439d9c1fe
The revealed part of the first message:  You mu**********change you wish to see in the worldMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM

The first encrypted message from Bob:  b6df9074943da252eb6c98984c879ee4f2362a94fb8acabb30b554fa3d98824be53c2a89f586b095028e7a8014a1b963da1550aac0a9b095028e7a8014a1b963da1550aac0a9b095028e7a8014a1b963da1550aac0a9b095028e7a8014a1b963da1550aac0a9b095028e7a8014a1b963da1550aac0a9b095028e7a8014a1b963
The second encrypted message from Bob:  b7f7f34fbc23e314b461c0c655d4d8e3e6783dc1fbc389ae6be016e379c2d344e02f6a90fa938aaf38b440ba2e9b8359e02f6a90fa938aaf38b440ba2e9b8359e02f6a90fa938aaf38b440ba2e9b8359e02f6a90fa938aaf38b440ba2e9b8359e02f6a90fa938aaf38b440ba2e9b8359e02f6a90fa938aaf38b440ba2e9b8359
The revealed part of the first message:  Do one**********ry day that scares youZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ

"""
