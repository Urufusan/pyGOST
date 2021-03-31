from GOST import GOST
import my_utils
import time

# gost = GOST()
# msg = "This algorithm is probably the best one I ever implemented <3."
# key, salt = my_utils.PBKDF2("GOST is the best algorithm")
# t1 = time.time()
# gost.set_message(my_utils.string_to_bytes(msg))
# gost.set_key(key)
# print("Msg: ", msg)
# print("Key: ", my_utils.leading_zeros_hex(key))
# print("Salt: ", salt)
# ciphertext = my_utils.leading_zeros_hex(gost.encrypt(gost.CBC))
# print("IV: ", my_utils.leading_zeros_hex(gost.get_iv()))
#
# print("Encrypted: ", ciphertext)
#
# #deciphered = gost.decrypt(gost.CBC)
# #print("Decrypted: ", my_utils.bytes_to_string(deciphered))
# t2 = time.time()
# print("Elapsed time (s): ", t2 - t1)
#
# #Decrypt the ciphertext obtained before using a new GOST object
# gost2 = GOST()
# key2 = my_utils.PBKDF2("GOST is the best algorithm", salt)[0]
# gost2.set_key(key2)
# iv2 = my_utils.leading_zeros_hex(gost.get_iv())
# gost2.set_iv(my_utils.hex_to_bin_mult_64(iv2))
# gost2.set_encrypted_msg(my_utils.hex_to_bin_mult_64(ciphertext))
#
# print("Decrypted from scratch: ", my_utils.bytes_to_string(gost2.decrypt()))

gost = GOST()
go_on = True
error_message = "An error occurred while processing the data."
while go_on:
    enc_or_dec = input("Type E to encrypt a message, D to decrypt one: ")
    if enc_or_dec.upper() == "E":
        message = input("Type the MESSAGE you want to encrypt: ")
        password = input("Type the PASSWORD you want to use: ")
        salt_or_no = input("Do you want to choose the salt? (Y/N) ")
        key, salt = None, None
        if salt_or_no.upper() == "Y":
            salt = input("Type the salt: ")
            key = my_utils.PBKDF2(password, salt)[0]
        else:
            key, salt = my_utils.PBKDF2(password, salt)
        time_b = time.time()
        gost.set_message(my_utils.string_to_bytes(message))
        gost.set_key(key)
        gost.set_iv()
        ciphertext = my_utils.leading_zeros_hex(gost.encrypt())
        time_e = time.time()
        print("Data summary")
        print("Message: ", message)
        print("Password: ", password)
        print("Salt: ", salt)
        print("IV (hex): ", my_utils.leading_zeros_hex(gost.get_iv()))
        print("\nEncrypted message (hex): ", ciphertext, '\n')
        print("Elapsed encryption time (s): ", time_e - time_b)
        file_or_no = input("Do you want to write the result to a file? (Y/N) ")
        if file_or_no.upper() == "Y":
            file_path = input("Type the full path to the file: ")
            if input("Do you want salt to be on the file? (Y/N) ").upper() == "Y":
                my_utils.write_to_file(file_path, ciphertext, my_utils.leading_zeros_hex(gost.get_iv()), salt)
            else:
                my_utils.write_to_file(file_path, ciphertext, my_utils.leading_zeros_hex(gost.get_iv()))
    else:
        ciphertext = input("Type the ciphertext: ")
        password = input("Type the PASSWORD you want to use: ")
        salt = input("Type the salt: ")
        iv = input("Type the IV: ")
        time_b = time.time()
        key, salt = my_utils.PBKDF2(password, salt)
        gost.set_encrypted_msg(my_utils.hex_to_bin_mult_64(ciphertext))
        gost.set_key(key)
        gost.set_iv(my_utils.hex_to_bin_mult_64(iv))
        plaintext = my_utils.bytes_to_string(gost.decrypt())
        time_e = time.time()
        print("Data summary")
        print("Ciphertext (hex): ", ciphertext)
        print("Password: ", password)
        print("Salt: ", salt)
        print("IV (hex): ", iv)
        print("\nDecrypted message: ", plaintext or error_message, '\n')
        print("Elapsed decryption time (s): ", time_e - time_b)
    go_on = input("Continue? (Y/N) ").upper() == "Y"
