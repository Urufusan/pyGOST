import secrets

# TODO: FINISH OTHER MODES

def shift_11(msg_bin: int) -> int:
    mask = (1 << 32) - 1  # Mask to ensure 32-bit result
    return ((msg_bin << 11) & mask) | (msg_bin >> (32 - 11))

class GOST:
    BLOCK_LEN = 64
    KEY_LEN = 256
    ECB, CBC, OFB, CFB, CTR = "ECB", "CBC", "OFB", "CFB", "CTR"

    SUB_BOXES = [
        [0xC, 4, 6, 2, 0xA, 5, 0xB, 9, 0xE, 8, 0xD, 7, 0, 3, 0xF, 1],
        [6, 8, 2, 3, 9, 0xA, 5, 0xC, 1, 0xE, 4, 7, 0xB, 0xD, 0, 0xF],
        [0xB, 3, 5, 8, 2, 0xF, 0xA, 0xD, 0xE, 1, 7, 4, 0xC, 9, 6, 0],
        [0xC, 8, 2, 1, 0xD, 4, 0xF, 6, 7, 0, 0xA, 5, 3, 0xE, 9, 0xB],
        [7, 0xF, 5, 0xA, 8, 1, 6, 0xD, 0, 9, 3, 0xE, 0xB, 4, 2, 0xC],
        [5, 0xD, 0xF, 6, 9, 2, 0xC, 0xA, 0xB, 7, 8, 1, 4, 3, 0xE, 0],
        [8, 0xE, 2, 5, 6, 9, 1, 0xC, 0xF, 4, 0xB, 0, 0xD, 0xA, 3, 7],
        [1, 7, 0xE, 0xD, 0, 5, 8, 3, 4, 0xF, 0xA, 6, 9, 0xC, 0xB, 2],
    ]

    def __init__(self):
        self.message = None
        self.key = None
        self.sub_keys = []
        self.encrypted = None
        self.decrypted = None
        self.iv = None
        self.operation_mode = self.CBC

    def set_message(self, message: bytes):
        self.message = self.pad_message(message)

    def pad_message(self, message: bytes) -> bytes:
        pad_len = (self.BLOCK_LEN - len(message) % self.BLOCK_LEN) % self.BLOCK_LEN
        return message.ljust(len(message) + pad_len, b'\x00')

    def set_key(self, key: bytes):
        if len(key) * 8 != self.KEY_LEN:
            raise ValueError("Key length must be 256 bits.")
        self.key = key
        self.sub_keys = [int.from_bytes(key[i * 4:(i + 1) * 4], 'big') for i in range(8)]

    def init_iv(self):
        self.iv = secrets.randbits(self.BLOCK_LEN)

    def encrypt_block(self, message: bytes) -> bytes:
        if len(message) * 8 != self.BLOCK_LEN:
            raise ValueError("Block length must be 64 bits.")
        msg_hi = int.from_bytes(message[:4], 'big')
        msg_lo = int.from_bytes(message[4:], 'big')
        for i in range(24):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i % 8])
        for i in range(8, 0, -1):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i - 1])
        return msg_lo.to_bytes(4, 'big') + msg_hi.to_bytes(4, 'big')

    def f_round(self, msg_hi: int, msg_lo: int, sub_key: int) -> tuple[int, int]:
        temp = msg_lo
        modulo2add = (msg_lo + sub_key) % (2 ** 32)
        pass_s_box = self.s_box_half_block_in(modulo2add)
        shifted = shift_11(pass_s_box)
        msg_lo = shifted ^ msg_hi
        return temp, msg_lo

    def s_box_half_block_in(self, half_block: int) -> int:
        result = 0
        for i in range(8):
            result |= self.SUB_BOXES[i][(half_block >> (i * 4)) & 0xF] << (i * 4)
        return result

    def encrypt(self):
        if self.iv is None:
            self.init_iv()
        messages = [self.message[i * 8: (i + 1) * 8] for i in range(len(self.message) // 8)]
        curr_iv = self.iv.to_bytes(8, 'big')
        encrypted = []
        for message in messages:
            if self.operation_mode == self.CBC:
                applied_mask = int.from_bytes(message, 'big') ^ int.from_bytes(curr_iv, 'big')
                curr_iv = self.encrypt_block(applied_mask.to_bytes(8, 'big'))
                encrypted.append(curr_iv)
            # TODO: FINISH OTHER MODES
        self.encrypted = b''.join(encrypted)
        return self.encrypted

    def decrypt(self):
        if self.iv is None:
            raise ValueError("IV must be set for decryption.")
        messages = [self.encrypted[i * 8: (i + 1) * 8] for i in range(len(self.encrypted) // 8)]
        curr_iv = self.iv.to_bytes(8, 'big')
        decrypted = []
        for message in messages:
            if self.operation_mode == self.CBC:
                dec_block = self.decrypt_block(message)
                applied_mask = int.from_bytes(dec_block, 'big') ^ int.from_bytes(curr_iv, 'big')
                curr_iv = message
                decrypted.append(applied_mask.to_bytes(8, 'big'))
            # TODO: FINISH OTHER MODES
        self.decrypted = b''.join(decrypted)
        return self.decrypted

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) * 8 != self.BLOCK_LEN:
            raise ValueError("Block length must be 64 bits.")
        msg_hi = int.from_bytes(ciphertext[:4], 'big')
        msg_lo = int.from_bytes(ciphertext[4:], 'big')
        for i in range(8):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[i])
        for i in range(24):
            msg_hi, msg_lo = self.f_round(msg_hi, msg_lo, self.sub_keys[7 - (i % 8)])
        return msg_lo.to_bytes(4, 'big') + msg_hi.to_bytes(4, 'big')

if __name__ == "__main__":
    # * Example usage:
    gost = GOST()
    gost.set_key(bytes.fromhex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'))
    gost.set_message(b'HelloWorld')
    encrypted_message = gost.encrypt()
    decrypted_message = gost.decrypt()
    print(f"Encrypted: {encrypted_message.hex()}")
    print(f"Decrypted: {decrypted_message.decode()}")