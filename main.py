from des import DesKey


# choose which blocks to attack (delete or switch)
def substitution_ecb(message, change_blocks=[], delete_blocks=[]):
    message = bytearray(message)

    if len(delete_blocks) > 0:
        for delete in delete_blocks:
            message.pop(delete)

    for ((a, b), (c, d)) in change_blocks:
        message[a:b], message[c:d] = message[c:d], message[a:b]

    return bytes(message)


def print_results(plain_text, swap_text, delete_text):
    print("====================")
    print("Plain text:")
    print("====================")
    print(bank_transfer)
    print("====================")
    print("Change decrypted message:")
    print("====================")
    print(plain_text_ecb_swap.decode())
    print("====================")
    print("Delete decrypted message:")
    print("====================")
    print(plain_text_ecb_delete)

# the fields in the bank transfer are 8 bytes long
# 0. sending bank's ID,
# 1. account number at sending bank,
# 2. receiving bank's ID,
# 3. account number at receiving bank,
# 4. amount transferred
bank_transfer = b"BANK1234ACCT5678BANK5678ACCT123400010000"

key0 = DesKey(b"some key")                  # for DES

encrypted_ecb = key0.encrypt(bank_transfer)

swap_message_ecb = substitution_ecb(encrypted_ecb, change_blocks=[((0,8), (8,16))])
plain_text_ecb_swap = key0.decrypt(swap_message_ecb)

delete_message_ecb = substitution_ecb(encrypted_ecb, delete_blocks=[0,1,2,4,5,6,7,8])
plain_text_ecb_delete = key0.decrypt(delete_message_ecb)

print_results(bank_transfer, plain_text_ecb_swap, plain_text_ecb_delete)


def substitution_cbc(original_message, modified_message=b"", change_block=0, delete_blocks=[]):
    original_message = bytearray(original_message)
    if len(delete_blocks) > 0:
        for delete in delete_blocks:
            original_message.pop(delete)
        return bytes(original_message)
    else:
        offset = change_block * 8
        before_block = original_message[offset - 8: offset]
        after_block = original_message[offset:]
        # find what to change
        xor_diff = bytes([a ^ b for a, b in zip(original_message, modified_message)])
        # make the change in the previous block
        modified_before_block = bytes([a ^ b for a, b in zip(before_block, xor_diff)])

        return bytes(original_message[:offset - 8] + modified_before_block + after_block)


encrypted_cbc = key0.encrypt(bank_transfer, initial=0)

bank_transfer_mod = b"BANK1234ACCT5679BANK5678ACCT123400010000"
changed_encr_message_cbc = key0.encrypt(bank_transfer_mod, initial=0)

changed_message_cbc = substitution_cbc(encrypted_cbc, changed_encr_message_cbc, change_block=3)
plain_text_cbc_change = key0.decrypt(changed_message_cbc)

delete_message_cbc = substitution_cbc(encrypted_cbc, delete_blocks=[0,1,2,4,5,6,7,8])
plain_text_cbc_delete = key0.decrypt(delete_message_cbc)

print_results(bank_transfer, plain_text_cbc_change, plain_text_cbc_delete)
