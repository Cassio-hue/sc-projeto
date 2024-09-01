# key expansion https://youtu.be/0RxLUf4fxs8
# aes https://youtu.be/k51UrbJjUyw?si=5F22fYGjr4zqJ_ji
# aes https://youtu.be/O4xNJsjtN6E?si=-eMKzNbh83hri7YF
# aes https://youtu.be/C4ATDMIz5wc?si=dm4TQEEYCwTNmXNG
# blog implements aes https://medium.com/wearesinch/building-aes-128-from-the-ground-up-with-python-8122af44ebf9

from constants import aes_sbox, reverse_aes_sbox
global PAD_MESSAGE

# Divide o conteudo em matriz 4x4 blocos de 16 bytes
# content: conteudo a ser dividido
# return: lista de blocos matriz 4x4
def break_in_grids_of_16(content):
    result = []
    for i in range(len(content) // 16):
        b = content[i * 16: i * 16 + 16]
        grid = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                grid[i].append(b[i + j * 4])
        result.append(grid)

    return result


# Procura um byte na S-Box
# byte: byte a ser procurado
# return: byte encontrado
def lookup(byte):
    x = byte >> 4
    y = byte & 15

    return aes_sbox[x][y]


# Inverso da função de lookup
# byte: byte a ser procurado
# return: byte encontrado
def reverse_lookup(byte):
    x = byte >> 4
    y = byte & 15

    return reverse_aes_sbox[x][y]


# Rotaciona uma linha para a esquerda, ou seja, move os elementos da esquerda para a direita
# row: linha a ser rotacionada
# n: número de posições a serem rotacionadas
# return: linha rotacionada
def rotate_row_left(row, n=1):
    return row[n:] + row[:n]


# Expande a chave para o número de rodadas
# key: chave de 16 bytes
# rounds: número de rodadas
# return: matriz da chave expandida
def expand_key(key, rounds):

    rcon = [[1, 0, 0, 0]]

    for _ in range(1, rounds):
        next_value = [rcon[-1][0] * 2, 0, 0, 0]
        if next_value[0] > 0x80:
            next_value[0] ^= 0x11b
        rcon.append(next_value)

    key_grid = break_in_grids_of_16(key)[0]

    for round in range(rounds):
        last_column = [row[-1] for row in key_grid]
        last_column_rotate = rotate_row_left(last_column)
        last_column_sbox = [lookup(b) for b in last_column_rotate]
        last_column_rcon = [last_column_sbox[i] ^ rcon[round][i] for i in range(len(last_column_rotate))]

        for r in range(4):
            key_grid[r] += bytes([last_column_rcon[r] ^ key_grid[r][round*4]])

        for i in range(len(key_grid)):
            for j in range(1, 4):
                key_grid[i] += bytes([key_grid[i][round*4+j] ^ key_grid[i][round*4+j+3]])

    return key_grid


# Multiplica por 2 um byte
# byte: byte a ser multiplicado
# return: byte multiplicado
def multiply_by_2(byte):
    result = byte << 1
    result &= 0xff
    if (byte & 128) != 0:
        result = result ^ 0x1b

    return result


# Multiplica por 3 um byte
# byte: byte a ser multiplicado
# return: byte multiplicado
def multiply_by_3(byte):
    return multiply_by_2(byte) ^ byte


# Mistura as colunas do bloco de texto
# grid: Matriz 4x4 com blocos de texto de 16 bytes
# return: Nova grid 4x4 com blocos de texto de 16 bytes
def mix_columns(grid):
    new_grid = [[], [], [], []]
    for i in range(4):
        col = [grid[j][i] for j in range(4)]
        col = mix_column(col)
        for i in range(4):
            new_grid[i].append(col[i])

    return new_grid


# Mistrura na coluna para fornecer confusão e difusão nos dados
# column: coluna de 4 bytes
# return: coluna de 4 bytes
def mix_column(column):
    return [
        multiply_by_2(column[0]) ^ multiply_by_3(column[1]) ^ column[2] ^ column[3],
        multiply_by_2(column[1]) ^ multiply_by_3(column[2]) ^ column[3] ^ column[0],
        multiply_by_2(column[2]) ^ multiply_by_3(column[3]) ^ column[0] ^ column[1],
        multiply_by_2(column[3]) ^ multiply_by_3(column[0]) ^ column[1] ^ column[2],
    ]


# Aplica a chave de rodada ao bloco de texto
# Realiza operação XOR entre dois blocos de 16 bytes
# block_grid: bloco de 16 bytes
# key_grid: chave de 16 bytes
# return: bloco de 16 bytes
def add_sub_key(block_grid, key_grid):
    result = []

    for i in range(4):
        result.append([])
        for j in range(4):
            result[-1].append(block_grid[i][j] ^ key_grid[i][j])

    return result


# Extri partes específicas da chave expandida para uma determinada rodada
# O número de elementos extraídos depende do round
# expanded_key: chave expandida
# round: rodada a extrair
# return: lista de 4 bytes
def extract_key_for_round(expanded_key, round):
    result = []

    for row in expanded_key:
        temp = row[round*4: round*4 + 4]
        result.append(temp)

    return result


# A função realiza cifragem AES
# key: chave de 16 bytes para cifrar
# plaintext: dados a serem cifrados
# return: texto cifrado
def aes_encrypt(key, plaintext):
    global PAD_MESSAGE
    PAD_MESSAGE = bytes(16 - len(plaintext) % 16)

    if len(PAD_MESSAGE) != 16:
        plaintext += PAD_MESSAGE

    grids = break_in_grids_of_16(plaintext)

    expanded_key = expand_key(key, 11)

    temp_grids = []
    round_key = extract_key_for_round(expanded_key, 0)

    for grid in grids:
        temp_grids.append(add_sub_key(grid, round_key))

    grids = temp_grids

    for round in range(1, 10):
        temp_grids = []

        for grid in grids:
            sub_bytes = [[lookup(val) for val in row] for row in grid]
            shift_rows = [rotate_row_left(sub_bytes[i], i) for i in range(4)]
            mix_column = mix_columns(shift_rows)
            round_key = extract_key_for_round(expanded_key, round)
            sub_key = add_sub_key(mix_column, round_key)
            temp_grids.append(sub_key)

        grids = temp_grids

    temp_grids = []
    round_key = extract_key_for_round(expanded_key, 10)

    for grid in grids:
        sub_bytes = [[lookup(val) for val in row] for row in grid]
        shift_rows = [rotate_row_left(sub_bytes[i], i) for i in range(4)]
        sub_key = add_sub_key(shift_rows, round_key)
        temp_grids.append(sub_key)

    grids = temp_grids

    int_stream = []

    for grid in grids:
        for column in range(4):
            for row in range(4):
                int_stream.append(grid[row][column])

    return bytes(int_stream)


# A função realiza decifragem AES
# key: chave de 16 bytes para decifrar
# cipher: cifra para ser decifrada
# return: texto decifrado
def aes_decrypt(key, cipher):

    grids = break_in_grids_of_16(cipher)
    expanded_key = expand_key(key, 11)
    temp_grids = []
    round_key = extract_key_for_round(expanded_key, 10)

    temp_grids = []

    for grid in grids:

        sub_key = add_sub_key(grid, round_key)
        shift_rows = [rotate_row_left(
            sub_key[i], -1 * i) for i in range(4)]
        sub_bytes = [[reverse_lookup(val) for val in row]
                          for row in shift_rows]
        temp_grids.append(sub_bytes)

    grids = temp_grids

    for round in range(9, 0, -1):
        temp_grids = []

        for grid in grids:
            round_key = extract_key_for_round(expanded_key, round)
            sub_key = add_sub_key(grid, round_key)

            mix_column = mix_columns(sub_key)
            mix_column = mix_columns(mix_column)
            mix_column = mix_columns(mix_column)
            shift_rows = [rotate_row_left(mix_column[i], -1 * i) for i in range(4)]
            sub_bytes  = [[reverse_lookup(val) for val in row] for row in shift_rows]
            temp_grids.append(sub_bytes)

        grids = temp_grids
        temp_grids = []

    round_key = extract_key_for_round(expanded_key, 0)

    for grid in grids:
        temp_grids.append(add_sub_key(grid, round_key))

    grids = temp_grids

    decrypted_list = []

    for grid in temp_grids:
        for column in range(4):
            for row in range(4):
                decrypted_list.append(grid[row][column])

    decrypted_bytes = bytes(decrypted_list)[:-len(PAD_MESSAGE)]

    return decrypted_bytes


# Função serve para incrementar o contador de acordo com o padrão AES-CTR
# Incrementa o contador
# counter: contador a ser incrementado
# return: contador incrementado
def increment_counter(counter):
    counter = bytearray(counter)
    for i in range(len(counter)-1, -1, -1):
        counter[i] += 1
        if counter[i] <= 255:
            break
        counter[i] = 0

    return bytes(counter)


# Realiza o XOR em duas listas de bytes
# a: lista de bytes
# b: lista de bytes
# return: resultado a XOR b
def xor_bytes(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])


# Função para cifrar e decifrar utilizando AES-CTR
# plaintext: texto a ser cifrado
# key: chave de 16 bytes
# nonce: valor único de 16 bytes
# return: texto cifrado ou decifrado
def aes_ctr_encrypt_decrypt(plaintext, key, nonce):
    
    plaintext_bytes = plaintext
    nonce_bytes = nonce.encode()

    blocks = [plaintext_bytes[i:i + 16] for i in range(0, len(plaintext_bytes), 16)]

    counter = nonce_bytes + bytes([0] * 8)

    result = []

    for block in blocks:
        encrypted_counter = aes_encrypt(key, counter)
        cipher_block = xor_bytes(block, encrypted_counter[:len(block)])
        result.extend(cipher_block)
        counter = increment_counter(counter)

    return bytes(result)


enc_key = '1111111111111111'.encode()

print()
print()
message_aes = 'Olá mundo! Essa mensagem será cifrada e decifrada com o algoritmo AES'
print("AES - Mensagem Original:", message_aes)
print()

encrypted_message_aes = aes_encrypt(enc_key, message_aes.encode())
print("AES - Mensagem Cifrada:", encrypted_message_aes)
print()

decrypted_message_aes = aes_decrypt(enc_key, encrypted_message_aes).decode()
print("AES - Mensagem Decifrada:", decrypted_message_aes)
print()
print("Mensagem Original == Mensagem Decifrada:", message_aes == decrypted_message_aes)

print()
print('= '*30, end='')
print('DIVISÃO ENTRE OS RESULTADOS', end='')
print(' ='*30)
print()

key = "chaveDe16BytesVemAqui".encode()
nonce = "valor_uinico"

message_aes_ctr = "Olá mundo! Essa mensagem será cifrada e decifrada com o algoritmo AES no modo CTR"
print("AES CTR - Mensagem Original:", message_aes_ctr)
print()

encrypted_message_aes_ctr = aes_ctr_encrypt_decrypt(message_aes_ctr.encode(), key, nonce)
print("AES CTR - Mensagem Cifrada:", encrypted_message_aes_ctr)
print()

decrypted_message_aes_ctr = aes_ctr_encrypt_decrypt(encrypted_message_aes_ctr, key, nonce).decode()
print("AES CTR - Mensagem Decifrada:", decrypted_message_aes_ctr)
print()
print("Mensagem Original == Mensagem Decifrada: ", message_aes_ctr == decrypted_message_aes_ctr)
print()
print()