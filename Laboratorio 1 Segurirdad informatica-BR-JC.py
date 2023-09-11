import requests
import json

# Laboratorio 1 Seguridad Informatica
# Bastian Rivas - Jose Castillo 

def cifrado(msj, rotnum1, rotnum2, clave):
    rot1 = rot_n(msj, rotnum1)
    vigenere_cipher = vigenere(rot1, clave, True)
    rot2 = rot_n(vigenere_cipher, rotnum2)
    return rot2

def descifrado(msj, rotnum1, rotnum2, clave):
    rot1 = rot_n(msj, rotnum1)
    vigenere_cipher = vigenere(rot1, clave, False)
    rot2 = rot_n(vigenere_cipher, rotnum2)
    return rot2


def rot_n(text, n):
    result = ''
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            result += chr((ord(char) - shift + n) % 26 + shift)
        else:
            result += char
    return result

def vigenere(text, key, encrypt):
    result = ''
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            key_char = key[i % key_len]
            key_shift = ord(key_char) - shift
            if encrypt:
                result += chr((ord(char) - shift + key_shift) % 26 + shift)
            else:
                result += chr((ord(char) - shift - key_shift) % 26 + shift)
        else:
            result += char
    return result


# DESAFIO 1

msj = "llamada a ana"
msj_cifrado = cifrado(msj,15,7,"cvqnoteshrwnszhhksorbqcoas")
print("Este es el mensaje crifrado:", msj_cifrado)

headers = {
    'Content-Type': 'text/plain',
}

mensaje = '{"msg":"cifrado(mensaje)"}'
data = mensaje.replace('cifrado(mensaje)', msj_cifrado)

response = requests.post('http://finis.malba.cl/SendMsg', headers=headers, data=data)

print("Este es el mensaje recibido del link:", response.text)

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------
# DESAFIO 2


headers = {
    'Content-Type': 'text/plain',
}

response2 = requests.get('http://finis.malba.cl/GetMsg', headers=headers)

print("Este es el mensaje recibido del link:", response2.text)

msj_der = response2.text

mensaje_json = json.loads(msj_der)

mensaje_deseado = mensaje_json['msg']

msj_des = descifrado((mensaje_deseado),-7,-15,"aobkqolrzsrigpknkufezioer")
print("Mensaje recibido descifrado:", msj_des)
