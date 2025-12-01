def encrypt(text, shift=3):
    result = ""
    for char in text:
        result += chr(ord(char) + shift)
    return result

def decrypt(text, shift=3):
    result = ""
    for char in text:
        result += chr(ord(char) - shift)
    return result
