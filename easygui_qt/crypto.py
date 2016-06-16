#!/usr/bin/env
# -*- coding: utf-8 -*-
# author=KGerring@gmail.com
# date = 6/16/16

import sys, os

try:
	from . import utils
	from . import language_selector
	from . import calendar_widget
	from . import multichoice
	from . import show_text_window
	from . import multifields
	from . import easygui_qt

except:
	import easygui_qt.utils as utils
	import easygui_qt.language_selector as language_selector
	import easygui_qt.calendar_widget as calendar_widget
	import easygui_qt.multichoice
	import easygui_qt.show_text_window
	import easygui_qt.multifields
	import easygui_qt.easygui_qt as easy

from codecs import utf_8_encode, utf_8_decode
from base64 import encodebytes, decodebytes
import json
from collections import OrderedDict

try:
	from Crypto.Cipher import AES
	from Crypto import Random
except ImportError:
	print("These functions require the 'pycrypto' library; "
		"See http://www.pycrypto.org/ or install with 'pip install pycrypto'")
	pass


__all__ =['encode', 'decode', 'mask', 'unmask', 'encrypt', 'decrypt', 'simple_encrypt', 'simple_decrypt', 
'encryption_function', 'secure_get_password', 'secure_get_username_password', 'secure_get_new_password']

def encode(string):
	'''
	Args:
	    string: the utf-8 string to be encoded to bytes

	Returns: the string in bytes
	'''
	return utf_8_encode(string)[0]
def decode(bytes):
	'''
	Args:
	    bytes: the bytestring to be turned back into a string

	Returns: The string
	'''
	return utf_8_decode(bytes)[0]

def mask(s):
	'''
	Args:
	    s: The string to encode to base-64 format.
	Returns: The masked string in base64.
		**Note** that this and the functions `simple_encrypt` and `simple_decrypt` are **NOT** a cipher or a true encryption as it doesn't require a key for
		reverting back and forth. Therefore, use this for non-sensitive data you want to mask to the human eye.
		When masked, there usually is a `\n` newline at the end of the string; it is stripped for a cleaner look but it
		will not affect the unmasked result if left in.
	'''
	return decode(encodebytes(encode(s))).strip()

def unmask(s):
	'''
	Args:
	    s: The string in base-64 format to be turned back into your original string. Use this with `mask`
	    See the warning on security in mask (TL;DR: This function is not protected by a key).
	Returns:
	'''
	return decode(decodebytes(encode(s)))

def encrypt(iterable, key=None):
	'''
	Args:
	    dictionary: The dictionary/str result from the password-functions in this module. It converts the OrderedDictionary
	        to a simple dictionary to allow it to be converted in FULL to a json-string
	        (i.e. o-dict([('a', '1'),('b', '2')]) --> '{"a": "1", "b": "2"}').
	        For values that only pass one string, a temporary dictionary is used for functionality, but is removed on
	        decryption. No pre-formatting is required.
	    key: A string in bytes, 16-characters long. Default is b'easygui password' for simplicity. The key MUST be this
	        length for this algorithm, and the same key is needed to permit decryption (i.e. don't lose/forget it).
	Returns: A string encrypted in Advanced Encryption Standard format from the package `pycrypto`, using the class
		`Crypto.Cipher.AES`.

	Further-Reading:
		http://www.pycrypto.org/
		http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
	'''
	if isinstance(iterable, str):
		message = json.dumps({'temporary_container': iterable})
	else:
		message = json.dumps(dict(iterable))
	key = b'easygui password' if not key else key
	msg_bytes = encode(message)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB, iv)
	msg = iv + cipher.encrypt(msg_bytes)
	print(msg)
	return msg

def decrypt(message, key=None):
	'''
	Args:
	    message: The encrypted message (from `encrypt`).
	    key: The 16-character bytestring used in encrypt, or None if the default was used.
	Returns: The original output from the password-functions in this module. It is returned with the same labels/keys as
		was passed in the original functions. No further processing is needed.
	'''
	key = b'easygui password' if not key else key
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB, iv)
	decrypted= cipher.decrypt(message)[16:]
	decoded= json.loads(decode(decrypted))
	if 'temporary_container' in decoded:
		return decoded.get('temporary_container', decoded)
	return OrderedDict(decoded)

def simple_encrypt(iterable):
	'''
	Args:
	    dictionary: The data from the password-functions in easygui_qt. This uses the `mask` function and provides a
	        built-in method in case pycrypto is not installed or high-security is not needed.
	Returns: A masked string to obscure the result. Use with `simple decrypt` to get the original input.
	'''
	if isinstance(iterable, str):
		message = json.dumps({'temporary_container':iterable})
	else:
		message = json.dumps(dict(iterable))
	masked =mask(message)
	print(masked)
	return masked

def simple_decrypt(message):
	'''
	Args:
	    message: The masked message from `simple encrypt` in base-64 format. See security-warning in `mask` (TL;DR: Don't
	    use this for sensitive data; can be unmasked by anyone using this function).
	Returns: The original data (with OrderedDict container) passed into `simple encrypt.` No further processing is necessary.

	'''
	decrypted = json.loads(unmask(message))
	if 'temporary_container' in decrypted:
		return decrypted.get('temporary_container', decrypted)
	return OrderedDict(decrypted)

def encryption_function(func=None, AES_encryption=False):
	'''
	Args:
	    func: the function you want to encrypt. Intended inputs are:
	        `easygui_qt.get_password.`, `easygui_qt.get_username_password.`
	        or `easygui_qt.get_new_password.` Default is 'get_password'
	    AES_encryption: boolean; default=False. Whether or not to use AES encryption/decryption or the simple
	        base-64 masking function. Use 'True' for AES (requires pycrypto).

	Returns: The functions themselves to
		(1) (A) Execute the original easygui-qt function.
			(B) Pass the result to the encryptor.
		(2) Using the result from (1B), get the answer unencrypted.

		Use like:
		>>> import easygui_qt as easy
		>>> hide, unhide = encryption_function(easy.get_new_password, True)

		>>> hidden_result = hide(title='Title, labels=('old','new','check'))
		>>> print("Encrypted result: :", hidden_result)

		>>> revealed_result = unhide(hidden_result)
		>>> print("Original result:", revealed_result)

	'''
	def encrypt_result(func=func, AES_encryption=AES_encryption,*args, **kwargs):
		'''Quick briefing; See its parent `encryption_function` for details and examples.
		Args:
		    func: One of `easygui_qt.get_password.`, `easygui_qt.get_username_password.` or `easygui_qt.get_new_password.`
		        Hasn't been tested with others.
		    *args,**kwargs: Used if amending the default paramaters of the `func` (optional)
		Returns: The encrypted result.

		***USED WITH its sibling `decrypt_result` to get the original answer.
		'''
		from easygui_qt import get_password, get_username_password, get_new_password
		#import all three for simplicity
		f = func(*args, **kwargs)
		if AES_encryption:
			encrypted = encrypt(f)
		else:
			encrypted = simple_encrypt(f)
		return encrypted

	def decrypt_result(msg, AES_encryption=AES_encryption):
		''' Quick briefing; See its parent `encryption_function` for details and examples.
		Args:
		    msg: The encrypted message from `encrypt_result.`
		Returns: The original user-input.
		'''
		if AES_encryption:
			decrypted = decrypt(msg)
		else:
			decrypted = simple_decrypt(msg)
		return decrypted

	return encrypt_result, decrypt_result


def secure_get_password(AES_encryption=True):
	from easygui_qt import get_password
	return encryption_function(func=get_password, AES_encryption=AES_encryption)

def secure_get_username_password(AES_encryption=True):
	from easygui_qt import get_username_password
	return encryption_function(func=get_username_password, AES_encryption=AES_encryption)

def secure_get_new_password(AES_encryption=True):
	from easygui_qt import get_new_password
	return encryption_function(func=get_new_password, AES_encryption=AES_encryption)

if __name__ == '__main__':
	from easygui_qt import crypto
	from easygui import get_new_password, get_username_password, get_password
	magenta = '\x1b[35m{}\x1b[0m' #for pretty_display
	blue= '\x1b[34m{}\x1b[0m'
	from easygui_qt import *
	pass_enc,    pass_dec    = crypto.secure_get_password(True)
	upass_enc,   upass_dec   = crypto.secure_get_username_password(False)
	newpass_enc, newpass_dec = crypto.secure_get_new_password()

	print(blue.format('AES Password Encryption/Decryption'))
	password = pass_enc()
	ans_a = pass_dec(password)
	print(magenta.format('Decrypted Input:'), ans_a)
	print('#'*30)
	print()

	print(blue.format('Base-64 Username-Password Encryption/Decryption'))
	userpass = upass_enc()
	ans_b = upass_dec(userpass)
	print(magenta.format('Decrypted Input:'),ans_b)
	print('#' * 30)
	print()

	print(blue.format('AES Password-Update Encryption/Decryption with unique parameters'))
	newpass = newpass_enc(labels=('old','new','confirm'))
	ans_c= newpass_dec(newpass)
	print(magenta.format('Decrypted Input:'), ans_c)








