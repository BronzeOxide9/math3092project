import ctypes
import serial
import time

libcurve25519 = ctypes.CDLL('./libcurve25519.so')

libcurve25519.generate_keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
libcurve25519.x25519.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
libcurve25519.x25519.restype = None

def to_ctypes_array(bytes_obj):
    return (ctypes.c_ubyte * len(bytes_obj))(*bytes_obj)

ser = serial.Serial('/dev/cu.usbmodem1401', 9600)
time.sleep(2) 

B_public = (ctypes.c_ubyte * 32)()
B_private = (ctypes.c_ubyte * 32)()
libcurve25519.generate_keypair(B_public, B_private)

A_public_bytes = ser.read(32)
A_public = to_ctypes_array(A_public_bytes)

ser.write(bytes(B_public))

shared_secret = (ctypes.c_ubyte * 32)()
libcurve25519.x25519(shared_secret, A_public, B_private)

shared_secret_bytes = bytes(bytearray(shared_secret))
print("The key is:", shared_secret_bytes.hex())

ser.close()
