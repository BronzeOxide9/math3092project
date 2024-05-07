# MATH3092 Project Code Repository

# Introduction

The C22519 code in this project was adapted from Martin Klepmann's article: https://www.cl.cam.ac.uk/teaching/2122/Crypto/curve25519.pdf

## Installation of C22519 code:

```
git clone https://github.com/BronzeOxide9/math3092project.git
```

```
sudo make
```

### Run C25519 code:

Pick relevant serial port such as `/dev/tty0` in `c25519.py`: 

```
python3 -m c25519.py
```

Alternatively to run the test `C` function:

```
gcc c25519.c -o c25519
./c25519
```
