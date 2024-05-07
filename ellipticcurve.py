import matplotlib.pyplot as plt

A = -4
B = 5
p = 29  

def elliptic_curve(x, A, B, p):
    return (x**3 + A*x + B) % p

def has_square_root(y_squared, p):
    # Fermat's Little Theorem to check for square root
    # A number has a square root mod p if y_squared^((p-1)/2) cong. to 1 mod p
    return pow(y_squared, (p - 1) // 2, p) == 1

def inverse_mod(a, m):
    return pow(a, m-2, m)

def point_addition(P, Q, A, p):
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2 and y1 == y2: 
        lam_numerator = 3*x1**2 + A
        lam_denominator = 2*y1
    else:  
        lam_numerator = y2 - y1
        lam_denominator = x2 - x1
    
    
    lam_denominator_inv = inverse_mod(lam_denominator, p)
    lam = (lam_numerator * lam_denominator_inv) % p
    
    x3 = (lam**2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    
    return x3, y3

P = (2, 18)
Q = (17, 23)
R_minus = point_addition(P, Q, A, p) 
R = (R_minus[0], p - R_minus[1]) 
            
curve_points = []

for x in range(p):
    y_squared = elliptic_curve(x, A, B, p)
    if has_square_root(y_squared, p):
        for y in range(p):
            if (y**2) % p == y_squared:
                curve_points.append((x, y))
                

             
fig, ax = plt.subplots(1, 2, figsize=(16, 8))

ax[0].scatter(*zip(*curve_points), color='blue')
ax[0].set_title('Elliptic Curve $y^2 = x^3 - 4x + 5$ over $\mathbb{F}_{29}$')
ax[0].set_xlabel('$x$')
ax[0].set_ylabel('$y$')
ax[1].scatter(*zip(*curve_points), color='blue')
ax[1].scatter(*P, color='red', label='P=(2,18)')
ax[1].scatter(*Q, color='green', label='Q  = (17, 23)')
ax[1].scatter(*R, color='magenta', label=r'$R = (23, 25)$')
ax[1].scatter(*R_minus, color='cyan', label=r'$-R = (23, 4)$')
line_x = [P[0], Q[0], R[0], R[0], P[0]]
line_y = [P[1], Q[1], R[1], R[1], P[1]] 
ax[1].plot(line_x, line_y, color='black', linestyle='-', label=r'Line through $P, Q, R$')
ax[1].plot([R_minus[0], R[0]], [R_minus[1], R[1]], color='black', linestyle=':', label='Reflection line')
ax[1].set_title('Addition on Elliptic Curve')
ax[1].set_xlabel('$x$')
ax[1].legend()
plt.tight_layout()
plt.savefig("EllipticCurve.pdf")
plt.show()
