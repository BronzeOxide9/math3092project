import numpy as np
import matplotlib.pyplot as plt
import scipy as sp
import secrets

def calculate_entropy(byte_data):
    if isinstance(byte_data, bytes):
        byte_data = np.frombuffer(byte_data, dtype=np.uint8)
    counts = np.bincount(byte_data, minlength=256)
    probabilities = counts / counts.sum()
    return sp.stats.entropy(probabilities, base=2) 

num_samples = 1
sample_size = 1000

entropy_secrets = []
entropy_numpy_unbiased = []
entropy_numpy_biased = []

for i in range(num_samples):
    
    secret_bytes = secrets.token_bytes(sample_size)
    entropy_secrets.append(calculate_entropy(secret_bytes))
    
    numpy_bytes_unbiased = np.random.randint(0, 256, sample_size, dtype=np.uint8)
    entropy_numpy_unbiased.append(calculate_entropy(numpy_bytes_unbiased))

    numpy_bytes_biased = np.concatenate((np.random.randint(0, 128, size=sample_size//2),
                              np.random.randint(0, 256, size=(sample_size - sample_size//2))))
    entropy_numpy_biased.append(calculate_entropy(numpy_bytes_biased))
    
plt.figure(figsize=(16, 8))
plt.plot(entropy_secrets, label='Secrets Module', color='blue')
plt.plot(entropy_numpy_unbiased, label='Numpy PRNG Unbiased', color='green')
plt.plot(entropy_numpy_biased, label='Numpy PRNG Biased', color='red')
plt.ylabel('Entropy (bits)')
plt.xlabel('Sample Number')
plt.title('Entropy Comparison: Secrets vs. Numpy PRNG (Unbiased/Biased)')
plt.legend()
plt.ylim(7.45, 7.9) 
plt.show()

