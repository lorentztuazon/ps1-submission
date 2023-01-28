"""
Problem Set 1.1 : Block Ciphers and Key Recovery Security Module
"""

import json
import sys, os, itertools

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *

"""
Problem 1 [100 points]
Let E be a blockcipher  E:{0, 1}^k x {0, 1}^n --> {0, 1}^n
and E_I be its inverse.
Define F: {0, 1}^k+n x {0, 1}^n --> {0, 1}^n as shown below.

Notes:
Sizes in comments are bits, sizes in code are in bytes (bits / 8).
In the code K1\in{0,1}^k and K2,M\in{0,1}^n
"""

def F(K, M):
    """
    Blockcipher F constructed from blockcipher E.

    :param K: blockcipher key
    :param M: plaintext message
    :return: ciphertext
    """
    K1 = K[:k_bytes]
    K2 = K[k_bytes:]

    C = E(K1, xor_strings(K2, M))
    return C

"""
(a) [50 points] Give a 1-query adversary A1 that has advantage
                Adv^kr_F(A1) = 1 and running time O(T_E + k + n).
"""

def A1(fn):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for.

    :param fn: This is the oracle supplied by GameKR, you can call this
    oracle to get an "encryption" of the data you pass into it.
    :return: return the a string that represents a key guess.
    """

    K1 = '\x00' * k_bytes
    M0 = '\x00' * n_bytes
    C0 = fn(M0)
    K2 = E_I(K1,C0)

    return K1+K2

"""
(b) [50 points] Give a 3-query adversary A3 that has advantage Adv^kr_F(A3) = 1
                and running time O(2^k * (T_E + k + n)).
"""

def A3(fn):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for.

    :param fn: This is the oracle supplied by GameKR, you can call this
    oracle to get an "encryption" of the data you pass into it.
    :return: return the a string that represents a key guess.
    """
    # Adversary picks three distinct arbitrary messages as input to oracle fn
    M0 = '\x00' * n_bytes
    M1 = '\xFF' * n_bytes
    M2 = random_string(n_bytes)

    while M0 == M2 or M1 == M2:
        M2 = random_string(n_bytes)

    # Oracle outputs
    C0 = fn(M0)
    C1 = fn(M1)
    C2 = fn(M2)

    # Exhaustive key search algorithm
    for i in range(2**k):
        K1 = int_to_string(i, k_bytes)

        # Rearranged system of linear equations
        K2_0 = xor_strings(E_I(K1,C0), M0)
        K2_1 = xor_strings(E_I(K1,C1), M1)
        K2_2 = xor_strings(E_I(K1,C2), M2)
        
        # If all three K_2 are equivalent, break
        if K2_0 == K2_1 and K2_0 == K2_2:
            break

    return K1+K2_0

"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""

from playcrypt.games.game_kr import GameKR
from playcrypt.simulator.kr_sim import KRSim

if __name__ == '__main__':

    # Arbitrary choices of k, n.
    k = 128
    n = 64
    # Block & key size in bytes.
    k_bytes = k//8
    n_bytes = n//8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g1 = GameKR(1, F, k_bytes+n_bytes, n_bytes)
    s1 = KRSim(g1, A1)
    print("The advantage of your adversary A1 is approximately " + str(s1.compute_advantage(20)))

    # Smaller choices of k, n.
    k = 8
    n = 64
    k_bytes = k//8
    n_bytes = n//8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g3 = GameKR(3, F, k_bytes+n_bytes, n_bytes)
    s3 = KRSim(g3, A3)
    print("The advantage of your adversary A3 is approximately " + str(s3.compute_advantage(20)))
