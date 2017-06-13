module Crypto where

import Data.Char

import Prelude hiding (gcd)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

gcd :: Int -> Int -> Int
gcd m n
    | n==0      =m
    | otherwise =gcd n (m `mod` n)

phi :: Int -> Int
phi m = length [x|x<-[1 .. m], gcd m x ==1]

--
-- Calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
-- such that au + bv = d
--
extendedGCD :: Int -> Int -> ((Int, Int), Int)
extendedGCD a b
     | b==0      =((1,0),a)
     | otherwise =((v',u'-(a `div` b)*v'),d)
                       where ((u',v'),d)= extendedGCD b (a `mod` b)



-- Inverse of a modulo m
inverse :: Int -> Int -> Int
inverse a m
    | gcd a m /=1  = error "no inverse"
    | otherwise    = u `mod` m
                where ((u,v),1)=extendedGCD a m



-- Calculates (a^k mod m)
--
modPow :: Int -> Int -> Int -> Int
modPow a k m
    | m==1           =0
    | k==0           =1
    | k==1           =a `mod` m
    | k `mod` 2 == 0 = modPow ((a `mod` m)^2 `mod` m) (k `div` 2) m
    | k `mod` 2 == 1 = (a `mod` m)*(modPow ((a `mod` m)^2 `mod` m) (k `div` 2) m) `mod`m

-- Returns the smallest integer that is coprime with x

smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf x
   = coPrimes x 2
   where
      coPrimes :: Int -> Int -> Int
      coPrimes z y
        |gcd z y ==1 = y
        |otherwise   = coPrimes z (y+1)

-- Generates keys pairs (public, private) = ((e, n), (d, n))
-- given two "large" distinct primes, p and q
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q
   = ((e,n),(d,n))
   where
      n= p*q
      e= smallestCoPrimeOf ((p-1)*(q-1))
      d= inverse e ((p-1)*(q-1))


--RSA encryption/decryption; (e, n) is the public key

rsaEncrypt :: Int -> (Int, Int) -> Int
rsaEncrypt m (e, n) = modPow m e n

rsaDecrypt :: Int -> (Int, Int) -> Int
rsaDecrypt c (d, n) = modPow c d n

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
toInt :: Char -> Int
toInt a = ord a - ord 'a'

-- Returns the n^th letter
toChar :: Int -> Char
toChar n = chr (n + ord 'a')

-- "adds" two letters
add :: Char -> Char -> Char
add a b = toChar ((toInt a + toInt b)`mod` ( ord 'z' - ord 'a' + 1))

-- "substracts" two letters
substract :: Char -> Char -> Char
substract a b = toChar ((toInt a - toInt b)`mod` ( ord 'z' - ord 'a' + 1))

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
--
ecbEncrypt :: Char -> String -> String
ecbEncrypt key m
   |m==[]     = []
   |otherwise = ((add key x) : ecbEncrypt key xs)
    where
       (x:xs)=m

ecbDecrypt :: Char -> String -> String
ecbDecrypt key m
   |m==[]     = []
   |otherwise = ((substract x key) : ecbDecrypt key xs)
    where
       (x:xs)=m


-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string
--
cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt key iv m
    = cbcEncrypt' key iv m
    where
       cbcEncrypt' key iv m
          | null m = []
          | otherwise = x : cbcEncrypt' key x xs
          where
             x = add key (add iv (head m))
             xs = tail m




cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt key iv m
   = cbcDecrypt' key iv m
   where
      cbcDecrypt' key iv m
        | null m = []
        | otherwise = x : cbcDecrypt' key (head m) xs
        where
           x = substract (substract (head m) iv) key
           xs = tail m
