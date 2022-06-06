# Summary
Suspected Fin7 JSSLoader packed with previously unseen crypter. Interestingly, unlike most crypters which decrypt or extract an entire embedded payload at once, this crypter actually on the fly decrypts each function, calls it, then reencrypts it so that there is never a complete payload sitting in memory that can be dumped. 

Attack flow:
    Quickbooks themed phish with link -> WSF (WINGKNIGHT) payload -> JSSLoader/BIRDWATCH

# Initialization
The malware starts off by parsing an array of encrypted function lengths that are located relative to EIP. By starting with a hardcoded addresss for the first function, it keeps adding these lengths in order to calculate the address of the next encrypted function.

It then xor decrypts the "wrapper" function. All further function calls are performed using this wrapper function, which accepts a function number, decrypts it, calls it, then reencrypts it:
![Wrapper Function](img/wrapper.png)



