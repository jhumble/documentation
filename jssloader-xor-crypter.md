# Summary
Suspected Fin7 JSSLoader packed with previously unseen crypter. Interestingly, unlike most crypters which decrypt or extract an entire embedded payload at once, this crypter actually on the fly decrypts each function, calls it, then reencrypts it so that there is never a complete payload sitting in memory that can be dumped. 

Attack flow:
    Quickbooks themed phish with link -> WSF (WINGKNIGHT) payload -> JSSLoader/BIRDWATCH


# Initialization
The malware starts off by parsing an array of encrypted function lengths that are located relative to EIP. By starting with a hardcoded addresss for the first function, it keeps adding these lengths in order to calculate the address of the next encrypted function. This list of function pointes is saved and referenced later by the wrapper function.

It then xor decrypts the "wrapper" function. All further function calls are performed using this wrapper function, which accepts a function number, decrypts it, calls it, then reencrypts it:
![Wrapper Function](img/wrapper.png)

All functions are decrypted with the same xor key. Which seems to be located 0x152 bytes after the last function. 


# Wrapper Function Usage
All further calls in the program look like this: 
![example](img/call_example.png)
Where 0x82 is the index into the array of encrypted function pointers and the other two args are arguments passed onto that function after it is decrypted. 

# Encrypted Strings
The string decryption function in shown and annoted below. strings are accessed similarly to the functions with a function `get_string(*decrypted_string, index)` which will decrypt the appropriate string and copy it to the supplied buffer.

To decrypt, every pair of characters are swapped, then 1 is added the first and 1 is subtracted from the second. If the string length is odd, the last character has 2 subtracted from it.
Decryption is easier to understand with a quick example:
    `BCDEF` => `DAFCD`

```
00405F70 | 53                       | push ebx                                |
00405F71 | 8B4C24 0C                | mov ecx,dword ptr ss:[esp+C]            |
00405F75 | 8B5424 08                | mov edx,dword ptr ss:[esp+8]            |
00405F79 | 8A1A                     | mov bl,byte ptr ds:[edx]                | bl = ciphertext[i]
00405F7B | 84DB                     | test bl,bl                              |
00405F7D | 8BC1                     | mov eax,ecx                             | ecx:"tV`132e-mk"
00405F7F | 74 25                    | je bw4.405FA6                           |
00405F81 | 8BC1                     | mov eax,ecx                             | ecx:"tV`132e-mk"
00405F83 | 8A7A 01                  | mov bh,byte ptr ds:[edx+1]              | bh = ciphertext[i+1]
00405F86 | 84FF                     | test bh,bh                              |
00405F88 | 74 0D                    | je bw4.405F97                           |
00405F8A | FEC7                     | inc bh                                  |
00405F8C | 8838                     | mov byte ptr ds:[eax],bh                | plaintext[i] = ciphertext[i+1] + 1
00405F8E | 40                       | inc eax                                 |
00405F8F | 0FB61A                   | movzx ebx,byte ptr ds:[edx]             |
00405F92 | 42                       | inc edx                                 |
00405F93 | FECB                     | dec bl                                  |
00405F95 | EB 03                    | jmp bw4.405F9A                          |
00405F97 | 80C3 FE                  | add bl,FE                               | if len(ciphertext)%2 !=  0: ciphertext[-1] -= 2
00405F9A | 8818                     | mov byte ptr ds:[eax],bl                | plaintext[i+1] = ciphertext[i] - 1
00405F9C | 40                       | inc eax                                 |
00405F9D | 0FB65A 01                | movzx ebx,byte ptr ds:[edx+1]           |
00405FA1 | 42                       | inc edx                                 |
00405FA2 | 84DB                     | test bl,bl                              |
00405FA4 | 75 DD                    | jne bw4.405F83                          |
00405FA6 | C600 00                  | mov byte ptr ds:[eax],0                 |
00405FA9 | 2BC1                     | sub eax,ecx                             | ecx:"tV`132e-mk"
00405FAB | 5B                       | pop ebx                                 |
00405FAC | C3                       | ret                                     |
```
# Script
I wrote a ![script](https://github.com/jhumble/Unpackers-and-Config-Extractors/blob/master/jssloader/unpack.py) to parse out the encrypted functions, decrypt them, and replace calls to the wrapper function with calls directly to the decrypted functions to simplify analysis.

It will also identify the "encrypted" strings, decrypt them and dump those out. Those strings are accessed similarly to the functions with a function `get_string(*decrypted_string, index)` which will decrypt the appropriate string and copy it to the supplied buffer. 

I'd eventually like to unpack those strings and replace references to `get_string` with direct references to the decrypted strings, but it is more difficult than the function replacements and I don't have it working  yet. 

Example usage/output:
```
python3 ~/tools/Unpackers-and-Config-Extractors/jssloader/unpack.py ~/RE/samples/fin7/2022-05-26/9eef2282daef2970a546afd4607af07f.exe  -vv
2022-06-06 15:33:20,946 - JSSLoader Unpacker - INFO     Processing /Users/jhumble/RE/samples/fin7/2022-05-26/9eef2282daef2970a546afd4607af07f.exe
2022-06-06 15:33:20,970 - JSSLoader Unpacker - INFO     Removing xor function 0x00404E20 from set of functions to decrypt (already decrypted at start)
2022-06-06 15:33:20,971 - JSSLoader Unpacker - INFO     Found call to main. function offset: 0x68 addr: 0x00406440
2022-06-06 15:33:20,971 - JSSLoader Unpacker - CRITICAL main patch: before: b'8bc48928c740043000000050ffd18b4c240889690a83c4106a68ffd1' after: b'e8b55200009090909090909090909090909090909090909090909090'
2022-06-06 15:33:20,971 - JSSLoader Unpacker - CRITICAL Patched call to main
2022-06-06 15:33:20,971 - JSSLoader Unpacker - INFO     xor passphrase: b'6558076622fdd7d9353f4a294aa5e01e6ebcfc21f10fa1244fddefb592e019'
2022-06-06 15:33:20,978 - JSSLoader Unpacker - INFO     Found decryption function 0x00403820
2022-06-06 15:33:20,991 - JSSLoader Unpacker - INFO     Failed to patch 0x00007795: Unable to get rva from addr 0x0000779C
2022-06-06 15:33:20,991 - JSSLoader Unpacker - INFO     Failed to patch 0x000078F9: Unable to get rva from addr 0x00007900
2022-06-06 15:33:20,991 - JSSLoader Unpacker - INFO     Failed to patch 0x00007985: Unable to get rva from addr 0x0000798C
2022-06-06 15:33:20,991 - JSSLoader Unpacker - CRITICAL Dumping unpacked file to /Users/jhumble/RE/samples/fin7/2022-05-26/9eef2282daef2970a546afd4607af07f.exe.unpacked
```
