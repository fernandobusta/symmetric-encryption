# Symmetric Encryption Using Diffie-Hellman Key Agreement

## Modes

This program has three modes

**Mode 1: Hash generation** - the program will run to create the keys used for encryption and save them in the appropriate files. This is an optional step, since values for the keys have been given by default in the files. This mode was implemented for development purposes.

This will generate:

- a new `b` value to replace the default and use it for encryption, saves it in b.txt
- a new `B` value and save it DH.txt

> To run this mode, execute:

```
java Assignment1 Assignment1.class generate > Encryption.txt
```

**Mode 2: Testing** - This mode tests the vaildity of the algorithm by creating a new Shared secret S

> To run this mode, execute:

```
java Assignment1 Assignment1.class test
```

**Mode 3: Encryption** - the program will run using the default values for the keys. Please run this mode if you are trying to check the implementation of the program.

> To run this mode, execute:

```
java Assignment1 Assignment1.class > Encryption.txt
```

**Goal:** Perform symmetric encryption using the block cipher AES. Before encryption can be done, a key must be exchanged with the receiver of the message; this will be done using Diffie-Hellman key agreement. The values are:

The prime modulus p is the following 1024-bit prime (given in hexadecimal):

```
b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323
```

The generator g is the following (again in hexadecimal):

```
44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68
```

The public shared value A for the Diffie-Hellman key change is given by $g^ai \mod p$ where a is the secret value. A has the following value

```
5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d
```

### Structure

- Assignment1.java - Program code file.
- DH.txt - 1024-bit shared Diffie-Hellman public value B in hexadecimal (256 hex digits with no white space).
- Encryption.txt - the AES encryption of the above class file produced using: `java Assignment1 Assignment1.class > Encryption.txt` (in hexadecimal with no white space).
- IV.txt - 128-bit IV in hexadecimal (32 hex digits with no white space).
- README.md

1 directory, 5 files
