# STOCKHOLM (PSEUDO RANSOMWARE)

#### ENCRYPTION TOOL FOR EDUCATIONAL PURPOSE :space_invader:

- Stockolm is a project write in C
- His purpose is replicate the encryption processe of a ransomware
- The program only act on files whose extensions have been affected by Wannacry
- The cibled platform is Linux
- For safety the programme only work in a folder called infection in the user’s HOME directory

## Usage
<img width="921" height="210" alt="stockolm-h-opt" src="https://github.com/user-attachments/assets/682649a9-64c0-4d8f-92df-83c0ad696244" />

## Functioning

### Encryption :warning:
```sh
./stockholm
```
* In first place `stockolm` search for the directory `infection` in the user's Home directorie.
* Whene he find it he create a random **`32 bytes key`** and save it in the file `Encryption_key.ft`.
* The cryptage of the folder can now start.
* `stockholm` recursively navigate in the folder and all the files with the extensions cibled by wanacry are `crypted` using `AES` (Advanced Encryption Standard).
* In addition a random **`16 bytes IV`** (initialization vector) is created for each file.
* So for 2 files with exactely the same contents, the crypted version is not the same.
* This prevent "any chance" of infer relationships between (potentially similar) segments and so decrypte the files.
* If the encryption process was succesful, the `.ft` extension is add to the name of the file.

### Decryption
> [!CAUTION]
> Be aware that the key is **always** save in the file **Encryption_key.ft** in the working directorie.
> And the previous content of the file will be **erased and replace** at each lunch of stockholm !
```sh
./stockholm -r file_name -f
```
OR
```sh
./stockholm -r $(cat Encryption_key.ft)
```
* After the **`key`** is succesfully retrievied, stockholm search for the file with the extension `.ft` in the infection directorie.
* Whene he find one, he retrieved the **`IV**` who was stocked a the start of the file and `decrypte` the file whith the provided **`key`**.

> [!CAUTION]
> If the **`Key`** is not the good one the data will be **CORUPTED**.
* The name of the file return to his original state.
* And if the decryption process was succesful, the data to.

## Installation
The project use the open-sll library for the AES aglorithme.
```sh
apt-get install libssl-dev
```
And strlcat.
```sh
apt-get install libbsd-dev
```
And finaly run make to build the project 



