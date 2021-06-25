# Symbol Path lookup (cross-platform)

This tool extracts the information from .exe/.dll/.pdb files used on a symbol server. The Microsoft SDK ships tools for this `SymStore.exe` but these are Windows only and I needed to run this on a Linux server.

Spending some time on where all the info is coming from, it's now possible to extract the strings that are used to identify the sources from these files.

# Usage

```
./SymbolPath <exe-dll-or-pdb-file>
```
this will return something like:

```
EEE088D93B144597982A540D7E2A0E04c
(for a PDB)

60D235EE10000
(for a EXE or DLL)
```

# References

* [Symbols the Microsoft Way - by Bruce Dawson](https://randomascii.wordpress.com/2013/03/09/symbols-the-microsoft-way/)  
* [Program Database - Wikipedia](https://en.wikipedia.org/wiki/Program_database)