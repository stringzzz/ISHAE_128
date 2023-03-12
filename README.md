# ISHAE 128: Intersperse Substitution Harmony Assembly Encryption

This was another 128-bit encryption system this time written in x86 assembly as a side project for an Assembly and Comp Org class I was taking about
a year ago. This encryption system is kind of the precursor to my ANGELITA 128-bit system. I'm sure it wouldn't hold up very 
well to any analysis done on the algorithm, as I never really tested that in the process of creating it. This project instead was mostly
to see if I could even pull off something like this in x86 Assembly.

As for its actual use, the project folder containing it is set up in a way to work with assembly in Visual Studio, so it might need some
changes to get it to work in a different setup. Also, this particular encryption system will actually produce an encrypted copy of the file, it won't edit it in place. As for decryption, it will prompt the user to name the newly decrypted file, while the old encrypted file will still be there. 

For further details on the algorithm itself, refer to the main .asm file in the project folder.
