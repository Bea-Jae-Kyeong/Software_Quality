# Software_Quality
Final project of Software Quality in Jaen University with one member

Our program is a code about 128bit AES encryption, which encrypts random numbers in plain.bin file using key.bin creating encrypted.bin and decrypted.bin.
The number in plain.bin file should be the same with the number in decrypted.bin.
Bea Jae Kyeong has contributed the program, and we used this to work on our software quality project.

The main purpose of the project is to apply SEI CERT Coding Standards
to check if our program is well-coded. This is to make our program’s quality
higher. If the code of the program doesn’t meet the standard of SEI CERT
C++ Coding Standard, we modified the code.
We used Cppcheck tool designed for C/C++ for this practice. Its main goal
is to detect the kinds of errors that a compiler usually can’t detect.

We’ve met 10 standards of SEI CERT Coding Standards by modifying our
code, solved 10 issues from cppcheck by selecting some of the problems
that cppcheck is able to detect, and finally reduced cyclomatic complexity of
our modules each by same or lower than 10. Our program was finally
improved by SEI CERT Coding Standards, Cppcheck, and Metriculator. The
potential of error occurring got lowered by handling some exceptions and
we checked errors and warnings by cppcheck to ensure the confidence of
our program. We have finally checked our complexity by metriculator to
make our program work efficiently. We made a change to our code by
removing hard coded part and finding a new solution. We can say that our
final program’s software quality has improved to a better quality.
