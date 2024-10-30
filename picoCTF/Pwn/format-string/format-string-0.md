## format string 0

Level: Easy

Category: Pwn

Link: [https://play.picoctf.org/practice/challenge/433](https://play.picoctf.org/practice/challenge/433)

### Description

Can you use your knowledge of format strings to make the customers happy?

Author: Cheng Zhang

### Solution

The program will print out the flag if a segmentation fault is triggered.

Since the first input is read using `scanf` without any length checking, we can overflow it.

