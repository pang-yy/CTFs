## weirdSnake

Level: Medium

Category: Reverse Engineering

Link: [https://play.picoctf.org/practice/challenge/428](https://play.picoctf.org/practice/challenge/428)

### Description

I have a friend that enjoys coding and he hasn't stopped talking about a snake recently He left this file on my computer and dares me to uncover a secret phrase from it. Can you assist?

Author: Junias Bonou

### Solution

We are given a python bytecodes file. Our goal is to understand and reverse python bytecodes.

The format of python bytecodes includes 5 columns. From left to right are **line number**, **instruction offset**, **opcode mnemonic**, **\*oparg** and **resolved argument in parentheses**.

> [!NOTE]
> "The oparg, which is what the opcode takes to resolve to the actual argument, it knows where to look based on the opcode. For example, with a LOAD_NAME opcode, the oparg will point to the index in the co_names tuple."  
> Reference: blackduck.com

Here's the first part of the bytecodes:

```
  1           0 LOAD_CONST               0 (4)
              2 LOAD_CONST               1 (54)
              4 LOAD_CONST               2 (41)
              6 LOAD_CONST               3 (0)
              8 LOAD_CONST               4 (112)
             10 LOAD_CONST               5 (32)
             12 LOAD_CONST               6 (25)
             14 LOAD_CONST               7 (49)
             16 LOAD_CONST               8 (33)
             18 LOAD_CONST               9 (3)
             20 LOAD_CONST               3 (0)
             22 LOAD_CONST               3 (0)
             24 LOAD_CONST              10 (57)
             26 LOAD_CONST               5 (32)
             28 LOAD_CONST              11 (108)
             30 LOAD_CONST              12 (23)
             32 LOAD_CONST              13 (48)
             34 LOAD_CONST               0 (4)
             36 LOAD_CONST              14 (9)
             38 LOAD_CONST              15 (70)
             40 LOAD_CONST              16 (7)
             42 LOAD_CONST              17 (110)
             44 LOAD_CONST              18 (36)
             46 LOAD_CONST              19 (8)
             48 LOAD_CONST              11 (108)
             50 LOAD_CONST              16 (7)
             52 LOAD_CONST               7 (49)
             54 LOAD_CONST              20 (10)
             56 LOAD_CONST               0 (4)
             58 LOAD_CONST              21 (86)
             60 LOAD_CONST              22 (43)
             62 LOAD_CONST              17 (110)
             64 LOAD_CONST              22 (43)
             66 LOAD_CONST              23 (88)
             68 LOAD_CONST               3 (0)
             70 LOAD_CONST              24 (67)
             72 LOAD_CONST              25 (104)
             74 LOAD_CONST              26 (125)
             76 LOAD_CONST              14 (9)
             78 LOAD_CONST              27 (78)
             80 BUILD_LIST              40
             82 STORE_NAME               0 (input_list)
```

The first part of the bytecodes is easy to understand, it first pushes 40 values onto the stack, then `BUILD_LIST` will consume the 40 values, then stores into `input_list`.

In Python:

```python
input_list = [4, 54, 41, 0, 112, 32, 25, 49, 33, 3, 0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 
              7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 43, 110, 43, 88, 0, 67, 104, 125, 9, 78]
```

Second part of the bytecodes:

```
  2          84 LOAD_CONST              28 ('J')
             86 STORE_NAME               1 (key_str)

  3          88 LOAD_CONST              29 ('_')
             90 LOAD_NAME                1 (key_str)
             92 BINARY_ADD
             94 STORE_NAME               1 (key_str)

  4          96 LOAD_NAME                1 (key_str)
             98 LOAD_CONST              30 ('o')
            100 BINARY_ADD
            102 STORE_NAME               1 (key_str)

  5         104 LOAD_NAME                1 (key_str)
            106 LOAD_CONST              31 ('3')
            108 BINARY_ADD
            110 STORE_NAME               1 (key_str)

  6         112 LOAD_CONST              32 ('t')
            114 LOAD_NAME                1 (key_str)
            116 BINARY_ADD
            118 STORE_NAME               1 (key_str)
```

The second part of the bytecodes describe how *key* is constructed. 

Note that the order of `LOAD_CONST` and `LOAD_NAME` is important. `BINARY_ADD` is similar to concatinate string.

In Python:

```python
key_str = 'J' # line 2
key_str = '_' + key_str # line 3
key_str = key_str + 'o' # line 4
key_str = key_str + '3' # line 5
key_str = 't' + key_str # line 6
# final key_str: t_Jo3
```

Third part of bytecodes:

```
  9         120 LOAD_CONST              33 (<code object <listcomp> at 0x7ffb38066d40, file "snake.py", line 9>)
            122 LOAD_CONST              34 ('<listcomp>')
            124 MAKE_FUNCTION            0
            126 LOAD_NAME                1 (key_str)
            128 GET_ITER
            130 CALL_FUNCTION            1
            132 STORE_NAME               2 (key_list)

<REDACTED>

Disassembly of <code object <listcomp> at 0x7ffb38066d40, file "snake.py", line 9>:
  9           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                12 (to 18)
              6 STORE_FAST               1 (char)
              8 LOAD_GLOBAL              0 (ord)
             10 LOAD_FAST                1 (char)
             12 CALL_FUNCTION            1
             14 LIST_APPEND              2
             16 JUMP_ABSOLUTE            4
        >>   18 RETURN_VALUE
```

The program first loads a *code object* onto the stack. It then load the name of the *code object* which is `'<listcomp>'`.

Next, it do `MAKE_FUNCTION`, which combines the previously loaded code object and object name to create a function and push the function onto the stack.

It then loads `key_str` onto stack and call `GET_ITER`. `GET_ITER` will do `iter()` on `key_str`, which return an iterator for `key_str` and push it onto the stack.

It then do `CALL_FUNCTION` with `flags` set. From docs: "`CALL_FUNCTION_EX` pops all arguments and the callable object off the stack, calls the callable object with those arguments, and pushes the return value returned by the callable object."

The result of the function is stored in `key_list`.

When we scroll further down, we can see the details for code object `'<listcomp>'` of line 9.

The function simply do `ord()` on every element (which is char) in the iterable (which is the argument).

In Python:

```python
key_list = [ord(char) for char in key_str]
```

Fourth part of bytecodes:

```
 11     >>  134 LOAD_NAME                3 (len)
            136 LOAD_NAME                2 (key_list)
            138 CALL_FUNCTION            1
            140 LOAD_NAME                3 (len)
            142 LOAD_NAME                0 (input_list)
            144 CALL_FUNCTION            1
            146 COMPARE_OP               0 (<)
            148 POP_JUMP_IF_FALSE      162

 12         150 LOAD_NAME                2 (key_list)
            152 LOAD_METHOD              4 (extend)
            154 LOAD_NAME                2 (key_list)
            156 CALL_METHOD              1
            158 POP_TOP
            160 JUMP_ABSOLUTE          134
```

Instructions 134 to 138 is equivalent to `len(key_list)`, similar for instructions 140 to 144.

Also note that there's 2 `>` beside the first line of instructions which indicate start of a loop.

`COMPARE_OP` will takes 2 items from the stack, compare them and push result onto stack.

The result will be used by `POP_JUMP_IF_FALSE`, which will jump to instruction 162 if result is false.

Otherwise, it will continue to instruction 150. Instruction 150 to 156 is equivalent to `key_list.extend(key_list)`

After that it will jump back to instruction 134.

In Python:

```python
while len(key_list) < len(input_list):
    key_list.extend(key_list)
```

Fifth part of bytecodes:

```
 15     >>  162 LOAD_CONST              35 (<code object <listcomp> at 0x7ffb38066df0, file "snake.py", line 15>)
            164 LOAD_CONST              34 ('<listcomp>')
            166 MAKE_FUNCTION            0
            168 LOAD_NAME                5 (zip)
            170 LOAD_NAME                0 (input_list)
            172 LOAD_NAME                2 (key_list)
            174 CALL_FUNCTION            2
            176 GET_ITER
            178 CALL_FUNCTION            1
            180 STORE_NAME               6 (result)

<REDACTED>

Disassembly of <code object <listcomp> at 0x7ffb38066df0, file "snake.py", line 15>:
 15           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                16 (to 22)
              6 UNPACK_SEQUENCE          2
              8 STORE_FAST               1 (a)
             10 STORE_FAST               2 (b)
             12 LOAD_FAST                1 (a)
             14 LOAD_FAST                2 (b)
             16 BINARY_XOR
             18 LIST_APPEND              2
             20 JUMP_ABSOLUTE            4
        >>   22 RETURN_VALUE

```

Instructions 162 to 166 is similar to what described in part 3 above.

Instructions 168 to 174 is equivalent to `zip(input_list, key_list)`. `CALL_FUNCTION    2` means 2 arguments.

Instructions 176 to 180 is the same concept as part 3. It call the function with return value from `zip(...)` and the the result in `result`.

Again, if we scroll to the bottom we can see the details for code object `'<listcomp>'` of line 15.

For every element in the iterable, it perform `BINARY_XOR` on the first entry (a) of the element with second entry (b) of the element.

In Python:

```python
result = [a ^ b for a, b in zip(input_list, key_list)]
```

Last part of bytecodes:

```
 18         182 LOAD_CONST              36 ('')
            184 LOAD_METHOD              7 (join)
            186 LOAD_NAME                8 (map)
            188 LOAD_NAME                9 (chr)
            190 LOAD_NAME                6 (result)
            192 CALL_FUNCTION            2
            194 CALL_METHOD              1
            196 STORE_NAME              10 (result_text)
            198 LOAD_CONST              37 (None)
            200 RETURN_VALUE
```

This part is conceptually similar to what we described above.

In Python:

```python
result_text = ''.join(map(chr, result))
```

Lastly, we just need to print out `result_text`.

Complete script:

```python
input_list = [4, 54, 41, 0, 112, 32, 25, 49, 33, 3, 0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 
              7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 43, 110, 43, 88, 0, 67, 104, 125, 9, 78]

key_str = 'J' # line 2
key_str = '_' + key_str # line 3
key_str = key_str + 'o' # line 4
key_str = key_str + '3' # line 5
key_str = 't' + key_str # line 6

key_list = [ord(char) for char in key_str]

while len(key_list) < len(input_list):
    key_list.extend(key_list)

result = [a ^ b for a, b in zip(input_list, key_list)]

result_text = ''.join(map(chr, result))

print(result_text)
```

Reference: 
- [https://docs.python.org/3/library/dis.html](https://docs.python.org/3/library/dis.html)
- [https://www.blackduck.com/blog/understanding-python-bytecode.html](https://www.blackduck.com/blog/understanding-python-bytecode.html)

Flag: `picoCTF{N0t_sO_coNfus1ng_sn@ke_1a73777f}`
