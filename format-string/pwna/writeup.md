# Format String - PwnA Solution
## Understand the vulnerability and internals of snprintf()
To start with, let's analyze the alleged vulnerable binary and see what we could exploit in it.
Let's look at this particular piece of code:
```
		char res[BUF_LEN];
		//Check that the user input doesn't contain the secret key
		char *too_ez = strchr(argv[1], '4');
		if (too_ez == NULL) {
			snprintf(res, BUF_LEN, argv[1]); // VULNERABILITY IS HERE
			if (strcmp("4",res) == 0) {
				system("/bin/sh");
			} else {
				printf("Free data:%s", res);
			}
		} else {
			puts("Nope !");
		}
```

What does the snprintf() function I've tagged?
Let's see how it works: for "*snprintf(STR buff, INT size, STR format)*", it will **interpret** the format specified in "STR format" and write the according result in "STR buff" (with maximal size "INT size" to avoid buffer overflows).

It means that for example in this case:
```
int main()
{
    int i=65; // = 0x41
    char buffer[3];
    char format[3] = "%x\n";
    
    snprintf(buffer, 3, format, i);
    puts(buffer);
    
    return 0;
}
```

snprintf will interpret what's in "format" ("%x\n"), meaning it will take the next argument (the 4rd one "INT i", which is equal to 65) and interpret it has an hexadecimal number (because of the "%x" operator).
It will then write the result in "buffer". So after snprintf() operation, "buffer" string will be equal to "41" (because decimal 65 gives 0x41 in hexadecimal) !

So, to get back to our program, what will do `snprintf(res, BUF_LEN, argv[1])` if argv[1] is equal to "%x" for example? As no 4rd argument is provided to snprintf() here, it will look for some value located kinda at the top of the stack, interpret it as an hexadecimal character and write the result to res.

So here, the vulnerability is that we can arbitrarily READ values on the stack. We could even WRITE values where we want (write-what-where) using the %n operator of printf (= classic format string vulnerability where you overwrite a GOT entry for example), but we won't have to do that for this challenge.

To avoid this kind of vulnerability, **one should never let the user control a string/input being used as a "format" in printf-like functions (= includes printf, snprintf etc.)**.

## What to do next? How to use it for fun and profit?
First thing we can see it this: argv[1] is interpreted and copied in "res" buffer.
Argv[1] MUST NOT contain a '4' character (so "4", "hello 4 world", "1347" etc will fail) otherwise we will receive the message "Nope !". But to obtain the shell, "res" buffer must be equal to '4'!

This sounds like non-sense: argv[1] is interpreted and copied in res, argv[1] MUST NOT contain a '4', res MUST be equal to '4'... It's an unsatisfiable constraint, isn't it?!

Well, as you can guess, the goal will be to craft a format string "argv[1]" that doesn't contain any '4' character but, once interpreted by snprintf(), gives a result equal to '4' and write it to the "res" string!

## The approach I chose

As I already told you, if we execute `snprintf(res, BUF_LEN, argv[1])` with argv[1] == "$x" for example, it will look for a value located kind of at the top of the stack, interpret it as hexadecimal and write the result to res.

What's interesting is that printf formats allow to specify an offset that will allows up to "walk through" the stack. For that, we use the format "%OFFSET_VALUE$OPERATOR".
So for example, "%1$p" will look for an address at offset+1, "%2$p" for an address at offset+2, etc.
To be more concrete, if our stack looks like this:
```
0x00000000:dead0000 | 0x0000000020000000
0x00000000:dead0008 | 0x4141414141414141 
0x00000000:dead0010 | 0x007f5d00f34a0de8
0x00000000:dead0018 | 0x007f5d0000000042
```
If "%1$p" prints "0x20000000", then "%2$p" will print "0x4141414141414141", "%3$p" will print "0x007f5d00f34a0de8", etc. Using those offsets will allow us to walk / iterate through values located on the stack.

In this case, it means if for example I choose format "%4\$c", it will lookup for a char at offset 4 and print it --> in this case it will take the char "0x42" (remember x86 is little-endian so we read left-to-right), meaning this command will interpret it at the corresponding ASCII char "B" and copy it in "res".

So, to solve the challenge you may guess what I'm gonna do: iterate/bruteforce through the stack using offset trick, until finding a value on the stack similar to this:
```
0x00000000:deadbeef | 0x??????????????34
```
? means "whatever byte" here.
The byte located next to the "0x34" doesn't need to be a nullchar as printf "%c" operator only lookups for one char, so that's cool! When copied in "res", a nullchar will be automatically appended to the result of course, don't worry!

As you can guess, if we find an offset containing such a value, "%OFFSET\$c" will interpret the "0x34" as the corresponding ASCII char which is... '4' ! And it will write it to res! Then, BOOM, secret key will be equal to that magical value and we'll obtain the shell!

It involves bruteforcing so I admit it's not an ultra reliable way, but in theory at each looked-up offset we have 1 chance out of 256 that this happen... So this is kinda OK for us!

This is only later that I found a more reliable way, see the last part "Path to the 100% success" for this. So I first started to write a bash bruteforcer that iterate through offsets, then we'll see I also chose to implement it in Python/PwnTools.

# Results obtained with bruteforcer

Using the bash bruteforcer, in my case (this will probably be different on your machine) I found out our char '4' was always located at offset 57. It means on my OS I can open a shell whenever I want using command: `./pwna %57\$c`.

However, it has limitations as it will only work on MY computer, that's why I decided to make a Python-PwnTools solution so that we'll be able to perform the exploit on a remote server!

Using Python-PwnTools script on my computer the exploit didn't work everytime at +57 offset (probably because execution context / stack when executed with PwnTools is different than when executed with bash), but in a few tries I was able to get my shell.

For both bash/Python script you might have to try 5 or 6 times until it works because you have to be lucky enough to finally print a '4' char located on the stack. But trust me, at some point you'll finally be lucky and a shell will pop!

NOTE: for each script, I added an "if condition" in the loop to check if the offset currently being tested contains a '4' or not (similarly to what does the strchr() function in the vuln binary): if yes, we increment the offset and go to the next iteration (= we don't send this input as we will receive a "Nope !").
It means we WON'T lookup at offset 4, 14, 24, 34, 40 to 49, 54 and so one as they contain a '4'...

# Path to the 100% success
## Theory
I was unsatisfied with the bruteforce solution as you have potentially to try a few times before it works. That's OK because you will get your shell in a few seconds, but, well... I'd be more satisfied with something more reliable.

So I got the following idea: when you execute programs with arguments in Linux, the address of their arguments (argv[1], argv[2], argv[3] etc) will be written somewhere on the stack. It means, if I execute the vulnerable program like this `./pwna AAAAA BBBB`, here's how my stack may look at some place:

```
0x00000000dead0000 | 000000000000001c
0x00000000dead0008 | 0000000000000003
0x00000000dead0010 | 00007fff5447daba   -->   points to string "/path/to/vuln.a"  (argv[0])
0x00000000dead0018 | 00007fff5447dafe   -->   points to string "AAAAAAAAA"        (argv[1])
0x00000000dead0020 | 00007fff5447db07   -->   points to string "BBBBBBBBB"        (argv[2])
0x00000000dead0028 | 0000000000000000
0x00000000dead0030 | 00007fff5447db12   -->   points to string "USER=johndoe"
0x00000000dead0038 | 00007fff5447db33   -->   points to string "SHELL=/bin/bash"
0x00000000dead0040 | 00007fff5447db51   -->   points to string "PATH=/usr/local/sbin/ etc."    (random env vars)
```
As represented in this output, argv[0] / argv[1] etc are generally located just before environment variables addresses (because environmnent variables addresses are also pushed on the stack in Linux).

So here's what we can do: if argv[2] address is located at offset 52, if I execute this: `./pwna %52\$s BBBB`... snprintf() will copy the string "BBBB" in res and it will then be printed!

So now, if I replace argv[2] by the string '4' by doing `./pwna %52\$s 4`... snprintf() will copy string '4' (from argv[2]) in res and BOOM, we'll get that shell!
Maybe we can't type any '4' in argv[1]... But we can do it in argv[2], argv[3] etc! Here's the trick!

## Practise and final solution

Unfortunately, in my case it appears the argv[2] "BBBBB" string was located at offset +41... Meaning there's a '4' in the offset so I will receive a "Nope !" when doing `./pwna %41\$s BBBB`... :(

To circumvent this, I decided to write more arguments (argv[3], argv[4], argv[5] etc) until finding one that I'm able to print using offset "50". For example, doing `./pwna %50\$s BBB CCC DDD EEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL MMMM NNNN` gave me this output: `Free data:KKKK`.

Now I know that "KKKK" string (argv[11]) is located at offset +50, so if I replace it with a string '4' like this: `./pwna %50\$s BBB CCC DDD EEE FFFF GGGG HHHH IIII JJJJ 4`

BOOM! '4' is copied in res and I've got my 100% reliable 1337 shell!

![Alt Text](https://i.imgur.com/vRU0Fum.gif)

On your system you may of course have to adapt this offset, but using the methodology I gave you, you'll be able to do it in the blink of an eye. ;)

# Conclusion

Hope you learned some stuff about internals of printf-related functions, about how stuff works in the OS/Linux (arguments, environment variables, x86 stack layout) and so one!
