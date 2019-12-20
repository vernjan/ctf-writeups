# HV19.19 🎅

🏁🍇🎶🔤🐇🦁🍟🗞🍰📘🥖🖼🚩🥩😵⛺❗️🥐😀🍉🥞🏁👉️🧀🍎🍪🚀🙋🏔🍊😛🐔🚇🔷🎶📄🍦📩🍋💩⁉️🍄🥜🦖💣🎄🥨📺🥯📽🍖🐠📘👄🍔🍕🐖🌭🍷🦑🍴⛪🤧🌟🔓🔥🎁🧦🤬🚲🔔🕯🥶❤️💎📯🎙🎚🎛📻📱🔋😈🔌💻🐬🖨🖱🖲💾💿🧮🎥🎞🔎💡🔦🏮📔📖🏙😁💤👻🛴📙📚🥓📓🛩📜📰😂🍇🚕🔖🏷💰⛴💴💸🚁🥶💳😎🖍🚎🥳📝📁🗂🥴📅📇📈📉📊🔒⛄🌰🕷⏳📗🔨🛠🧲🐧🚑🧪🐋🧬🔬🔭📡🤪🚒💉💊🛏🛋🚽🚿🧴🧷🍩🧹🧺😺🧻🚚🧯😇🚬🗜👽🔗🧰🎿🛷🥌🎯🎱🎮🎰🎲🏎🥵🧩🎭🎨🧵🧶🎼🎤🥁🎬🏹🎓🍾💐🍞🔪💥🐉🚛🦕🔐🍗🤠🐳🧫🐟🖥🐡🌼🤢🌷🌍🌈✨🎍🌖🤯🐝🦠🦋🤮🌋🏥🏭🗽⛲💯🌁🌃🚌📕🚜🛁🛵🚦🚧⛵🛳💺🚠🛰🎆🤕💀🤓🤡👺🤖👌👎🧠👀😴🖤🔤 ❗️➡️ ㉓ 🆕🍯🐚🔢🍆🐸❗️➡️ 🖍🆕㊷ 🔂 ⌘ 🆕⏩⏩ 🐔🍨🍆❗️ 🐔㉓❗️❗️ 🍇 ⌘ ➡️🐽 ㊷ 🐽 ㉓ ⌘❗️❗️🍉 🎶🔤🍴🎙🦖📺🍉📘🍖📜🔔🌟🦑❤️💩🔋❤️🔔🍉📩🎞🏮🌟💾⛪📺🥯🥳🔤 ❗️➡️ 🅜 🎶🔤💐🐡🧰🎲🤓🚚🧩🤡🔤 ❗️➡️ 🅼 😀 🔤 🔒 ➡️ 🎅🏻⁉️ ➡️ 🎄🚩 🔤❗️📇🔪 🆕 🔡 👂🏼❗️🐔🍨🍆❗️🐔🍨👎🍆❗️❗️❗️ ➡️ 🄼 ↪️🐔🄼❗️🙌 🐔🍨🍆❗️🍇🤯🐇💻🔤👎🔤❗️🍉 ☣️🍇🆕🧠🆕🐔🅜❗️❗️➡️ ✓🔂 ⌘ 🆕⏩⏩🐔🍨🍆❗️🐔🅜❗️❗️🍇🐽 ㊷ 🐽 🅜 ⌘❗️❗️ ➡️ ⌃🐽 🄼 ⌘ 🚮🐔🄼❗️❗️➡️ ^💧🍺⌃➖🐔㉓❗️➗🐔🍨👎👍🍆❗️❗️❌^❌💧⌘❗️➡️ ⎈ ↪️ ⌘ ◀ 🐔🅼❗️🤝❎🍺🐽 ㊷ 🐽 🅼 ⌘❗️❗️➖ 🤜🤜 🐔🅜❗️➕🐔🅜❗️➖🐔🄼❗️➖🐔🅼❗️➕🐔🍨👍🍆❗️🤛✖🐔🍨👎👎👎🍆❗️🤛 🙌 🔢⎈❗️❗️🍇 🤯🐇💻🔤👎🔤❗️🍉✍✓ ⎈ ⌘ 🐔🍨👎🍆❗️❗️🍉🔡🆕📇🧠✓ 🐔🅜❗️❗️❗️➡️ ⌘↪️⌘ 🙌 🤷‍♀️🍇🤯🐇💻🔤👎🔤❗️🍉😀🍺⌘❗️🍉 🍉

---

This is actually a program written in [Emojicode](https://www.emojicode.org/).

I tried to run it using the official [Docker image](https://hub.docker.com/r/esolang/emojicode)
```
$ docker run -ti -v /home/vernjan/emojic/:/emojic:rw esolang/emojicode sh
$ emojicode /emojic/day19.emojic
/tmp/code.emojic:1:297: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:423: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:452: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:491: ⚠️  warning: Type is ambiguous without more context.
 🔒 ➡️ 🎅🏻⁉️ ➡️ 🎄🚩
> hello
🤯 Program panicked: 👎
```

Ok, I think we will need to provide the right input .. Let's analyze the code!

```
Start block
🏁🍇

Init array ㉓ (256 items)
🎶🔤🐇🦁🍟🗞🍰📘🥖🖼🚩🥩😵⛺❗️🥐😀🍉🥞🏁👉️🧀🍎🍪🚀🙋🏔🍊😛🐔🚇🔷🎶📄🍦📩🍋💩⁉️🍄🥜🦖💣🎄🥨📺🥯📽🍖🐠📘👄🍔🍕🐖🌭🍷🦑🍴⛪🤧🌟🔓🔥🎁🧦🤬🚲🔔🕯🥶❤️💎📯🎙🎚🎛📻📱🔋😈🔌💻🐬🖨🖱🖲💾💿🧮🎥🎞🔎💡🔦🏮📔📖🏙😁💤👻🛴📙📚🥓📓🛩📜📰😂🍇🚕🔖🏷💰⛴💴💸🚁🥶💳😎🖍🚎🥳📝📁🗂🥴📅📇📈📉📊🔒⛄🌰🕷⏳📗🔨🛠🧲🐧🚑🧪🐋🧬🔬🔭📡🤪🚒💉💊🛏🛋🚽🚿🧴🧷🍩🧹🧺😺🧻🚚🧯😇🚬🗜👽🔗🧰🎿🛷🥌🎯🎱🎮🎰🎲🏎🥵🧩🎭🎨🧵🧶🎼🎤🥁🎬🏹🎓🍾💐🍞🔪💥🐉🚛🦕🔐🍗🤠🐳🧫🐟🖥🐡🌼🤢🌷🌍🌈✨🎍🌖🤯🐝🦠🦋🤮🌋🏥🏭🗽⛲💯🌁🌃🚌📕🚜🛁🛵🚦🚧⛵🛳💺🚠🛰🎆🤕💀🤓🤡👺🤖👌👎🧠👀😴🖤🔤 ❗️➡️ ㉓

Create empty map ㊷
🆕🍯🐚🔢🍆🐸❗️➡️ 🖍🆕㊷ 

# Iterate over array ㉓ (for ⌘ 0..㉓.size)
🔂 ⌘ 🆕⏩⏩ 🐔🍨 🍆❗️ 🐔㉓❗️❗️ 
    # Put items from Array ㉓ into map ㊷ (emoji is key, index is value)
    🍇 ⌘ ➡️🐽 ㊷ 🐽 ㉓ ⌘❗️❗️🍉

Init array 🅜 (26 items) - This is the scrambled flag
🎶🔤🍴🎙🦖📺🍉📘🍖📜🔔🌟🦑❤️💩🔋❤️🔔🍉📩🎞🏮🌟💾⛪📺🥯🥳🔤 ❗️➡️ 🅜 

Init array 🅼 (8 items)
🎶🔤💐🐡🧰🎲🤓🚚🧩🤡🔤 ❗️➡️ 🅼

Print "🔒 ➡️ 🎅🏻⁉️ ➡️ 🎄🚩"
😀 🔤 🔒 ➡️ 🎅🏻⁉️ ➡️ 🎄🚩 🔤❗️

Read user input (password) and copy 1 character into 🄼
📇🔪 🆕 🔡 👂🏼❗️🐔🍨🍆❗️🐔🍨👎🍆❗️❗️❗️ ➡️ 🄼

If user input length = 0
↪️🐔🄼❗️🙌 🐔🍨🍆❗️
    Panic (exit with 👎)
    🍇🤯🐇💻🔤👎🔤❗️🍉

Native memory
☣️🍇
    Allocate memory (size 26) and store pointer into ✓
    🆕🧠🆕🐔🅜❗️❗️➡️ ✓

    Iterate over array 🅜 (for ⌘ 0..🅜.size)
    🔂 ⌘ 🆕⏩⏩🐔🍨🍆❗️🐔🅜❗️❗️
        🍇
            Get value (i.e. 0-255) from map ㊷ for key 🅜[⌘] and store it into ⌃
            🐽 ㊷ 🐽 🅜 ⌘❗️❗️ ➡️ ⌃
            My print
            😀🔡🍺⌃ 10❗️❗️

            Get 1 byte from user input (🚮 is modulus) and store it into ^
            🐽 🄼 ⌘ 🚮🐔🄼❗️❗️➡️ ^
            My print
            😀🔡🔢^❗️10❗️❗️

            Unscrambled flag letter using user input (password)
            ((byte)⌃ - 256) / 2 * ^ * ⌘
            Lazy to revert this fucntion (involes byte overflows) - It's quite easy to bruteforce 
            Value [0-255] - 256     / 2 * USER_INPUT * ⌘         
            💧🍺⌃➖🐔㉓❗️➗🐔🍨👎👍🍆❗️❗️❌^❌💧⌘❗️➡️ ⎈
            😀🔡🔢⎈❗️10❗️❗️
        
            If (⌘ < 8 && ! ㊷[🅜[⌘]] - ((26 - 26 - 4 - 9 + 1) * 3)) = ⎈ 
            Simplified: If (⌘ < 8 && ! ㊷[🅜[⌘]] - 123) = ⎈ 
            Note: Assuming 🐔🄼 (user input length) is 4 (one emoji in UTF-8 = 4 bytes)
            ↪️ ⌘ ◀ 🐔🅼❗️🤝❎🍺🐽 ㊷ 🐽 🅼 ⌘❗️❗️➖ 🤜🤜 🐔🅜❗️➕🐔🅜❗️➖🐔🄼❗️➖🐔🅼❗️➕🐔🍨👍🍆❗️🤛✖🐔🍨👎👎👎🍆❗️🤛 🙌 🔢⎈❗️❗️
                Panic (exit with 👎)
                🍇 🤯🐇💻🔤👎🔤❗️🍉
            
            Write ⎈ into allocated memory ✓ [offset ⌘, length 1] - Collecting the flag!
            ✍✓ ⎈ ⌘ 🐔🍨👎🍆❗️❗️
        🍉
    
    Copy memory from ✓ to ⌘
    🔡🆕📇🧠✓ 🐔🅜❗️❗️❗️➡️ ⌘
    
    If flag (wrapped in optional type) is empty
    ↪️⌘ 🙌 🤷‍♀️
        Panic (exit with 👎)
        🍇🤯🐇💻🔤👎🔤❗️🍉
    
    Unwrap flag from optional and print it
    😀🍺⌘❗️
🍉 

End block  
🍉
```

I guessed the password based on 2 things:
- Calculating the expected value of ⎈ (simply ㊷[🅜[⌘]] - 123) for the first 4 rounds
- Printing the actual value of ⎈ for a random input (random emoji)

I compared the actual and expected value and adjusted the input accordingly.

```
$ emojicode /emojic/day19-prints.emojic
/tmp/code.emojic:1:297: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:423: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:452: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:491: ⚠️  warning: Type is ambiguous without more context.
 🔒 ➡️ 🎅🏻⁉️ ➡️ 🎄🚩
> 🚩 // Random input
-16 // Round 1 - OK - All emoji in UTF-8 have the same first two bytes
72
-97 // Round 2 - OK
86
-102 // Round 3 - Failed - We got 63 but wanted TODO XXX 
63
🤯 Program panicked: 👎
Aborted
```

I calculated the 3rd and 4th round.

The correct key is: 🔑 (nice!)
```
$ emojicode /emojic/day19-prints.emojic
/tmp/code.emojic:1:297: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:423: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:452: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:491: ⚠️  warning: Type is ambiguous without more context.
 🔒 ➡️ 🎅🏻⁉️ ➡️ 🎄🚩
> 🔑
-16
72
-97
86
-108
49
-111
57
-16
123
-97
42
-108
60
-111
124
-16
58
🤯 Program panicked: Index out of bounds in 🍨🐽
Aborted
```

I don't know why but it didn't work as expected.. I simply removed the whole IF statement
(suspecting the issue is there) and then it worked:
```
$ emojicode /emojic/day19-no-password-check.emojic
/tmp/code.emojic:1:297: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:423: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:451: ⚠️  warning: Type is ambiguous without more context.
/tmp/code.emojic:1:490: ⚠️  warning: Type is ambiguous without more context.
 🔒 ➡️ 🎅🏻⁉️ ➡️ 🎄🚩
> 🔑
HV19{*<|:-)____\o/____;-D}
```

The flag is `HV19{*<|:-)____\o/____;-D}`