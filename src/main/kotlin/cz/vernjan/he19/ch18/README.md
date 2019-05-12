# 18 - Egg Storage

*Last year someone stole some eggs from Thumper.*

*This year he decided to use cutting edge technology to protect his eggs.*

[Egg Storage](challenges/eggstorage/index.html)

---

![](challenge.png)

After short inspection of the site, it's obvious we will need to crack
[WebAssembly](https://webassembly.org/) code to reverse the 24-length password.

```js
function callWasm(instance) {
    if (instance.exports.validatePassword(...password)) {
        setResultImage(`eggs/${getEgg(instance)}`);
    } else {
        showError();
    }
}
```

There is a nice article on the topic of
[reverse engineering WebAssembly](https://medium.com/@pnfsoftware/reverse-engineering-webassembly-ed184a099931).

The validation logic is mainly implemented in [wasm-d986c06a-2](challenges/wasm/wasm-d986c06a-2)
and consists of the following steps:

1) Password characters at positions 5..24 must be one of `01345HLXcdfr`, i.e. one of ASCII codes
48, 49, 51, 52, 53, 72, 76, 88, 99, 100, 102, 114

2) The password starts with `Th3P`

3) The following rules must hold true (Xth means the Xth character of the password):
    ```
    24th = 18th
    13th = 17th
    23rd = 16th                 : MY CALCULATIONS
    6th - 8th = 14              : 114 - 100 = 14 
    15th +1 = 16th              : 48 + 1 = 49
    10th % 9th = 40             : 88 % 48 = 40
    6th - 10th + 20th = 79      : 114 - 88 + 53 = 79
    8th - 15th = 21st           : 100 - 48 = 52
    (10th % 5th) * 2 = 14th     : (88 % 52) * 2 = 72
    14th % 7th = 20             : 72 % 52
    12th % 14th = 22nd - 46     : 102 % 72 = 76 - 46, 114 % 72 = 88 - 46
    8th % 7th = 11th            : 100 % 52 = 48
    24th % 23rd = 2	            : 51 % 49, 100 % 49
    ```
    
    The solution is not complete yet but gives a pretty good idea what the password might look like:
    ```
    5th:    52          4
    6th:    114         r
    7th:    52          4
    8th:    100         d
    9th:    48          0
    10th:   88          X
    11th:   48          0
    12th:   102 / 114   f / r
    13th:   ?           ?
    14th:   72          H
    15th:   48          0
    16th:   49          1
    17th:   ?           ?
    18th:   51 /100     3 / d
    19th:   ?           ?
    20th:   53          5
    21st:   52          4
    22nd:   76 / 88     L / X
    23rd:   49          1
    24th:   51/ 100     3 / d
    ```

4) Sum of all characters is `1352`
5) XOR of all characters is `44`

I skipped the last 2 conditions and was able to guess the password:
`Th3 P4r4d0X 0f cH01c3 15 4 L13` (The paradox of choice is a lie).

Here is the egg:

![](challenges/images/eggs/2929dac4326ad3553872c6a7.png)
