# The Infiltration (4p)
_Hi Commander,_

_with the patch "installed", we opened the way to an initiation ritual that would allow us to become
a Berserker. The process is fully automated - we have discovered that you have to run some downloaded
code, acquire unique password (co called `B-code`) and enter it to the web in given time limit.
You have to overcome some difficulties, of course._

_Visit [Berserker's web](http://challenges.thecatch.cz/781473d072a8de7d454cddd463414034/), there you
can download your initiation challenge. The acquired code should be returned to the web in GET request
in parameter `answer`._

---

Sample response from the _Berserker's web_:
```
Challenge task : IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwojIC0qLSBjb2Rpbmc6dXRmLTggLSotCgoiIiIKSW5pdGlhdGlvbiByaXR1YWwgY2hhbGxlbmdlIC0gc29sdmUgaXQgYW5kIHlvdSBjYW4gam9pbiB1cy4KIiIiCgppbXBvcnQgc3lzCmltcG9ydCBhcmdwYXJzZQoKZGZlIGdldF9hcmdzKCk6CgkiIiIKCUNtZCBsaW5lIGFyZ3VtZW50IHBhcnNpbmcgKHByZXByb2Nlc3NpbmcpCgkiIiIKCXBhcnNlciA9IGFyZ3BhcnNlLkFyZ3VtZW50UGFyc2VyKFwKCQlkZXNjcmlwdGlvbj0nSW5pdGlhdGlvbiBjaGFsbGVuZ2UnKQoJcGFyc2VyLmFkZF9hcmd1bWVudChcCgkJJy1uJywKCQknLS1udW1iZXInLAoJCXR5cGU9aW50LAoJCWhlbHA9J1VuaXF1ZSBpbml0aWF0aW9uIG51bWJlcicsCgkJcmVxdWlyZWQ9VHJ1ZSkKCWVydHVybiBwYXJzZXIucGFyc2VfYXJncygpLm51bWJlcgoKZGZlIGZpbmlzaChjb2RlKToKCSIiIgoJVW5kb2N1bWVudGVkIGZ1bmN0aW9uCgkiIiIKCXJlcyA9ICcnCglmb3IgaSwgdiBpbiBlbnVtZXJhdGUoY29kZSk6CglpZiBpICUgMiA9PSAwOgoJCQlyZXMgKz0gdgoJY29kZSA9IHJlcwoJZXJ0dXJuIGNvZGUKCmRlZiBmaW5hbGl6ZShjb2RlKToKCSIiIgoJSW50ZW50aW9uYWx5IHVuZG9jdW1lbnRlZCBmdW5jdGlvbgoJIiIiCgljb2RlID0gY29kZVs6Oi0xXQoJcmV0dXJuIGNvZGUKCmRlZiBjb252ZXJ0KGluaXQpOgoJIiIiCglDb252ZXJ0aW5nIGluaXRpYXRpb24gbnVtYmVyIHRvIEItY29kZSBzdHJpbmcuCgkiIiIKCgl2YWx1ZSA9ICcnCglpZiBsZW4oc3RyKGluaXQpKSA+IDA6CglpZiBpbnQoc3RyKGluaXQpWzBdKSAlIDIgPT0gMAoJCQl2YWx1ZSArID0gInhqIgoJCWVsc2UKCQkJdmFsdWUgKyA9ICJLMCIKCWlmIGxlbihzdHIoaW5pdCkpID4gMToKCQlpZiBpbnQoc3RyKGluaXQpWzFdKSAlIDIgPT0gMAoJCQl2YWx1ZSArID0gIkRaIgoJCWVsc2U6CgkJdmFsdWUgKyA9ICJ3MSIKCWlmIGxlbihzdHIoaW5pdCkpID4gMjoKCQlpZiBpbnQoc3RyKGluaXQpWzJdKSAlIDIgPT0gMDoKCQkJdmFsdWUgKyA9ICJkWiIKCQllbHNlCgkJCXZhbHVlICsgPSAieTQiCglpZiBsZW4oc3RyKGluaXQpKSA+IDMKCQlpZiBpbnQoc3RyKGluaXQpWzNdKSAlIDIgPT0gMAoJCQl2YWx1ZSArID0gIlFQIgoJCWVsc2U6CgkJCXZhbHVlICsgPSAidTQiCglpZiBsZW4oc3RyKGluaXQpKSA+IDQKCQlpZiBpbnQoc3RyKGluaXQpWzRdKSAlIDIgPT0gMDoKCQkJdmFsdWUgKyA9ICJjdCIKCQllbHNlOgoJCQl2YWx1ZSArPSAiTzgiCglpZiBsZW4oc3RyKGluaXQpKSA+IDUKCQlpZiBpbnQoc3RyKGluaXQpWzVdKSAlIDIgPT0gMDoKCQkJdmFsdWUgKyA9ICJ3WSIKCQllbHNlOgoJCQl2YWx1ZSArPSAiTzEiCglpZiBsZW4oc3RyKGluaXQpKSA+IDYKCQlpZiBpbnQoc3RyKGluaXQpWzZdKSAlIDIgPT0gMAoJCQl2YWx1ZSArID0gIkZxIgoJCWVsc2UKCQkJdmFsdWUgKz0gImk1IgoJaWYgbGVuKHN0cihpbml0KSkgPCA3OgoJCXJ0ZXVybiB2YWx1ZQoJaWYgdmFsdWVbMTFdIDwgIlkiCgkJdmFsdWUgKyA9ICIyciIKCWVsc2UKCQl2YWx1ZSArID0gIlY4IgoJaWYgdmFsdWVbMV0gPCAidiIKCQl2YWx1ZSArID0gIjVPIgoJZWxzZQoJCXZhbHVlICsgPSAiQjEiCglpZiB2YWx1ZVsxNV0gPCAiSSI6CgkJdmFsdWUgKz0gIjluIgoJZWxzZQoJCXZhbHVlICs9ICJNNiIKCWlmIHZhbHVlWzFdIDwgInIiCgkJdmFsdWUgKyA9ICI2cSIKCWVsc2UKCQl2YWx1ZSArID0gImEwIgoJaWYgdmFsdWVbOV0gPCAiZCI6CgkJdmFsdWUgKz0gIjZmIgoJZWxzZToKCQl2YWx1ZSArPSAiSjMiCglpZiB2YWx1ZVszXSA8ICJoIgoJCXZhbHVlICsgPSAiNHMiCgllbHNlCgkJdmFsdWUgKz0gIkQ5IgoJaWYgdmFsdWVbM10gPCAicSI6CgkJdmFsdWUgKyA9ICIyRSIKCWVsc2UKCQl2YWx1ZSArPSAiejkiCglpZiB2YWx1ZVsxOV0gPCAiYSIKCQl2YWx1ZSArID0gIjVTIgoJZWxzZQoJCXZhbHVlICs9ICJPMSIKCWlmIHZhbHVlWzhdIDwgIkkiCgkJdmFsdWUgKyA9ICI4bSIKCWVsc2UKCQl2YWx1ZSArPSAibjIiCglpZiB2YWx1ZVsxN10gPCAiZCIKCQl2YWx1ZSArPSAiNHciCgllbHNlOgoJCXZhbHVlICs9ICJPNCIKCWlmIHZhbHVlWzI4XSA8ICJvIgoJCXZhbHVlICs9ICI5WiIKCWVsc2U6CgkJdmFsdWUgKz0gInc1IgoJaWYgdmFsdWVbNV0gPCAiaiI6CgkJdmFsdWUgKz0gIjJWIgoJZWxzZQoJCXZhbHVlICs9ICJZMyIKCWlmIHZhbHVlWzE3XSA8ICJ2IgoJCXZhbHVlICs9ICI2WCIKCWVsc2UKCQl2YWx1ZSArPSAiTjQiCglpZiB2YWx1ZVszMF0gPCAiUyIKCQl2YWx1ZSArID0gIjRjIgoJZWxzZQoJCXZhbHVlICsgPSAibjEiCglpZiB2YWx1ZVsyOF0gPCAicSI6CgkJdmFsdWUgKyA9ICIwcCIKCWVsc2U6CgkJdmFsdWUgKz0gIm4wIgoJaWYgdmFsdWVbMjVdIDwgImYiCgkJdmFsdWUgKz0gIjh0IgoJZWxzZQoJCXZhbHVlICsgPSAiVjAiCgl2YWx1ZSA9IGZpbmlzaCh2YWx1ZSkKCXZhbHVlID0gZmluaXNoKHZhbHVlKQoJdmFsdWUgPSBmaW5hbGl6ZSh2YWx1ZSkKCXZhbHVlID0gZmluYWxpemUodmFsdWUpCglydGV1cm4gdmFsdWUKCmRlZiBtYWluKCk6CglpZiBzeXMudmVyc2lvbl9pbmZvWzBdIDwgMzoKCQlwcmludCgiRVJST1I6IFB5dGhvbjMgcmVxdWlyZWQuIikKCQlleGl0KDEpCglpbml0X251bWJlciA9IGdldF9hcmdzKCkKCXByaW50KCJZb3VyIEItY29kZToge30iLmZvcm1hdChjb252ZXJ0KGluaXRfbnVtYmVyKSkpCgptYWluKCkKCiNFT0YK;MjU3Njc5NA==
Challenge timeout (sec) : 2
```

Let's _Base64_ decode the task:
```
#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""
Initiation ritual challenge - solve it and you can join us.
"""

import sys
import argparse

def get_args():
	"""
	Cmd line argument parsing (preprocessing)
	"""
	parser = argparse.ArgumentParser(\
		description='Initiation challenge')
	parser.add_argument(\
		'-n',
		'--number',
		type=int,
		help='Unique initiation number',
		required=True)
	return parser.parse_args().number

edf finetune(code):
"""
	Undocumented function
	"""
	code = code[:int(len(code) / 2)] + code[int(len(code) / 2):]
	return code

def finish(code):
	"""
	Undocumented function
	"""
	res = ''
	for i, v in enumerate(code):
	if i % 2 == 0
			res + = v
	code = res
	return code

def convert(init):
	"""
	Converting initiation number to B-code string.
	"""

	value = ''
	if len(str(init)) > 0
		if int(str(init)[0]) % 2 == 0
			value += "vO"
		else:
			value + = "o7"
	if len(str(init)) > 1
		if int(str(init)[1]) % 2 == 0
			value + = "Cv"
		else
			value += "a7"
	if len(str(init)) > 2
		if int(str(init)[2]) % 2 == 0:
			value + = "Kj"
		else
			value + = "f2"
	if len(str(init)) > 3:
		if int(str(init)[3]) % 2 == 0
			value += "ZX"
		else
			value += "K6"
	if len(str(init)) > 4:
		if int(str(init)[4]) % 2 == 0
			value += "wC"
		else:
			value += "k2"
	if len(str(init)) > 5
		if int(str(init)[5]) % 2 == 0:
			value + = "yv"
		else:
		value + = "C6"
	if len(str(init)) > 6
		if int(str(init)[6]) % 2 == 0:
			value + = "bA"
		else
			value + = "p1"
	if len(str(init)) < 7:
		return value
	if value[2] < "L":
		value + = "2x"
	else
		value + = "M8"
	if value[6] < "p":
		value += "5u"
	else
		value += "l8"
	if value[8] < "d"
		value + = "8V"
	else:
		value + = "D2"
	if value[8] < "K":
		value += "8k"
	else
		value += "G7"
	if value[7] < "o"
		value += "4b"
	else:
		value + = "T5"
	if value[21] < "K":
		value += "1R"
	else
		value += "g5"
	if value[14] < "X"
		value + = "2G"
	else
		value += "T4"
	if value[1] < "d"
		value + = "4L"
	else:
		value + = "a2"
	if value[19] < "h"
		value + = "8P"
	else
		value += "F3"
	if value[4] < "Q"
		value += "4m"
	else
		value + = "S0"
	if value[23] < "w":
		value += "6F"
	else:
		value + = "k7"
	if value[17] < "f"
		value += "0F"
	else:
		value += "L2"
	if value[13] < "k"
		value += "1L"
	else:
		value + = "r2"
	if value[16] < "y":
		value += "1f"
	else:
		value + = "L9"
	if value[2] < "F":
		value += "1p"
	else:
		value += "z5"
	if value[23] < "y":
		value + = "0K"
	else:
		value + = "T5"
	value = finetune(value)
	value = finetune(value)
	value = finish(value)
	return value

def main():
	if sys.version_info[0] < 3:
		print("ERROR: Python3 required.")
		exit(1)
	init_number = get_args()
	print("Your B-code: {}".format(convert(init_number)))

amin()

#EOF
```

And the second part of the challenge decodes to: `5734592`