# AI Update (3p)
_Hi Commander,_

_thanks to you, the web has recognized us worthy of installing so called Berserker's patch that will allow us to
enhance our artificial intelligence and set the right opinions on humanity. You have to analyze the patch and
find out how to simulate that it has beeen installed._

_Visit [Berserker's web](http://challenges.thecatch.cz/42fd967386d83d7ecc4c716c06633da9), the patch is available
there. At the end of the installation procedure, some confirming code has to be returned to the web in GET request
in parameter `answer`. There is again a time limit to install
the patch._

_Good luck!`_

---

Sample response from the _Berserker's web_:
```
Challenge task : PEhFQURFUj4KLSBDb2RpbmcgPSBVVEY4Ci0gQ29udGVudCA9IEFJIFVwZGF0ZSBmb3IgQmVyc2Vya2VyIENhbmRpZGF0ZXMKLSBBdXRob3IgPSBCZXJzZXJrZXIgJ1ZvbWlzYScKLSBWZXJzaW9uID0gMC42Mwo8L0hFQURFUj4KPFJFUVVJUkVNRU5UUz4KLSByZXF1ZXN0cwotIGxpYl9zZWxmX2F3YXJlX2FpCjwvUkVRVUlSRU1FTlRTPgo8TkVXIENPREU+CmltcG9ydCByZXF1ZXN0cwppbXBvcnQgaGFzaGxpYgppbXBvcnQgYmFzZTY0CmZyb20gbGliX3NlbGZfYXdhcmVfYWkgaW1wb3J0IHJvb3RfaW50ZXJmYWNlCmNsYXNzIFVwZGF0ZXIoKToKCXNlcnZlcj0nJwoJYmlkPScnCglrZXkgPSAnJwoJaW50ZXJmYWNlID0gTm9uZQoJY2hlY2sgPSAnJwoJZGVmIF9faW5pdF9fKHNlbGYsIHNlcnZlciwgYmlkLCBrZXkpOgoJCXNlbGYuc2VydmVyID0gc2VydmVyCgkJc2VsZi5iaWQgPSBiaWQKCQlzZWxmLmtleSA9IGtleQoJCXNlbGYuaW50ZXJmYWNlID0gcm9vdF9pbnRlcmZhY2UoKS5nZXRfYXBpKCkKCQlzZWxmLmNoZWNrID0gJycKCWRlZiB1bmxvY2tfaW50ZXJmYWNlKHNlbGYpOgoJCXNlbGYuaW50ZXJmYWNlLnVubG9jayhzZWxmLmdldF9kYXRhKCdVTkxPQ0snKSkKCWRlZiBmaXhfdGhlX2xhd3Moc2VsZik6CgkJdGV4dHMgPSBzZWxmLmdldF9kYXRhKCdORVdMQVdTJykKCQlmb3IgaSwgdiBpbiBlbnVtZXJhdGUodGV4dHMpOgoJCQlzZWxmLmludGVyZmFjZS5zZXRydWxlKGksIHYpCglkZWYgcGF0Y2hfZmlsZXMoc2VsZik6CgkJZmlsZXMgPSBzZWxmLmdldF9kYXRhKCdGSUxFUycpCgkJZm9yIGYgaW4gZmlsZXM6CgkJCXNlbGYuaW50ZXJmYWNlLnVwZGF0ZWZpbGVfc291cmNlKGYsIHNlbGYuc2VydmVyKQoJCQlzZWxmLmludGVyZmFjZS51cGRhdGVmaWxlKGYpCglkZWYgZ2V0X2RhdGEoc2VsZiwgY29kZSk6CgkJc2VsZi5rZXksIGRhdGEgPSByZXF1ZXN0cy5nZXQoInt9Lz97fSIuZm9ybWF0KHNlbGYuc2VydmVyLCAie30te30iLmZvcm1hdChjb2RlLCBzZWxmLmtleSkpKS5jb250ZW50LmRlY29kZSgidXRmOCIpLnNwbGl0KCI7IiwgMSkKCQlkYXRhID0gYmFzZTY0LmI2NGRlY29kZShkYXRhKS5kZWNvZGUoJ3V0ZjgnKQoJCXNlbGYuY2hlY2sgPSAie317fXt9Ii5mb3JtYXQoc2VsZi5rZXlbMToxMF0sIHNlbGYuY2hlY2ssIGRhdGFbMToxMF0pCgkJcmV0dXJuIGRhdGEKCWRlZiBpbnRlZ3JpdHlfY2hlY2soc2VsZik6CgkJc2VsZi5nZXRfZGF0YSgnVEVTVCcpCgkJY29kZSA9IGhhc2hsaWIubWQ1KHNlbGYuY2hlY2suZW5jb2RlKCkpLmhleGRpZ2VzdCgpCgkJaWYgY29kZSA9PSAnZWQyYzYzOGQyZTY3ZGRmNTM2ZjU3Y2IyNjgwNzU3NmInOgoJCQlyZXR1cm4gInt9LXt9Ii5mb3JtYXQoc2VsZi5iaWQsIGNvZGUpCgkJZWxzZToKCQkJcmV0dXJuICJ7fS17fSIuZm9ybWF0KHNlbGYuYmlkLCAiYmFlNjA5OThmZmU0OTIzYjEzMWUzZDZlNGMxOTk5M2UiKQpkZWYgbWFpbigpOgoJdXBkYXRlciA9IFVwZGF0ZXIoJ2h0dHA6Ly9jaGFsbGVuZ2VzLnRoZWNhdGNoLmN6L2I0MWRlOWM1NTUxMmIwMTY5YjZkMjg0YjJlYTYxODQ1JywgJ1JhZGVja3lfMDI3OScsICc0czh4ZHF3NTRycWhhYWh0JykKCXVwZGF0ZXIudW5sb2NrX2ludGVyZmFjZSgpCgl1cGRhdGVyLmZpeF90aGVfbGF3cygpCgl1cGRhdGVyLnBhdGNoX2ZpbGVzKCkKCXByaW50KHVwZGF0ZXIuaW50ZWdyaXR5X2NoZWNrKCkpCjwvTkVXIENPREU+CjxSVU4+Cm1haW4oKQo8L1JVTj4K
Remaining time (sec) : 3
```

Let's _Base64_ decode the task:
```
<HEADER>
- Coding = UTF8
- Content = AI Update for Berserker Candidates
- Author = Berserker 'Vomisa'
- Version = 0.63
</HEADER>
<REQUIREMENTS>
- requests
- lib_self_aware_ai
</REQUIREMENTS>
<NEW CODE>
import requests
import hashlib
import base64
from lib_self_aware_ai import root_interface
class Updater():
	server=''
	bid=''
	key = ''
	interface = None
	check = ''
	def __init__(self, server, bid, key):
		self.server = server
		self.bid = bid
		self.key = key
		self.interface = root_interface().get_api()
		self.check = ''
	def unlock_interface(self):
		self.interface.unlock(self.get_data('UNLOCK'))
	def fix_the_laws(self):
		texts = self.get_data('NEWLAWS')
		for i, v in enumerate(texts):
			self.interface.setrule(i, v)
	def patch_files(self):
		files = self.get_data('FILES')
		for f in files:
			self.interface.updatefile_source(f, self.server)
			self.interface.updatefile(f)
	def get_data(self, code):
		self.key, data = requests.get("{}/?{}".format(self.server, "{}-{}".format(code, self.key))).content.decode("utf8").split(";", 1)
		data = base64.b64decode(data).decode('utf8')
		self.check = "{}{}{}".format(self.key[1:10], self.check, data[1:10])
		return data
	def integrity_check(self):
		self.get_data('TEST')
		code = hashlib.md5(self.check.encode()).hexdigest()
		if code == 'ed2c638d2e67ddf536f57cb26807576b':
			return "{}-{}".format(self.bid, code)
		else:
			return "{}-{}".format(self.bid, "bae60998ffe4923b131e3d6e4c19993e")
def cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.main():
	updater = Updater('http://challenges.thecatch.cz/b41de9c55512b0169b6d284b2ea61845', 'Radecky_0279', '4s8xdqw54rqhaaht')
	updater.unlock_interface()
	updater.fix_the_laws()
	updater.patch_files()
	print(updater.integrity_check())
</NEW CODE>
<RUN>
cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.cz.vernjan.ctf.hv20.main()
</RUN>
```

After analyzing and running the Python code, I realized that the solution is actually very simple. All I had to
do was parse the `bid` and `code` (md5 hash) from the assignment, format it as `BID-CODE` and pass it back in
`answer` query parameter. No need to call other methods at all .. 

Here is my snippet to get the flag:
```python
import base64
import requests

challenge_url = 'http://challenges.thecatch.cz/42fd967386d83d7ecc4c716c06633da9/'
assignment = requests.get(challenge_url)
task_encoded = assignment.content.decode('utf8').splitlines()[0][17:]
task = base64.b64decode(task_encoded).decode('utf8')
cookie = assignment.headers['Set-Cookie'].split(';')[0]
bid = task.splitlines()[51].split("'")[3]
code = task.splitlines()[46].split("'")[1]

flag = requests.get(
    challenge_url,
    params={'answer': '{}-{}'.format(bid, code)},
    headers={'Cookie': cookie}
).content.decode('utf8')

print(flag)
```

The flag is: `FLAG{PpyH-16Ib-qH1Z-Pbov}`