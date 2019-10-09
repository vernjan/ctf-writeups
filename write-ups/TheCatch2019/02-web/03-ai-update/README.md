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
See [sample response](assignment.txt) from the _Berserker's web_.

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
def main():
	updater = Updater('http://challenges.thecatch.cz/b41de9c55512b0169b6d284b2ea61845', 'Radecky_0279', '4s8xdqw54rqhaaht')
	updater.unlock_interface()
	updater.fix_the_laws()
	updater.patch_files()
	print(updater.integrity_check())
</NEW CODE>
<RUN>
main()
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