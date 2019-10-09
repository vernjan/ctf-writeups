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

[Sample response](assignment-sample.txt) from the _Berserker's web_.

Decoding base64 yields:
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

