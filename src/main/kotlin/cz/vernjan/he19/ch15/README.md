# 15 - Seen in Steem

*An unknown person placed a secret note about Hacky Easter 2019 in the Steem blockchain.*
*It happend during Easter 2018.*

*Go find the note, and enter it in the egg-o-matic below. Lowercase only, and no spaces!*

---

I started with looking up info about [Steem](https://en.wikipedia.org/wiki/Steem). I found this link to [Steem block
explorer](https://steemblockexplorer.com/) to be very useful.

Another key information to know is when *Easter* took place in 2018 and it was on **1th April**.

Now using the *Steem block explorer* and binary search I quickly determined that I need to go through blocks from
21,170,000 to 21,200,000. That's only 30,000 blocks.

I wrote a small Kotlin program [SteemCrawler](SteemCrawler.kt) which helped me with that. The crawler
downloaded all the blocks to my local filesystem.

This is the example of the call to get the block
```
POST https://api.steemit.com/
{"id":4,"jsonrpc":"2.0","method":"call","params":["database_api","get_block",[21170000]]}
```

Once all the blocks where downloaded, I used `grep` to look for the workd `hacky`:
```
$ grep -rioP '.{0,10}hacky.{0,20}' steem/

steem/21187964.json:","memo":"Hacky Easter 2019 takes p
steem/21187549.json::"fardelynhacky","author":"dyslexic
steem/21187567.json::"fardelynhacky","author":"dyslexic
```

Nice, the message is in the block [21187964](https://steemblockexplorer.com/block/21187964):

```Hacky Easter 2019 takes place between April and May 2019. Take a note: nomoneynobunny```