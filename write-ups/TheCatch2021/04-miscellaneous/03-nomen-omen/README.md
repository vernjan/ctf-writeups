# Nomen Omen

Hi Expert,

oh no, bad news! All archaeologist computers connected to discovered port were infected by some kind of self-changing malware - it changes its file name and also its hash differs (i.e. the content change) after each run. Find the algorithm of name change in order to get some IoC (Indicators of Compromise). Download the file [nomen-omen.zip](nomen-omen.zip) (sha256 fingerprint: `510a672a60289d708c4d41b18f73c50dbacf98e852065242946d6d846b182a32`; password for archive: `infected`).

Good Luck!

---

The archive contains single file `{iyyrzthmlfpoljlwaq-jhsye.exe`.

For some reason, the executable doesn't work in standard Windows Command prompt. It prints:
```
Bad filename... tampering detected...
Bye bye!
```

I thought this was a part of the challenge, so I started with reverse engineering.
[IDA Freeware](https://hex-rays.com/ida-free/) worked quite well. I could easily debug it.
However, once I got onto the name changing algorithm, it looked way to complicated. I also discovered the executable
works without any issues using PowerShell or MINGW64.

Running the executable creates a new almost identical executable in `APPDATA` (environment variable)
defined path. The new executable has a different name. Running this new executable, again, creates
a new executable with a new name. Here is the start of the chain:
```
{iyyrzthmlfpoljlwaq-jhsye.exe
r{vpxoqumzqbypgaqa-sogpq}.exe
xrsex--fwlnfseravuyrj-ehz.exe
xgaremyuqpyxxeouqtnjgsynw.exe
et{c--gyvevxsydtnleadynne.exe
..
```

The idea how to get the flag is straight forward. Keep creating new executables until the executable name is the
flag. I really hoped I can do it with a shell script and avoid reversing the algorithm (for performance reasons).
Luckily, the script was good enough:
```shell
APPDATA='/d/ctfs/nomen'

# Run the original executable
./{iyyrzthmlfpoljlwaq-jhsye.exe
 
echo

for run in {2..1000}; do
  # Run the last executable (sorted by timestamp)
  ./$(ls -t | head -n 1)
  echo $run
  if [ "$(ls -t | head -n 1)" == flag* ]; then
    echo "DONE"
    exit 0
  fi
done
```

After ~700 cycles, executable named `flag{fwsg-iboz-hmlt-pqhz}.exe` gets created.