# HV20.10 Be patient with the adjacent

_Ever wondered how Santa delivers presents, and knows which groups of friends should be provided with the best gifts? It should be as great or as large as possible! Well, here is one way._

_Hmm, I cannot seem to read the file either, maybe the internet knows?_

[Download](what.col.b)

## Hints
- _Hope this cliques for you_
- _Segfaults can be fixed - maybe read the source_
- _There is more than one thing you can do with this type of file! Try other options..._
- _Groups, not group_

---

What is this file?
```
$ strings what.col.b
c --------------------------------
c Reminder for Santa:
c   104 118 55 51 123 110 111 116 95 84 72 69 126 70 76 65 71 33 61 40 124 115 48 60 62 83 79 42 82 121 125 45 98 114 101 97 100 are the nicest kids.
c   - bread.
c --------------------------------
p edges 18876 439050
```

Numbers decode to `hv73{not_THE~FLAG!=(|s0<>SO*Ry}-bread`
(notice that all chars are unique).

The rest of the file is a binary gibberish.

We have edges and cliques, this is about [Clique (graph theory)](https://en.wikipedia.org/wiki/Clique_(graph_theory)).

Let's try to understand the file format.
Googling for `file extension "col.b"` points to https://reference.wolfram.com/language/guide/ListingOfAllFormats.html:
`col.b` is for `DIMACS graph data format`

List of specs:
- [ASCII version](https://github.com/akinanop/mvl-solver/wiki/DIMACS-Graph-Format)
- [binary version](http://archive.dimacs.rutgers.edu/pub/challenge/graph/translators/binformat/README.binformat)
- [translator](http://archive.dimacs.rutgers.edu/pub/challenge/graph/translators/binformat/ANSI/) (`bin2asc` and `asc2bin`)

I compiled the translator and ran it:
```
$ ./bin2asc what.col.b
Segmentation fault
```

Fortunately, this is easy to fix. Make this changes in `genbin.h`:
```
#define MAX_NR_VERTICES		20000
#define MAX_NR_VERTICESdiv8	2500
```

Now we can translate from the binary format to ASCII and, hopefully, make some sense out of it:
```
$ ./bin2asc what.col.b
$ head what.col
c -------------------------------- 
c Reminder for Santa:
c   104 118 55 51 123 110 111 116 95 84 72 69 126 70 76 65 71 33 61 40 124 115 48 60 62 83 79 42 82 121 125 45 98 114 101 97 100 are the nicest kids.
c   - bread.
c -------------------------------- 
p edges 18876 439050
e 30 18
e 42 24
e 42 29
e 48 7
...
```

My first idea was to print the largest cliques. I used [JGraphT](https://jgrapht.org/) library.
I sorted the cliques by the total number of nodes. This is the result:
```
[125, 123, 120, 118, 117, 116, 114, 113, 110, 109, 108, 107, 106, 105, 104, 103, 102, 100, 99, ...
```

Not bad, all within ASCII range. After a while, I got the idea to **map _the nicest kids_ from Santa's reminder
to cliques to which they belong** (kid/node is a member of group/clique).

The idea was correct, unfortunately, this library didn't provide any good API.

I was advised to use this very nice Python library [NetworkX](https://networkx.org/documentation/stable/tutorial.html):
```python
import networkx as nx

G = nx.Graph()

f = open("edges.txt", "r")
# 30 18
# 42 24
# 42 29
# 48 7
# 48 25
#..

for line in f:
    edge = line.split()
    G.add_nodes_from(edge)
    G.add_edge(edge[0], edge[1])

kids = "104 118 55 51 123 110 111 116 95 84 72 69 126 70 76 65 71 33 61 40 124 115 48 60 62 83 79 42 82 121 125 45 98 114 101 97 100"
for kid in kids.split():
    print (chr(nx.node_clique_number(G, kid)), end='')
```

The flag is `HV20{Max1mal_Cl1qu3_Enum3r@t10n_Fun!}`
