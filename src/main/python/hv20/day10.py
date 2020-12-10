import networkx as nx

G = nx.Graph()

f = open("edges.txt", "r")
for line in f:
    edge = line.split()
    G.add_nodes_from(edge)
    G.add_edge(edge[0], edge[1])

kids = "104 118 55 51 123 110 111 116 95 84 72 69 126 70 76 65 71 33 61 40 124 115 48 60 62 83 79 42 82 121 125 45 98 114 101 97 100"
for kid in kids.split():
    print (chr(nx.node_clique_number(G, kid)), end='')
