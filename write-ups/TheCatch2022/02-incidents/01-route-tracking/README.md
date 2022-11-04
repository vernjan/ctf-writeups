# Route tracking

Hi, packet inspector,

our company uses on-board route recorders, so traffic controller can optimize movement of all vehicles and also control
the schedule. Any route can be described by a text string that contains the codes of individual sites in the order in
which they were visited (except depot, because each drive starts and also ends there).

Unfortunately, one of the recorders has been damaged and the particular sites were not recorded, just the total length
of the route is known (exactly `163 912` meters). In addition, the driver told us that he never visited the same place
more than once (except depot, of course).

Your task is to identify the exact route of the vehicle.

Download [the map of vehicle operating area and backround info](route_tracking.zip) (MD5
checksum `5fd3f52bcb404eae543eba68d7f4bb0a`).

May the Packet be with you!

---

DOT is a [graph description language](https://en.wikipedia.org/wiki/DOT_(graph_description_language)).

I loaded the graph into [NetworkX](https://networkx.org/) Python library and did a _depth-first search_,
looking for the path (from depot, i.e. node `000`, back to depot) of the given total distance.

```python
import networkx as nx

g = nx.nx_agraph.read_dot("Area_52.dot")

visited_nodes = set()
path = list()


def dfs(node_id, total_distance):
    if node_id in visited_nodes:
        if node_id == "000" and total_distance == 163912:
            print("Solution found!")
            nodes_to_letters = {n[0]: n[1].get("code", "") for n in g.nodes(data=True)}
            print("".join(nodes_to_letters[n] for n in path))
            exit(0)

    else:
        visited_nodes.add(node_id)
        path.append(node_id)

        node = g[node_id]

        for neighbor_node_id in g.neighbors(node_id):
            distance = int(node[neighbor_node_id][0]['dist'])
            dfs(neighbor_node_id, total_distance + distance)

        visited_nodes.discard(node_id)
        path.remove(node_id)


dfs("000", 0)
```

Script outputs:

```
Solution found!
FLAG{SLiH-QPWV-hIm5-hWcU}
```