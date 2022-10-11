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
            # print("Visiting %s from %s. Current %d, total  %d"
            #       % (neighbor_node_id, node_id, distance, total_distance + distance))
            dfs(neighbor_node_id, total_distance + distance)

        # print("Stepping back. Discarding %s" % node_id)
        visited_nodes.discard(node_id)
        path.remove(node_id)


dfs("000", 0)
