#include <vector>

#include <algorithm>
#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>
#include <map>

using namespace std;

struct node {
    string name;
    set<node *> links;
};

struct path {
    vector<node *> nodes;
    bool double_visit;
};


size_t count_all_paths(const vector<string> &data, bool allow_double_visit);

struct S1 : public StarBase {
    S1() : StarBase(12, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return count_all_paths(data, false);
    }
};

struct S2 : public StarBase {
    S2() : StarBase(12, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return count_all_paths(data, true);
    }
};

void update_node(map<string, node> &nodes, const string &node1_name, const string &node2_name) {
    if (!nodes.contains(node1_name)) {
        nodes[node1_name] = node{node1_name};
    }
    if (!nodes.contains(node2_name)) {
        nodes[node2_name] = node{node2_name};
    }
    nodes[node1_name].links.insert(&nodes[node2_name]);
    nodes[node2_name].links.insert(&nodes[node1_name]);
}

bool is_visited(const vector<node *> &nodes, const node *node) {
    return find(nodes.begin(), nodes.end(), node) != nodes.end();
}

size_t count_all_paths(const vector<string> &data, bool allow_double_visit) {
    map<string, node> nodes_map;
    for (const auto &line: data) {
        auto link = aoc::split(line, "-");
        update_node(nodes_map, link[0], link[1]);
    }

    int total = 0;
    node *start_node = &nodes_map["start"];
    vector<path> paths;
    paths.emplace_back(vector<node *>{start_node}, !allow_double_visit);
    while (!paths.empty()) {
        path current_path = paths.back();
        paths.pop_back();
        vector<node *> nodes = current_path.nodes;
        node *current_node = nodes.back();
        if (current_node->name == "end") {
            total++;
        } else {
            for (node *link: current_node->links) {
                if (isupper(link->name[0]) || !current_path.double_visit || !is_visited(nodes, link)) {
                    if (link->name == "start") {
                        continue;
                    }
                    path new_path = current_path;
                    new_path.nodes.push_back(link);

                    if (!current_path.double_visit && islower(link->name[0]) && is_visited(nodes, link)) {
                        new_path.double_visit = true;
                    }
                    paths.push_back(new_path);
                }
            }
        }
    }

    return total;
}


int main() {
    S1 s1;
    s1.run_test(10);
    s1.run(5178);

    S2 s2;
    s2.run_test(36);
    s2.run(130094);

    return 0;
}