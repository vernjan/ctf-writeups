#include <vector>

#include <aoc/StarBase.h>
#include <aoc/aoc_utils.h>
#include <map>

using namespace std;

struct node {
    string name;
    set<node *> links;
};

void update_node(map<string, node*> &nodes, const string &node1_name, const string &node2_name) {
    if (!nodes.contains(node1_name)) {
        nodes[node1_name] = new node{node1_name};
    }
    if (!nodes.contains(node2_name)) {
        nodes[node2_name] = new node{node2_name};
    }
    nodes[node1_name]->links.insert(nodes[node2_name]);
    nodes[node2_name]->links.insert(nodes[node1_name]);
}

struct S1 : public StarBase {
    S1() : StarBase(12, 1) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        map<string, node*> nodes;
        for (const auto &line: data) {
            auto link = aoc::split(line, "-");
            update_node(nodes, link[0], link[1]);
        }
        nodes = {};
        return 0;
    }
};

struct S2 : public StarBase {
    S2() : StarBase(12, 2) {}

    [[nodiscard]] size_t execute(const vector<string> &data) const override {
        return 0;
    }
};


int main() {
    S1 s1;
    s1.run_test(226);
    s1.run(0);

    S2 s2;
    s2.run_test(0);
    s2.run(0);

    return 0;
}