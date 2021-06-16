use super::*;

#[derive(Debug)]
struct MerkleNode {
    value: Hash,
    children: Option<(usize, usize)>,
    size: usize,
}

impl MerkleNode {
    pub fn new(x: &impl Hashable) -> MerkleNode {
        MerkleNode {
            value: x.hash(),
            children: None,
            size: 1,
        }
    }

    pub fn empty() -> MerkleNode {
        MerkleNode {
            value: Hash::empty(),
            children: None,
            size: 0,
        }
    }

    pub fn merge(tree: &[MerkleNode], left: usize, right: usize) -> MerkleNode {
        let size = tree[left].size + tree[right].size;
        MerkleNode {
            value: hash![tree[left], tree[right], size],
            children: Some((left, right)),
            size,
        }
    }
}

impl Hashable for MerkleNode {
    fn hash(&self) -> Hash {
        self.value
    }
}

#[derive(Debug)]
pub struct MerkleTree {
    nodes: Vec<MerkleNode>,
    root: usize,
    leaves: usize, // Number of leaves
}

impl MerkleTree {
    pub fn new<H: Hashable>(leaves: &[H]) -> MerkleTree {
        // Return empty tree if there is no leaf
        if leaves.is_empty() {
            return MerkleTree {
                nodes: vec![MerkleNode::empty()],
                root: 0,
                leaves: 0,
            };
        }
        // Create a MerkleNode for each leaf
        let mut nodes: Vec<MerkleNode> = leaves.iter().map(|leaf| MerkleNode::new(leaf)).collect();

        // Reference the indices of the leaves
        let mut current_layer: Vec<usize> = (0..nodes.len()).collect();

        // For keeping track of the previous layer
        let mut prev_layer = Vec::<usize>::new();

        while current_layer.len() != 1 {
            // prev_layer = current_layer, but reduces allocations
            std::mem::swap(&mut prev_layer, &mut current_layer);
            current_layer.clear();

            // Iterate through and merge all pairs from the previous layer
            for i in (0..prev_layer.len() - 1).step_by(2) {
                let left = prev_layer[i];
                let right = prev_layer[i + 1];

                nodes.push(MerkleNode::merge(&nodes, left, right));
                current_layer.push(nodes.len() - 1);
            }
            // If there's one node left over, add it to the end
            if prev_layer.len() % 2 == 1 {
                current_layer.push(prev_layer.len() - 1);
            }
        }
        MerkleTree {
            nodes,
            root: current_layer[0],
            leaves: leaves.len(),
        }
    }
}

impl Hashable for MerkleTree {
    fn hash(&self) -> Hash {
        self.nodes[self.root].hash()
    }
}

impl PartialEq for MerkleTree {
    fn eq(&self, rhs: &Self) -> bool {
        self.hash() == rhs.hash()
    }
}

impl Eq for MerkleTree {}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test() {
        MerkleTree::new(&Vec::<u8>::new());
        MerkleTree::new::<u8>(&[1]);
        MerkleTree::new::<u8>(&[1, 2]);
        MerkleTree::new::<u8>(&[1, 2, 3]);
        MerkleTree::new::<u8>(&[1, 2, 3, 4]);
        MerkleTree::new::<u8>(&[1, 2, 3, 4, 5]);
    }
}