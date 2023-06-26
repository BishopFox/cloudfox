package internal

import (
	"github.com/shivamMg/ppds/tree"
)

type Node struct {
	ID string
	c    []*Node
}

func (n *Node) Data() interface{} {
	return n.ID
}

func (n *Node) Children() (children []tree.Node) {
	for _, c := range n.c {
		children = append(children, tree.Node(c))
	}
	return
}

func (n *Node) Add(child Node) {
	n.c = append(n.c, &child)
	return
}
