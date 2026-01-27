/*
File: trie.go
Version: 1.3.0 (Fix Search Match Logic)
Description: A generic, high-performance Domain Radix Trie.
             FIXED: Search now correctly distinguishes between Exact (full match) and Wildcard matches.
             Prevents "Exact" log for partial path matches.
*/

package main

import (
	"strings"
)

// TrieNode represents a node in the domain trie.
type TrieNode[T any] struct {
	Children    map[string]*TrieNode[T]
	Value       T    // Stored inline
	Wildcard    T    // Stored inline
	HasValue    bool // Flag to indicate Value presence (Exact match for this node)
	HasWildcard bool // Flag to indicate Wildcard presence (*.this_node)
}

// DomainTrie is a generic trie for domain suffixes.
type DomainTrie[T any] struct {
	Root *TrieNode[T]
}

func NewDomainTrie[T any]() *DomainTrie[T] {
	return &DomainTrie[T]{Root: &TrieNode[T]{}}
}

// Insert adds a value to the trie.
func (t *DomainTrie[T]) Insert(domain string, value T) {
	parts := strings.Split(domain, ".")

	// Handle "*.example.com" or ".example.com"
	isWildcard := false
	if len(parts) > 0 && (parts[0] == "*" || parts[0] == "") {
		isWildcard = true
		parts = parts[1:]
	}

	node := t.Root
	// Iterate backwards (com -> example -> google)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		if node.Children == nil {
			node.Children = make(map[string]*TrieNode[T])
		}

		child, ok := node.Children[part]
		if !ok {
			child = &TrieNode[T]{}
			node.Children[part] = child
		}
		node = child
	}

	if isWildcard {
		node.Wildcard = value
		node.HasWildcard = true
		// Some configs treat ".domain" as both exact and wildcard
		// If the input was ".example.com", we effectively block "example.com" AND "*.example.com"
		if strings.HasPrefix(domain, ".") {
			node.Value = value
			node.HasValue = true
		}
	} else {
		node.Value = value
		node.HasValue = true
	}
}

// Search finds the best match for a query domain.
// Returns:
//   value: The value found (zero value if not found)
//   found: True if a match was found
//   isWildcard: True if the match was a wildcard match, False if exact
// Priority: Exact Match > Deepest Wildcard Match.
func (t *DomainTrie[T]) Search(qName string) (T, bool, bool) {
	node := t.Root
	var lastWildcard T
	var foundWildcard bool
	fullMatch := false

	// Iterate backwards using string indices to avoid splitting/allocation
	end := len(qName)
	for end > 0 {
		start := strings.LastIndexByte(qName[:end], '.')
		part := qName[start+1 : end]

		// Capture wildcard at this level if it exists (before moving deeper)
		if node.HasWildcard {
			lastWildcard = node.Wildcard
			foundWildcard = true
		}

		if node.Children == nil {
			break
		}

		next, ok := node.Children[part]
		if !ok {
			break
		}
		node = next

		if start == -1 {
			fullMatch = true
			break
		}
		end = start
	}

	// 1. Check Exact Match (Only if we matched the entire query string)
	if fullMatch && node.HasValue {
		return node.Value, true, false
	}

	// 2. Check Wildcard at the current node
	// If we stopped early (not fullMatch), this node represents a prefix of the query.
	// If this node has a wildcard, it matches the rest of the query.
	// Example: Query "foo.example.com", Node "example". HasWildcard=true. Match!
	if node.HasWildcard {
		return node.Wildcard, true, true
	}

	// 3. Fallback to deepest wildcard found along the path
	if foundWildcard {
		return lastWildcard, true, true
	}

	var zero T
	return zero, false, false
}

