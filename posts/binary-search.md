---
layout: post-page.njk
title: "The Logic Behind Binary Search"
description: "Why repeatedly cutting the search space in half turns a large problem into a logarithmic one."
category: Computing
readTime: 5
date: 2026-09-18
tags:
  - computer science
  - algorithms
  - programming
---

Suppose a sorted list contains 1,000 items. Checking every item could take 1,000 comparisons. Binary search instead checks the middle, then keeps only the half that can still contain the answer.

$$T(n) = T\left(\frac{n}{2}\right) + O(1) \Rightarrow T(n) = O(\log n)$$

Each comparison cuts the remaining search space roughly in half.

```js
let low = 0, high = data.length - 1;
while (low <= high) {
  const mid = Math.floor((low + high) / 2);
  // compare data[mid], then discard one half
}
```

The important idea is not the particular loop. It is the invariant: the answer, if it exists, stays inside the remaining interval.
