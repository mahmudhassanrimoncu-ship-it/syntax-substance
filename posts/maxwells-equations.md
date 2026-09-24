---
layout: post-page.njk
title: "Why Maxwell's Equations Matter"
description: "A visual intuition for the four equations that connect electricity, magnetism, light, and waves."
category: Physics
readTime: 6
date: 2026-09-24
tags:
  - physics
  - mathematics
  - electromagnetism
---

At first glance, Maxwell's equations look intimidating. Their real power comes from how each equation describes a relationship between a field and its source or behaviour.

$$\nabla \cdot \mathbf{E} = \frac{\rho}{\varepsilon_0}$$

The equation says that electric charge acts as a source of electric field divergence.

The equations are especially useful because they can be written compactly while still supporting concrete predictions about electromagnetic waves.

```js
const waveSpeed = 1 / Math.sqrt(mu0 * epsilon0);
console.log(waveSpeed); // approximately 299,792,458 m/s
```

That number is not just a coding exercise. It is the speed of light in vacuum, emerging from electromagnetic constants.
