//! The lattice — **wheels within wheels**.
//!
//! > "…a wheel in the middle of a wheel." — Ezekiel 1:16
//!
//! Layers form a forest by their `parent` links, ordered by a sensitivity/
//! clearance `level`. The load-bearing invariant is **no layer widens itself**:
//! a child, nested inside its parent like an inner wheel, may never carry a
//! higher `level` than the parent that contains it. A policy that widens a
//! child is refused ([`Lattice::validate_no_widening`]).
//!
//! For [`Edition::Business`](crate::policy::Edition::Business) the same `level`
//! drives Bell-LaPadula: **no read up** (a subject may read only at or below its
//! clearance) and **no write down** (a subject may write only at or above its
//! clearance). Those checks live on the evaluator; the helpers here
//! ([`Lattice::level`], [`Lattice::may_read`], [`Lattice::may_write`]) express
//! them.

use std::collections::BTreeMap;

use crate::policy::{Layer, PolicyError};

/// A resolved partial order over layers: each layer's clearance `level` and its
/// parent link. Built once by [`Lattice::build`]; parents are proven to resolve
/// and to be acyclic, so ancestry queries always terminate.
#[derive(Debug, Clone)]
pub struct Lattice {
    level: BTreeMap<String, u32>,
    parent: BTreeMap<String, Option<String>>,
}

impl Lattice {
    /// Build the lattice from the declared layers: every named `parent` must
    /// resolve to a declared layer, and the parent chains must be acyclic.
    pub fn build(layers: &[Layer]) -> Result<Lattice, PolicyError> {
        let mut level = BTreeMap::new();
        let mut parent = BTreeMap::new();
        for l in layers {
            level.insert(l.name.clone(), l.level);
            parent.insert(l.name.clone(), l.parent.clone());
        }

        // Every named parent resolves.
        for l in layers {
            if let Some(p) = &l.parent {
                if !level.contains_key(p) {
                    return Err(PolicyError::UnknownLayerParent {
                        layer: l.name.clone(),
                        parent: p.clone(),
                    });
                }
            }
        }

        let lattice = Lattice { level, parent };

        // No cycles: walking parents from any layer must reach a root.
        for l in layers {
            lattice.check_acyclic(&l.name)?;
        }

        Ok(lattice)
    }

    fn check_acyclic(&self, start: &str) -> Result<(), PolicyError> {
        let mut cur = start.to_string();
        let mut hops = 0usize;
        let bound = self.parent.len() + 1;
        loop {
            match self.parent.get(&cur).and_then(|p| p.as_ref()) {
                None => return Ok(()),
                Some(p) => {
                    hops += 1;
                    if hops > bound {
                        return Err(PolicyError::LayerCycle {
                            layer: start.to_string(),
                        });
                    }
                    cur = p.clone();
                }
            }
        }
    }

    /// The clearance/sensitivity level of `layer`, if it exists.
    pub fn level(&self, layer: &str) -> Option<u32> {
        self.level.get(layer).copied()
    }

    /// Reject any child whose `level` exceeds its parent's — *no layer widens
    /// itself*. This is the reject rule "child > parent".
    pub fn validate_no_widening(&self, layers: &[Layer]) -> Result<(), PolicyError> {
        for l in layers {
            if let Some(parent_name) = &l.parent {
                let parent_level = self.level(parent_name).expect("parent resolved in build");
                if l.level > parent_level {
                    return Err(PolicyError::ChildWidensParent {
                        child: l.name.clone(),
                        child_level: l.level,
                        parent: parent_name.clone(),
                        parent_level,
                    });
                }
            }
        }
        Ok(())
    }

    /// Is `ancestor` a strict (proper) ancestor of `descendant` in the wheel
    /// tree — i.e. above it, closer to the root? Used to detect inverted
    /// control in the personal edition.
    pub fn is_strict_ancestor(&self, ancestor: &str, descendant: &str) -> bool {
        let mut cur = self.parent.get(descendant).and_then(|p| p.clone());
        let bound = self.parent.len() + 1;
        let mut hops = 0usize;
        while let Some(node) = cur {
            if node == ancestor {
                return true;
            }
            hops += 1;
            if hops > bound {
                return false; // build() already proved acyclic; defensive.
            }
            cur = self.parent.get(&node).and_then(|p| p.clone());
        }
        false
    }

    /// Bell-LaPadula **no read up**: a subject at `subject_level` may read a
    /// resource at `resource_level` only if it is at or above the resource.
    pub fn may_read(subject_level: u32, resource_level: u32) -> bool {
        subject_level >= resource_level
    }

    /// Bell-LaPadula **no write down**: a subject at `subject_level` may write a
    /// resource at `resource_level` only if it is at or below the resource.
    pub fn may_write(subject_level: u32, resource_level: u32) -> bool {
        subject_level <= resource_level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(name: &str, parent: Option<&str>, level: u32) -> Layer {
        Layer {
            name: name.into(),
            parent: parent.map(String::from),
            level,
        }
    }

    #[test]
    fn no_widening_accepts_narrowing_child() {
        let layers = vec![layer("root", None, 3), layer("inner", Some("root"), 2)];
        let lat = Lattice::build(&layers).unwrap();
        assert!(lat.validate_no_widening(&layers).is_ok());
    }

    #[test]
    fn no_widening_rejects_child_over_parent() {
        let layers = vec![layer("root", None, 2), layer("inner", Some("root"), 5)];
        let lat = Lattice::build(&layers).unwrap();
        let err = lat.validate_no_widening(&layers).unwrap_err();
        assert!(matches!(err, PolicyError::ChildWidensParent { .. }));
    }

    #[test]
    fn ancestry_and_blp() {
        let layers = vec![
            layer("root", None, 3),
            layer("mid", Some("root"), 2),
            layer("leaf", Some("mid"), 1),
        ];
        let lat = Lattice::build(&layers).unwrap();
        assert!(lat.is_strict_ancestor("root", "leaf"));
        assert!(!lat.is_strict_ancestor("leaf", "root"));
        assert!(Lattice::may_read(3, 1)); // read down: ok
        assert!(!Lattice::may_read(1, 3)); // read up: denied
        assert!(Lattice::may_write(1, 3)); // write up: ok
        assert!(!Lattice::may_write(3, 1)); // write down: denied
    }
}
