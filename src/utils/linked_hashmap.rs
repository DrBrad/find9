use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq)]
pub struct LinkedHashMap<K: Eq + Hash, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
    capacity: usize
}

impl<K, V> LinkedHashMap<K, V> where K: Eq + Hash + Clone, V: Clone {

    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity: 0
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.map.len() >= self.capacity {
            if let Some(eldest) = self.order.pop_front() {
                self.map.remove(&eldest);
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    pub fn values(&self) -> Vec<V> {
        self.order
            .iter()
            .filter_map(|key| self.map.get(key).cloned())
            .collect()
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn entry(&mut self, key: K) -> std::collections::hash_map::Entry<K, V> {
        self.map.entry(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.order.iter().filter_map(move |key| self.map.get_key_value(key))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
