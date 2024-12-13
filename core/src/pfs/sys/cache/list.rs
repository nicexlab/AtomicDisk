// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..
use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::mem;
use core::ptr::NonNull;
use crate::prelude::*;
/// A doubly-linked list with owned nodes.
pub struct LinkedList {
    head: Option<NonNull<Node>>,
    tail: Option<NonNull<Node>>,
    len: usize,
    marker: PhantomData<Box<Node>>,
}

pub struct Node {
    next: Option<NonNull<Node>>,
    prev: Option<NonNull<Node>>,
    element: u64,
}

pub struct Iter<'a> {
    head: Option<NonNull<Node>>,
    tail: Option<NonNull<Node>>,
    len: usize,
    marker: PhantomData<&'a Node>,
}

impl<'a> fmt::Debug for Iter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Iter")
            .field(&*mem::ManuallyDrop::new(LinkedList {
                head: self.head,
                tail: self.tail,
                len: self.len,
                marker: PhantomData,
            }))
            .field(&self.len)
            .finish()
    }
}

impl<'a> Clone for Iter<'a> {
    fn clone(&self) -> Self {
        Iter { ..*self }
    }
}

/// A mutable iterator over the elements of a `LinkedList`.
pub struct IterMut<'a> {
    head: Option<NonNull<Node>>,
    tail: Option<NonNull<Node>>,
    len: usize,
    marker: PhantomData<&'a mut Node>,
}

impl<'a> fmt::Debug for IterMut<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("IterMut")
            .field(&*mem::ManuallyDrop::new(LinkedList {
                head: self.head,
                tail: self.tail,
                len: self.len,
                marker: PhantomData,
            }))
            .field(&self.len)
            .finish()
    }
}

/// An owning iterator over the elements of a `LinkedList`.
pub struct IntoIter {
    list: LinkedList,
}

impl fmt::Debug for IntoIter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("IntoIter").field(&self.list).finish()
    }
}

impl Node {
    fn new(element: u64) -> Self {
        Node {
            next: None,
            prev: None,
            element,
        }
    }

    #[allow(clippy::boxed_local)]
    fn into_element(self: Box<Self>) -> u64 {
        self.element
    }
}

// private methods
impl LinkedList {
    /// Adds the given node to the front of the list.
    #[inline]
    fn push_front_node(&mut self, mut node: Box<Node>) {
        // This method takes care not to create mutable references to whole nodes,
        // to maintain validity of aliasing pointers into `element`.
        unsafe {
            node.next = self.head;
            node.prev = None;
            let node = Some(Box::leak(node).into());

            match self.head {
                None => self.tail = node,
                // Not creating new mutable (unique!) references overlapping `element`.
                Some(head) => (*head.as_ptr()).prev = node,
            }

            self.head = node;
            self.len += 1;
        }
    }

    /// Removes and returns the node at the front of the list.
    #[inline]
    fn pop_front_node(&mut self) -> Option<Box<Node>> {
        // This method takes care not to create mutable references to whole nodes,
        // to maintain validity of aliasing pointers into `element`.
        self.head.map(|node| unsafe {
            let node = Box::from_raw(node.as_ptr());
            self.head = node.next;

            match self.head {
                None => self.tail = None,
                // Not creating new mutable (unique!) references overlapping `element`.
                Some(head) => (*head.as_ptr()).prev = None,
            }

            self.len -= 1;
            node
        })
    }

    /// Adds the given node to the back of the list.
    #[inline]
    fn push_back_node(&mut self, mut node: Box<Node>) {
        // This method takes care not to create mutable references to whole nodes,
        // to maintain validity of aliasing pointers into `element`.
        unsafe {
            node.next = None;
            node.prev = self.tail;
            let node = Some(Box::leak(node).into());

            match self.tail {
                None => self.head = node,
                // Not creating new mutable (unique!) references overlapping `element`.
                Some(tail) => (*tail.as_ptr()).next = node,
            }

            self.tail = node;
            self.len += 1;
        }
    }

    /// Removes and returns the node at the back of the list.
    #[inline]
    fn pop_back_node(&mut self) -> Option<Box<Node>> {
        // This method takes care not to create mutable references to whole nodes,
        // to maintain validity of aliasing pointers into `element`.
        self.tail.map(|node| unsafe {
            let node = Box::from_raw(node.as_ptr());
            self.tail = node.prev;

            match self.tail {
                None => self.head = None,
                // Not creating new mutable (unique!) references overlapping `element`.
                Some(tail) => (*tail.as_ptr()).next = None,
            }

            self.len -= 1;
            node
        })
    }

    /// Unlinks the specified node from the current list.
    ///
    /// Warning: this will not check that the provided node belongs to the current list.
    ///
    /// This method takes care not to create mutable references to `element`, to
    /// maintain validity of aliasing pointers.
    #[inline]
    unsafe fn unlink_node(&mut self, mut node: NonNull<Node>) {
        let node = node.as_mut(); // this one is ours now, we can create an &mut.

        // Not creating new mutable (unique!) references overlapping `element`.
        match node.prev {
            Some(prev) => (*prev.as_ptr()).next = node.next,
            // this node is the head node
            None => self.head = node.next,
        };

        match node.next {
            Some(next) => (*next.as_ptr()).prev = node.prev,
            // this node is the tail node
            None => self.tail = node.prev,
        };

        self.len -= 1;
    }

    pub unsafe fn move_to_head(&mut self, mut node: NonNull<Node>) {
        if self.is_empty() {
            return;
        }

        let node_ref = node.as_mut(); // this one is ours now, we can create an &mut.
        match node_ref.prev {
            Some(prev) => (*prev.as_ptr()).next = node_ref.next,
            // this node is the head node
            None => return,
        };

        match node_ref.next {
            Some(next) => (*next.as_ptr()).prev = node_ref.prev,
            // this node is the tail node
            None => self.tail = node_ref.prev,
        };

        node_ref.next = self.head;
        node_ref.prev = None;
        let node = Some(node);
        match self.head {
            None => self.tail = node,
            Some(head) => (*head.as_ptr()).prev = node,
        }

        self.head = node;
    }

    pub unsafe fn move_to_tail(&mut self, mut node: NonNull<Node>) {
        if self.is_empty() {
            return;
        }

        let node_ref = node.as_mut(); // this one is ours now, we can create an &mut.
        match node_ref.prev {
            Some(prev) => (*prev.as_ptr()).next = node_ref.next,
            // this node is the head node
            None => self.head = node_ref.next,
        };

        match node_ref.next {
            Some(next) => (*next.as_ptr()).prev = node_ref.prev,
            // this node is the tail node
            None => return,
        };

        node_ref.next = None;
        node_ref.prev = self.tail;
        let node = Some(node);
        match self.tail {
            None => self.head = node,
            Some(tail) => (*tail.as_ptr()).next = node,
        }

        self.tail = node;
    }

    #[inline]
    pub unsafe fn head_node_ref(&self) -> Option<NonNull<Node>> {
        self.head
    }

    #[inline]
    pub unsafe fn tail_node_ref(&self) -> Option<NonNull<Node>> {
        self.tail
    }
}

impl Default for LinkedList {
    /// Creates an empty `LinkedList<T>`.
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl LinkedList {
    /// Creates an empty `LinkedList`.
    pub const fn new() -> Self {
        LinkedList {
            head: None,
            tail: None,
            len: 0,
            marker: PhantomData,
        }
    }

    /// Moves all elements from `other` to the end of the list.
    pub fn append(&mut self, other: &mut Self) {
        match self.tail {
            None => mem::swap(self, other),
            Some(mut tail) => {
                // `as_mut` is okay here because we have exclusive access to the entirety
                // of both lists.
                if let Some(mut other_head) = other.head.take() {
                    unsafe {
                        tail.as_mut().next = Some(other_head);
                        other_head.as_mut().prev = Some(tail);
                    }

                    self.tail = other.tail.take();
                    self.len += mem::replace(&mut other.len, 0);
                }
            }
        }
    }

    /// Provides a forward iterator.
    #[inline]
    pub fn iter(&self) -> Iter {
        Iter {
            head: self.head,
            tail: self.tail,
            len: self.len,
            marker: PhantomData,
        }
    }

    /// Provides a forward iterator with mutable references.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut {
        IterMut {
            head: self.head,
            tail: self.tail,
            len: self.len,
            marker: PhantomData,
        }
    }

    /// Returns `true` if the `LinkedList` is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Returns the length of the `LinkedList`.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Removes all elements from the `LinkedList`.
    #[inline]
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Returns `true` if the `LinkedList` contains an element equal to the
    /// given value.
    pub fn contains(&self, x: &u64) -> bool {
        self.iter().any(|e| e == x)
    }

    /// Provides a reference to the front element, or `None` if the list is
    /// empty.
    #[inline]
    pub fn front(&self) -> Option<&u64> {
        unsafe { self.head.as_ref().map(|node| &node.as_ref().element) }
    }

    /// Provides a mutable reference to the front element, or `None` if the list
    /// is empty.
    #[inline]
    pub fn front_mut(&mut self) -> Option<&mut u64> {
        unsafe { self.head.as_mut().map(|node| &mut node.as_mut().element) }
    }

    /// Provides a reference to the back element, or `None` if the list is
    /// empty.
    #[inline]
    pub fn back(&self) -> Option<&u64> {
        unsafe { self.tail.as_ref().map(|node| &node.as_ref().element) }
    }

    /// Provides a mutable reference to the back element, or `None` if the list
    /// is empty.
    #[inline]
    pub fn back_mut(&mut self) -> Option<&mut u64> {
        unsafe { self.tail.as_mut().map(|node| &mut node.as_mut().element) }
    }

    /// Adds an element first in the list.
    pub fn push_front(&mut self, elt: u64) {
        self.push_front_node(Box::new(Node::new(elt)));
    }

    /// Removes the first element and returns it, or `None` if the list is
    /// empty.
        pub fn pop_front(&mut self) -> Option<u64> {
        self.pop_front_node().map(Node::into_element)
    }

    /// Appends an element to the back of a list.
    pub fn push_back(&mut self, elt: u64) {
        self.push_back_node(Box::new(Node::new(elt)));
    }

    /// Removes the last element from a list and returns it, or `None` if
    /// it is empty.
    pub fn pop_back(&mut self) -> Option<u64> {
        self.pop_back_node().map(Node::into_element)
    }

    /// Creates an iterator which uses a closure to determine if an element should be removed.
    pub fn drain_filter<F>(&mut self, filter: F) -> DrainFilter<'_, F>
    where
        F: FnMut(&mut u64) -> bool,
    {
        // avoid borrow issues.
        let it = self.head;
        let old_len = self.len;

        DrainFilter {
            list: self,
            it,
            pred: filter,
            idx: 0,
            old_len,
        }
    }
}

impl Drop for LinkedList {
    fn drop(&mut self) {
        struct DropGuard<'a>(&'a mut LinkedList);

        impl<'a> Drop for DropGuard<'a> {
            fn drop(&mut self) {
                // Continue the same loop we do below. This only runs when a destructor has
                // panicked. If another one panics this will abort.
                while self.0.pop_front_node().is_some() {}
            }
        }

        while let Some(node) = self.pop_front_node() {
            let guard = DropGuard(self);
            drop(node);
            mem::forget(guard);
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a u64;

    #[inline]
    fn next(&mut self) -> Option<&'a u64> {
        if self.len == 0 {
            None
        } else {
            self.head.map(|node| unsafe {
                // Need an unbound lifetime to get 'a
                let node = &*node.as_ptr();
                self.len -= 1;
                self.head = node.next;
                &node.element
            })
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }

    #[inline]
    fn last(mut self) -> Option<&'a u64> {
        self.next_back()
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<&'a u64> {
        if self.len == 0 {
            None
        } else {
            self.tail.map(|node| unsafe {
                // Need an unbound lifetime to get 'a
                let node = &*node.as_ptr();
                self.len -= 1;
                self.tail = node.prev;
                &node.element
            })
        }
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {}

impl<'a> Iterator for IterMut<'a> {
    type Item = &'a mut u64;

    #[inline]
    fn next(&mut self) -> Option<&'a mut u64> {
        if self.len == 0 {
            None
        } else {
            self.head.map(|node| unsafe {
                // Need an unbound lifetime to get 'a
                let node = &mut *node.as_ptr();
                self.len -= 1;
                self.head = node.next;
                &mut node.element
            })
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }

    #[inline]
    fn last(mut self) -> Option<&'a mut u64> {
        self.next_back()
    }
}

impl<'a> DoubleEndedIterator for IterMut<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<&'a mut u64> {
        if self.len == 0 {
            None
        } else {
            self.tail.map(|node| unsafe {
                // Need an unbound lifetime to get 'a
                let node = &mut *node.as_ptr();
                self.len -= 1;
                self.tail = node.prev;
                &mut node.element
            })
        }
    }
}

impl<'a> ExactSizeIterator for IterMut<'a> {}

/// An iterator produced by calling `drain_filter` on LinkedList.
pub struct DrainFilter<'a, F: 'a>
where
    F: FnMut(&mut u64) -> bool,
{
    list: &'a mut LinkedList,
    it: Option<NonNull<Node>>,
    pred: F,
    idx: usize,
    old_len: usize,
}

impl<'a, F> Iterator for DrainFilter<'a, F>
where
    F: FnMut(&mut u64) -> bool,
{
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        while let Some(mut node) = self.it {
            unsafe {
                self.it = node.as_ref().next;
                self.idx += 1;

                if (self.pred)(&mut node.as_mut().element) {
                    // `unlink_node` is okay with aliasing `element` references.
                    self.list.unlink_node(node);
                    return Some(Box::from_raw(node.as_ptr()).element);
                }
            }
        }

        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.old_len - self.idx))
    }
}

impl<'a, F> Drop for DrainFilter<'a, F>
where
    F: FnMut(&mut u64) -> bool,
{
    fn drop(&mut self) {
        struct DropGuard<'r, 'a, F>(&'r mut DrainFilter<'a, F>)
        where
            F: FnMut(&mut u64) -> bool;

        impl<'r, 'a, F> Drop for DropGuard<'r, 'a, F>
        where
            F: FnMut(&mut u64) -> bool,
        {
            fn drop(&mut self) {
                self.0.for_each(drop);
            }
        }

        while let Some(item) = self.next() {
            let guard = DropGuard(self);
            drop(item);
            mem::forget(guard);
        }
    }
}

impl<'a, F> fmt::Debug for DrainFilter<'a, F>
where
    F: FnMut(&mut u64) -> bool,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DrainFilter").field(&self.list).finish()
    }
}

impl Iterator for IntoIter {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<u64> {
        self.list.pop_front()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.list.len, Some(self.list.len))
    }
}

impl DoubleEndedIterator for IntoIter {
    #[inline]
    fn next_back(&mut self) -> Option<u64> {
        self.list.pop_back()
    }
}

impl ExactSizeIterator for IntoIter {}

impl IntoIterator for LinkedList {
    type Item = u64;
    type IntoIter = IntoIter;

    /// Consumes the list into an iterator yielding elements by value.
    #[inline]
    fn into_iter(self) -> IntoIter {
        IntoIter { list: self }
    }
}

impl<'a> IntoIterator for &'a LinkedList {
    type Item = &'a u64;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut LinkedList {
    type Item = &'a mut u64;
    type IntoIter = IterMut<'a>;

    fn into_iter(self) -> IterMut<'a> {
        self.iter_mut()
    }
}

impl PartialEq for LinkedList {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other)
    }

    #[allow(clippy::partialeq_ne_impl)]
    fn ne(&self, other: &Self) -> bool {
        self.len() != other.len() || self.iter().ne(other)
    }
}

impl Eq for LinkedList {}

impl PartialOrd for LinkedList {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.iter().partial_cmp(other)
    }
}

impl Ord for LinkedList {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter().cmp(other)
    }
}

impl fmt::Debug for LinkedList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self).finish()
    }
}

impl Hash for LinkedList {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len().hash(state);
        for elt in self {
            elt.hash(state);
        }
    }
}

unsafe impl Send for LinkedList {}
unsafe impl Sync for LinkedList {}
unsafe impl<'a> Send for Iter<'a> {}
unsafe impl<'a> Sync for Iter<'a> {}
unsafe impl<'a> Send for IterMut<'a> {}
unsafe impl<'a> Sync for IterMut<'a> {}
