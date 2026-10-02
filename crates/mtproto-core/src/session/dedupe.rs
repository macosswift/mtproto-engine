#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateCheck {
    New,
    Duplicate,
    TooOld,
}

#[derive(Debug, Clone)]
pub struct DuplicateChecker {
    ids: Vec<i64>,
    capacity: usize,
}

impl DuplicateChecker {
    pub fn new(capacity: usize) -> Self {
        Self { ids: Vec::with_capacity(capacity * 2), capacity }
    }

    pub fn peek(&self, id: i64) -> DuplicateCheck {
        let retained = if self.ids.len() == self.capacity * 2 { &self.ids[self.capacity..] } else { &self.ids[..] };
        match retained.last() {
            None => return DuplicateCheck::New,
            Some(&last) if id > last => return DuplicateCheck::New,
            _ => {}
        }
        if retained.len() >= self.capacity && id < retained[0] {
            return DuplicateCheck::TooOld;
        }
        if retained.binary_search(&id).is_ok() { DuplicateCheck::Duplicate } else { DuplicateCheck::New }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn check(&mut self, id: i64) -> DuplicateCheck {
        if self.ids.len() == self.capacity * 2 {
            self.ids.drain(..self.capacity);
        }
        match self.ids.last() {
            None => {
                self.ids.push(id);
                return DuplicateCheck::New;
            }
            Some(&last) if id > last => {
                self.ids.push(id);
                return DuplicateCheck::New;
            }
            _ => {}
        }
        if self.ids.len() >= self.capacity && id < self.ids[0] {
            return DuplicateCheck::TooOld;
        }
        match self.ids.binary_search(&id) {
            Ok(_) => DuplicateCheck::Duplicate,
            Err(position) => {
                self.ids.insert(position, id);
                DuplicateCheck::New
            }
        }
    }

    pub fn contains(&self, id: i64) -> bool {
        self.ids.binary_search(&id).is_ok()
    }

    pub fn oldest(&self) -> Option<i64> {
        self.ids.first().copied()
    }

    pub fn newest(&self) -> Option<i64> {
        self.ids.last().copied()
    }

    pub fn clear(&mut self) {
        self.ids.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn detects_duplicates_and_out_of_order() {
        let mut checker = DuplicateChecker::new(4);
        assert_eq!(checker.check(10), DuplicateCheck::New);
        assert_eq!(checker.check(30), DuplicateCheck::New);
        assert_eq!(checker.check(20), DuplicateCheck::New);
        assert_eq!(checker.check(20), DuplicateCheck::Duplicate);
        assert_eq!(checker.check(30), DuplicateCheck::Duplicate);
        assert!(checker.contains(10));
    }

    #[test]
    fn forgets_oldest_beyond_capacity() {
        let mut checker = DuplicateChecker::new(3);
        for id in 1..=6 {
            assert_eq!(checker.check(id * 10), DuplicateCheck::New);
        }
        assert_eq!(checker.check(70), DuplicateCheck::New);
        assert_eq!(checker.check(5), DuplicateCheck::TooOld);
    }

    #[test]
    fn peek_does_not_record() {
        let mut checker = DuplicateChecker::new(2);
        assert_eq!(checker.peek(10), DuplicateCheck::New);
        assert_eq!(checker.peek(10), DuplicateCheck::New);
        assert!(checker.is_empty());
        assert_eq!(checker.check(10), DuplicateCheck::New);
        assert_eq!(checker.peek(10), DuplicateCheck::Duplicate);
        assert_eq!(checker.len(), 1);
    }

    proptest! {
        #[test]
        fn peek_predicts_check(ids in proptest::collection::vec(0i64..200, 1..400), capacity in 1usize..16) {
            let mut checker = DuplicateChecker::new(capacity);
            for id in ids {
                let predicted = checker.peek(id);
                prop_assert_eq!(checker.check(id), predicted);
                prop_assert!(checker.len() <= capacity * 2);
            }
        }

        #[test]
        fn never_accepts_same_id_twice_within_window(ids in proptest::collection::vec(0i64..500, 1..300)) {
            let mut checker = DuplicateChecker::new(1000);
            let mut seen = std::collections::HashSet::new();
            for id in ids {
                let result = checker.check(id);
                if seen.contains(&id) {
                    prop_assert_eq!(result, DuplicateCheck::Duplicate);
                } else {
                    prop_assert_eq!(result, DuplicateCheck::New);
                    seen.insert(id);
                }
            }
        }
    }
}
