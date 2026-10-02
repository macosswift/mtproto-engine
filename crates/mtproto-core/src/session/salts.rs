#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServerSalt {
    pub salt: i64,
    pub valid_since: f64,
    pub valid_until: f64,
}

#[derive(Debug, Clone)]
pub struct SaltState {
    current: ServerSalt,
    future: Vec<ServerSalt>,
}

pub const SALT_SAFETY_MARGIN: f64 = 60.0;
pub const SINGLE_SALT_LIFETIME: f64 = 600.0;

impl SaltState {
    pub fn empty() -> Self {
        Self {
            current: ServerSalt { salt: 0, valid_since: f64::NEG_INFINITY, valid_until: f64::NEG_INFINITY },
            future: Vec::new(),
        }
    }

    pub fn from_salts(salts: &[ServerSalt], server_time: f64) -> Self {
        let mut state = Self::empty();
        if let Some(best) = salts
            .iter()
            .filter(|salt| salt.valid_since <= server_time && salt.valid_until > server_time)
            .max_by(|a, b| a.valid_until.total_cmp(&b.valid_until))
        {
            state.current = *best;
        } else if let Some(first) = salts.first() {
            state.current = *first;
        }
        state.set_future(salts.iter().copied().filter(|salt| salt.valid_since > server_time).collect(), server_time);
        state
    }

    pub fn set_server_salt(&mut self, salt: i64, server_time: f64) {
        self.current = ServerSalt { salt, valid_since: server_time, valid_until: server_time + SINGLE_SALT_LIFETIME };
        self.future.clear();
    }

    pub fn invalidate_current(&mut self) {
        self.current.valid_until = f64::NEG_INFINITY;
    }

    pub fn current_value(&self) -> i64 {
        self.current.salt
    }

    pub fn set_future(&mut self, salts: Vec<ServerSalt>, server_time: f64) {
        let mut salts: Vec<ServerSalt> = salts
            .into_iter()
            .filter(|salt| {
                salt.valid_since.is_finite() && salt.valid_until.is_finite() && salt.valid_until > salt.valid_since
            })
            .collect();
        if salts.is_empty() {
            return;
        }
        salts.sort_by(|a, b| b.valid_since.total_cmp(&a.valid_since));
        self.future = salts;
        self.rotate(server_time);
    }

    fn rotate(&mut self, server_time: f64) {
        while let Some(next) = self.future.last() {
            if next.valid_since < server_time {
                self.current = *next;
                self.future.pop();
            } else {
                break;
            }
        }
    }

    pub fn current_salt(&mut self, server_time: f64) -> i64 {
        self.rotate(server_time);
        self.current.salt
    }

    pub fn has_valid_salt(&mut self, server_time: f64) -> bool {
        self.rotate(server_time);
        self.current.valid_until > server_time + SALT_SAFETY_MARGIN
    }

    pub fn needs_future_salts(&mut self, server_time: f64) -> bool {
        self.rotate(server_time);
        self.future.is_empty() || self.current.valid_until <= server_time + SALT_SAFETY_MARGIN
    }

    pub fn all(&self) -> Vec<ServerSalt> {
        let mut salts = self.future.clone();
        salts.push(self.current);
        salts.sort_by(|a, b| a.valid_since.total_cmp(&b.valid_since));
        salts
    }

    pub fn next_change_time(&self) -> Option<f64> {
        let rotation = self.future.last().map(|salt| salt.valid_since);
        let expiry = Some(self.current.valid_until - SALT_SAFETY_MARGIN).filter(|value| value.is_finite());
        match (rotation, expiry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt(salt: i64, since: f64, until: f64) -> ServerSalt {
        ServerSalt { salt, valid_since: since, valid_until: until }
    }

    #[test]
    fn empty_state_needs_salts() {
        let mut state = SaltState::empty();
        assert!(!state.has_valid_salt(1000.0));
        assert!(state.needs_future_salts(1000.0));
    }

    #[test]
    fn bad_server_salt_gives_ten_minutes() {
        let mut state = SaltState::empty();
        state.set_server_salt(7, 1000.0);
        assert!(state.has_valid_salt(1000.0));
        assert_eq!(state.current_salt(1000.0), 7);
        assert!(state.needs_future_salts(1000.0));
        assert!(state.has_valid_salt(1000.0 + 539.0));
        assert!(!state.has_valid_salt(1000.0 + 541.0));
    }

    #[test]
    fn future_salts_rotate_in_order() {
        let mut state = SaltState::empty();
        state.set_server_salt(1, 0.0);
        state.set_future(vec![salt(3, 3600.0, 7200.0), salt(2, 0.0, 3600.0), salt(4, 7200.0, 10800.0)], 10.0);
        assert_eq!(state.current_salt(10.0), 2);
        assert!(!state.needs_future_salts(10.0));
        assert_eq!(state.current_salt(3600.5), 3);
        assert_eq!(state.current_salt(7300.0), 4);
        assert!(state.needs_future_salts(7300.0));
        assert_eq!(state.all().len(), 1);
    }

    #[test]
    fn restore_picks_currently_valid_salt() {
        let salts = vec![salt(1, 0.0, 100.0), salt(2, 100.0, 2000.0), salt(3, 2000.0, 4000.0)];
        let mut state = SaltState::from_salts(&salts, 150.0);
        assert_eq!(state.current_salt(150.0), 2);
        assert_eq!(state.current_salt(2001.0), 3);
        assert_eq!(state.next_change_time(), Some(3940.0));
    }
}
