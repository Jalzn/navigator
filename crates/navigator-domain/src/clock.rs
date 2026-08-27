use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(u64);

impl MonotonicInstant {
    #[must_use]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self(ticks)
    }

    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.0
    }
}

pub trait Clock {
    fn wall_now(&self) -> OffsetDateTime;
    fn monotonic_now(&self) -> MonotonicInstant;
}
