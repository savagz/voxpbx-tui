pub mod calls;
pub mod extensions;
pub mod overview;
pub mod queues;
pub mod sip_trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Calls,
    Extensions,
    Queues,
    SipTrace,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Overview,
        Tab::Calls,
        Tab::Extensions,
        Tab::Queues,
        Tab::SipTrace,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Calls => "Calls",
            Tab::Extensions => "Extensions",
            Tab::Queues => "Queues",
            Tab::SipTrace => "SIP Trace",
        }
    }

    pub fn index(&self) -> usize {
        Self::ALL
            .iter()
            .position(|t| t == self)
            .expect("Tab siempre está en Tab::ALL")
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}
