use crate::dnssec::chain::DnssecChain;
use crate::resolver::{iterative::ResolutionTrace, DnsQueryResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Records,
    Dnssec,
    Trace,
}

pub struct App {
    pub domain: String,
    pub view: View,
    pub scroll: u16,
    pub records: DnsQueryResult,
    pub dnssec: DnssecChain,
    pub trace: ResolutionTrace,
}

impl App {
    pub fn new(
        domain: String,
        records: DnsQueryResult,
        dnssec: DnssecChain,
        trace: ResolutionTrace,
    ) -> Self {
        Self {
            domain,
            view: View::Records,
            scroll: 0,
            records,
            dnssec,
            trace,
        }
    }

    pub fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }

    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub fn set_view(&mut self, view: View) {
        if self.view != view {
            self.view = view;
            self.scroll = 0;
        }
    }
}
