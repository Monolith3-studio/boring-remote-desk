//! Our modules join `base` only once boring/rebrand.py adds their `mod` lines to upstream's
//! lib.rs (nothing upstream is hand-edited), so their tests run from here, raw checkout or not.
#![allow(dead_code)]

use base::message_proto;

#[path = "../src/direct_link.rs"]
mod direct_link;
#[path = "../src/high_efficiency.rs"]
mod high_efficiency;
#[path = "../src/lan.rs"]
mod lan;
#[path = "../src/trust.rs"]
mod trust;
#[path = "../src/update_feed.rs"]
mod update_feed;
