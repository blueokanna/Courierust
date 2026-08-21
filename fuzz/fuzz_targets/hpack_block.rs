#![no_main]

use courierust::courierust_hpack::Decoder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(4096, 1 << 20);
    let _ = decoder.decode(data);
});
