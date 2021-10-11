/*
MIT License

Copyright (c) 2021 Philipp Schuster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
use tar_no_std::TarArchive;

/// This example needs the `alloc` feature.
fn main() {
    // log: not mandatory
    std::env::set_var("RUST_LOG", "trace");
    env_logger::init();

    // also works in no_std environment (except the println!, of course)
    let archive = include_bytes!("../tests/gnu_tar_default.tar");
    let archive_heap_owned = archive.to_vec().into_boxed_slice();
    let archive = TarArchive::new(archive_heap_owned);
    // Vec needs an allocator of course, but the library itself doesn't need one
    let entries = archive.entries().collect::<Vec<_>>();
    println!("{:#?}", entries);
    println!("content of last file:");
    println!("{:#?}", entries[2].data_as_str().expect("Invalid UTF-8"));
}
