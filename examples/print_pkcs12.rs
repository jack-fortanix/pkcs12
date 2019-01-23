/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate pkcs12;

use pkcs12::PFX;
use std::env;
use std::fs::File;
use std::io::Read;

fn dump_info(pfx: &PFX) {
    println!("Certificates:");
    let certs = pfx.certificates().unwrap();
    for cert in &certs {
        println!("{:?}", cert);
    }

    println!("Private Keys:");
    let private_keys = pfx.private_keys().unwrap();

    for pkcs12_pk in private_keys {
        let pk = &pkcs12_pk.0;
        let names = &pkcs12_pk.1;

        println!("{:?} {}-{}", names, pk.name().unwrap(), pk.len());
    }
}

fn main() {

    let args = env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        println!("Usage {} pkcs12_file password", args[0]);
        return;
    }

    let pkcs12_file = &args[1];
    let password = &args[2];

    let mut pkcs12 = vec![];
    let mut f = match File::open(pkcs12_file) {
        Ok(f) => f,
        Err(e) => { println!("Failed to open file: {:?}", e); return; }
    };

    f.read_to_end(&mut pkcs12).unwrap();

    match PFX::parse(&pkcs12) {
        Err(e) => {
            println!("Parsing PKCS12 file failed {:?}", e);
        },

        Ok(pfx) => {
            println!("PFX = {:?}", pfx);
            let pfx = pfx.decrypt(&password).unwrap();
            dump_info(&pfx);
        }
    }
}
