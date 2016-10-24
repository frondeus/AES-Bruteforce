extern crate rustc_serialize;
extern crate openssl;
extern crate data_encoding;
extern crate byteorder;


extern crate num;


use data_encoding::base64;
use openssl::crypto::symm::{Type, decrypt};
use rustc_serialize::hex::{FromHex, ToHex};

use byteorder::{BigEndian, WriteBytesExt};

use std::time::Instant;
use num::pow;

use std::env;


fn decrypt_from_to(from: u64, 
                   to: u64,
                   iv: &Vec<u8>,
                   suffix: &str,
                   input: &Vec<u8>,
                   prefix_length: usize) -> bool {
    for i in from..to {

        let prefix = create_prefix(i, prefix_length);
        let key = prefix + suffix;
        let _key = key.from_hex().unwrap();
        //let mut prefix = vec![];
        //prefix.write_u32::<BigEndian>(i as u32).unwrap();
        
        //prefix.extend(suffix.clone());

        let output = decrypt(Type::AES_256_CBC, &_key, Some(iv), input);

        match output {
            Ok(o) => match String::from_utf8(o) {
                Ok(s) => {
                    println!("Decrypted for key {}: {}", key, s);
                    return true;
                },
                Err(_) => ()
            },
            Err(_) => ()
        };

    }

    return false;
}

use std::thread;
use std::sync::{Arc, Mutex};

fn main() {
    let key_length = 64;

    //let input = "EGSz+edincW0ukwMqftJlIbkZNiERzUiZfvFlpsYoqcVwbwYzlWUIyzNA9+XDFJWaSQS9sRCfR0IpZa82QSP8BA/dRRgYzv48JfnFHmhdsAbi8C9JGdOvjns+p+WzOvxpDpGoAZXiljuxMiXjPdt/YSraLsXDifeAnN0HSv22ug=";
    //let iv = "e2fd57f289635be74028adc6624f7b35";
    //let suffix = "cc4498b9b12eee0eadd822b26671356fd7d66e16037ad70c4c72f7b0";

    let iv = "518be2ee1dc5da4a4263b69a677b6223";
    let suffix = "70d34982c91a63d9f51b8929ee406940f6a5e52e55105dbc0a9306f";
    let input = "8tkbGMX+AZf0mhkfV1/LsAs+1pK6CsQjWE2Tvp5YN38zPbOm+HuwEQjQe4OvuqrGk6fUtcI7yxXkYO8vB3YA9f1az3ByRUGyljLTiPUNcNSAz+MUiKl2Jc9YC9Rrt+o5";

    let _iv = iv.from_hex().unwrap();
    let _input = base64::decode(input.as_bytes()).unwrap();
    //let _suffix = suffix.from_hex().unwrap();

    let prefix_length = key_length - suffix.len();
    let max_prefix = pow(16 as u64, prefix_length as usize);
    let least_prefix :u64 = 0;
                        

    //Threading 
    let threads_size = 4;
    let mut threads = vec![];
    let batch_size = 65536;

    let now = Instant::now();
    println!("Thread\tElapsed\t\tFrom ... to ...");

    let i = Arc::new(Mutex::new(least_prefix as u64));

    for ts in 0..threads_size {
        let i = i.clone();
        let _iv = _iv.clone();
        let _input = _input.clone();
        //let _suffix = _suffix.clone();
        let thread = thread::spawn(move || {
            loop {
                let from: u64;
                let to: u64;
                {
                    let mut _i = i.lock().unwrap();
                    if *_i >= max_prefix { return false; }
                    from = *_i;
                    to = *_i + batch_size;
                    *_i += batch_size;
                }

                println!("{}\t{} seconds\t{} to {} {}%", 
                         ts,
                         now.elapsed().as_secs(),
                         create_prefix(from, prefix_length),
                         create_prefix(to, prefix_length),
                         ((to as f64 / max_prefix as f64) * 100 as f64) as f64
                         );
                
                let res = decrypt_from_to(from, to, &_iv, suffix, &_input, prefix_length);
                if res == true {
                    let mut _i = i.lock().unwrap();
                    *_i = max_prefix + 1;
                    println!("Found... exitting");
                    return true;
                }
            }
        });

        threads.push(thread);
    }

    for t in threads {
        let _ = t.join();
    }

}

fn create_prefix(i: u64, prefix_length: usize) -> String {
    let prefix = format!("{:x}", i);
    let p = (0..(prefix_length - prefix.len())).map(|_| "0").collect::<String>();
    return p + prefix.as_str();
}


