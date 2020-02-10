use std::env; //eivnornment variables
use std::fs; //file stuff
use std::io; //file io
use std::io::prelude::*;
use std::char;
//https://doc.rust-lang.org/rust-by-example/conversion/string.html


//from jeremey
fn read_byte_by_byte(file_path: &str) -> Result<Vec<u8>, io::Error> {
    let mut f = fs::File::open(file_path)?;
    let mut bytes = vec![0u8; 0]; //default value of 0 with type u8, capacity 0
    let mut mut_byte_buffer = vec![0u8; 1]; //default value of 1 with type u8, capacity 1

    while f.read(&mut mut_byte_buffer)? != 0 { //read byte by byte through the file we passed in - 0 bytes = EOF
        bytes.extend(&mut_byte_buffer); //takes mutable buffer - also works with vecs
        //bytes.extend appends the bytes to our bytes vector
    }
    Ok(bytes)
}

//https://www.geeksforgeeks.org/reverse-actual-bits-given-number/ used this C function as a reference
fn reverse_bits(mut n: u8) -> u8 {
    let mut rev = 0;
    let mut i = 0;
    loop {
        if i == 8 {
            break;
        }
        else {
            rev <<= 1;
            if n & 1 == 1 {
                rev ^= 1;
            }
            n >>= 1;
        }
        i += 1
    }
    rev
}

fn bytes_to_char(vec: Vec<u8>) -> Result<String, io::Error> {
    let mut res = String::new();
    //let mut char_rep: Vec<u8> = vec![0u8; 0];
    let mut char_rep: [u8; 8] = [0; 8];
    let mut i = 0;
    for bytes in vec {
        let twid = bytes & LSB_MASK;
        char_rep[i] = twid;
        //res += std::string::ToString(twid);
        //let b_char = twid.make_ascii_lowercase();
        i += 1
    }
    let char_rep = &char_rep;
    //println!("{:?}", char_rep);
    //let char_rep: u8 = char_rep.trim().parse().expect("Could not parse to u8");
    let mut char_u8: u8 = 0;
    //let char_u8_2: u8 = 0;
    for i in 0..8 {
        char_u8 |= char_rep[i] << i;
        //char_u8 |= (char_rep[i]) << i;
        //char_u8 |= char_rep[i] | (char_u8 & mask);
    }
    //println!("{:?}", char_rep); //least significant bits represented as an 8 bit char
    //println!("val: {:b}", char_u8); //least significant bits
    //println!("rev: {:b}", reverse_bits(char_u8)); //reveersed LSB for correct value
    res.push(char::from(reverse_bits(char_u8)));
    Ok(res)
}


const NULL_BYTE: u8 = 0x00;
//const SPACE: u8 = 0x0a;
const LSB_MASK: u8 = 0b00000001;


/*const PPM_HEADER: [u8; 13] = [0x50, 0x36, SPACE, 0x37, 0x30, 0x20,
                    0x34, 0x36, SPACE, 0x32, 0x35, 0x35, SPACE];*/ //this is deorecated. was using this in an assert before I realized that the second row values are the width/height
fn main() {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        2 => {
            //one argument passed - unhide secret message in specified file path
            let args_slice = &args[1].trim();
            let file_bytes: Vec<u8> = read_byte_by_byte(args_slice).expect("Error: could not read file bytes.");
            //let header = &file_bytes[0..13]; //header is 13 bytes, start at 14th byte
            //println!("Header = {:?}", header);
            //assert_eq!(header, PPM_HEADER);
            let data_bytes = &file_bytes[15..];
            //println!("Hex representation:\n{:x?}", data_bytes); //:x rex representation
            //println!("{:x?}", data_bytes[8..16].to_vec());
            let mut ascii_representation = String::new();
            let mut i = 0;
            loop {
                let ascii_rep = bytes_to_char(data_bytes[(8*i)..(8*i) + 8].to_vec()).expect("Error: couldn't convert character correctly.");
                if ascii_rep == '\0'.to_string() {
                    ascii_representation.push_str(&ascii_rep);
                    break;
                }
                ascii_representation.push_str(&ascii_rep);
                i += 1
            }
            println!("Decoded message: {}\n", ascii_representation);
            //let ascii_rep_2 = bytes_to_char(data_bytes[8..16].to_vec()).expect("Whoops, didn't convert char correctly");
            //println!("{}", ascii_rep);
            //println!("{}", ascii_rep_2);
            //ascii_representation += &ascii_rep;
            //println!("{}", ascii_representation);
        },
        3 => {
            //two argument passed - hide specified secret message in specified file
            //println!("lol not implemented yet");
            let file = &args[1].trim();
            let message = &args[2].trim();
            let mut file_bytes: Vec<u8> = read_byte_by_byte(file).expect("Error: could not read file bytes.");
            //let mut mut_file_bytes = &mut file_bytes[13..];
            //let header = &file_bytes[0..14]; //header is 13 bytes, start at 14th byte
            //println!("Header = {:?}", &header);
            //assert_eq!(header, PPM_HEADER);
            let data_bytes = &mut file_bytes[15..];
            //println!("first data byte: {}", &data_bytes[0]);
            //println!("{:x?}", &data_bytes[0..8]);
            let mut i = 0;
            let _encoded = message.as_bytes();
            let mut encoded: Vec<u8> = vec![0u8; 0];
            for i in 0.._encoded.len() {
                encoded.push(_encoded[i]);
            }
            //println!("{}", encoded.len());
            encoded.push(NULL_BYTE); //push 0x00 to ensure that decoding is possible in the future, otherwise there is no way to spefify end of the message
            //println!("{:x?}", encoded);
            if encoded.len() / 8 > data_bytes.len() {
                eprintln!("Error: message size too large");
            }
            //println!("{}", encoded.len());
            loop {
                if i == encoded.len() { break };
                //println!("{:b}", encoded[i]);
                for j in 0..8 {
                    //skip zero as there is no ascii in that range - nevermind lol
                    //let mask = 0b10000000 >> j;
                    /*let val = match encoded[i] & mask {
                        0 => {
                            0b00000000
                        },
                        _ => {
                            0b00000001
                        }
                    };*/
                    //println!("val={}", val);
                    let mut val = encoded[i] >> (7 - j);
                    val &= 1;
                    let index = (8 * i) + j;
                    let data = data_bytes[index] & !LSB_MASK; //remove least signifcant bit
                    data_bytes[index] = data | val;
                }
                i += 1;
            }
            println!("{:x?}", &file_bytes[0..]);
            let mut f = fs::File::create("output.ppm").expect("Error: could not generate output file");
            f.write(&file_bytes).expect("Error: could not write to output file");
            //f.write(b"\r\r\n").expect("Error: could not write end of file garbage.");
            println!("Encoded \"{0}\" to {1}", message, file);
        },
        _ => {
            eprintln!("Usage: cargo run <file_path> <message>");
            //std::process::exit(1);
        }
    };
}
