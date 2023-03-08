use std::io;
use process_memory::{Pid, TryIntoProcessHandle, copy_address, Memory, DataMember, ProcessHandleExt, Architecture, ProcessHandle};
use sysinfo::{ProcessExt, System, SystemExt, Process, PidExt};
use pelite::{pe64::{Pe, PeFile}};
use std::str;

use skidscan::{signature};

fn read_mem(handle: ProcessHandle, address: usize, size: usize) -> io::Result<Vec<u8>> {
    let _bytes = copy_address(address, size, &handle)?;
    Ok(_bytes)
}

fn read<T : Copy>(handle: ProcessHandle, address: usize) -> std::io::Result<T> {
    let ret: std::io::Result<T>;
    let member: DataMember<T> = DataMember::new_offset(handle, vec![address]);
    unsafe { ret = member.read() }
    ret
}

fn write<T : Copy + std::fmt::Display>(handle: ProcessHandle, address: usize, value: T) {
    let member: DataMember<T> = DataMember::new_offset(handle, vec![address]);

    match member.write(&value) {
        Ok(()) => (),
        Err(error) => { println!("Failed to write {} to {} (error: {})!", value, address, error); }
    }
}

fn resolve_relative(handle: ProcessHandle, address: usize, offset: usize, instr_size: usize) -> usize {
    let rip = read::<u32>(handle, address + offset).unwrap() as usize;
    address + rip + instr_size
}

fn get_entity(handle: ProcessHandle, client_entity_list: usize, index: u32) -> usize {
    read::<usize>(handle, (((index + 1) << 0x5) as usize + client_entity_list) - 0x280050).unwrap()
}

fn main() {
    let base: usize = 0x140000000;

    let s = System::new_all();
    let pids: Vec<&Process> = s.processes_by_exact_name("R5Apex.exe").collect();
    let pid = pids[0].pid().as_u32() as process_memory::Pid;

    let handle = pid.try_into_process_handle().unwrap().set_arch(Architecture::Arch64Bit);

    let pe_header = read::<[u8; 0x1000]>(handle, base).unwrap();

    let pe_file = match PeFile::from_bytes(pe_header.as_slice()) {
        Ok(file) => file,
        Err(error) => panic!("Problem parsing pe: {:#?}", error),
    };

    let text_sec = pe_file.section_headers()
    .iter()
    .find(|sec| str::from_utf8(sec.name_bytes()).unwrap() == String::from(".text"))
    .unwrap();

    println!("Found text section: {:#?}", text_sec);

    let text_base = base + (text_sec.VirtualAddress as usize);
    let loaded_text_sec = read_mem(handle, text_base, text_sec.VirtualSize as usize).unwrap();

    println!("Loaded .text into our memory. Size: 0x{:X}", loaded_text_sec.len());

    let local_player = read::<usize>(handle, text_base + 0x01ee8cb0 + 0x8).unwrap();
    let local_team = read::<u32>(handle, local_player + 0x044c).unwrap();

    let client_entity_list_sig = signature!("4C 8B 15 ? ? ? ? 33 F6");
    let client_entity_list_adr = client_entity_list_sig.scan(loaded_text_sec.as_slice()).unwrap_or(0);
    
    while client_entity_list_adr > 0 {
        let client_entity_list = resolve_relative(handle, client_entity_list_adr + text_base, 3, 7) + 0x8;
        //println!("Found IClientEntityList: 0x{:X}", client_entity_list);

        for i in 0..70 {
            let entity = get_entity(handle, client_entity_list, i);
            if entity > 0 {
                let health = read::<u32>(handle, entity + 0x043C).unwrap();
                let team = read::<u32>(handle, entity + 0x044c).unwrap();

                //println!("Entity: 0x{:X} Health: {} Team: {}", entity, health, team);

                if team != local_team {        
                    write::<i32>(handle, entity + 0x2C4, 1512990053);
                    write::<i32>(handle, entity + 0x3C8, 1);
                    write::<i32>(handle, entity + 0x3D0, 1);
                    write::<f32>(handle, entity + 0x3B4, 99999999.0f32);
                    write::<f32>(handle, entity + 0x1D0, 255.0f32);
                } else {
                    write::<f32>(handle, entity + 0x1D4, 255.0f32);
                }
            }
        }
    }
}
