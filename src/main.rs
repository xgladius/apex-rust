use libm::fmodf;
use pelite::pe64::{Pe, PeFile};
use process_memory::{
    copy_address, Architecture, DataMember, Memory, ProcessHandle, ProcessHandleExt,
    TryIntoProcessHandle,
};
use sysinfo::{PidExt, Process, ProcessExt, System, SystemExt};

use skidscan::signature;

#[derive(Copy, Clone, Debug)]
pub struct Vec2 {
    pub pitch: f32,
    pub yaw: f32,
}

fn read<T: Copy>(handle: ProcessHandle, address: usize) -> std::io::Result<T> {
    unsafe { DataMember::<T>::new_offset(handle, vec![address]).read() }
}

fn write<T: Copy>(handle: ProcessHandle, address: usize, value: T) -> std::io::Result<()> {
    DataMember::<T>::new_offset(handle, vec![address]).write(&value)
}

fn resolve_relative(
    handle: ProcessHandle,
    address: usize,
    offset: usize,
    instr_size: usize,
) -> std::io::Result<usize> {
    Ok(address + read::<u32>(handle, address + offset)? as usize + instr_size)
}

fn get_entity(
    handle: ProcessHandle,
    client_entity_list: usize,
    index: u32,
) -> std::io::Result<usize> {
    read::<usize>(
        handle,
        (((index + 1) << 0x5) as usize + client_entity_list) - 0x280050,
    )
}

fn main() -> std::io::Result<()> {
    let base: usize = 0x140000000;

    let s = System::new_all();
    let pids: Vec<&Process> = s.processes_by_exact_name("R5Apex.exe").collect();
    let pid = pids[0].pid().as_u32() as process_memory::Pid;

    let handle = pid
        .try_into_process_handle()
        .unwrap()
        .set_arch(Architecture::Arch64Bit);

    let pe_header = read::<[u8; 0x1000]>(handle, base).unwrap();

    let pe_file = match PeFile::from_bytes(pe_header.as_slice()) {
        Ok(file) => file,
        Err(error) => panic!("Problem parsing pe: {:#?}", error),
    };

    let text_sec = pe_file
        .section_headers()
        .iter()
        .find(|sec| std::str::from_utf8(sec.name_bytes()).unwrap() == String::from(".text"))
        .unwrap();

    println!("Found text section: {:#?}", text_sec);

    let text_base = base + (text_sec.VirtualAddress as usize);
    let loaded_text_sec = copy_address(text_base, text_sec.VirtualSize as usize, &handle).unwrap();

    println!(
        "Loaded .text into our memory. Size: 0x{:X}",
        loaded_text_sec.len()
    );

    let local_player = read::<usize>(handle, base + 0x1EE8D58).unwrap();
    let local_team = read::<u32>(handle, local_player + 0x044c).unwrap();
    println!(
        "Found localplayer: 0x{:X} Team: {}",
        local_player, local_team
    );

    let client_entity_list_sig = signature!("4C 8B 15 ? ? ? ? 33 F6");
    let client_entity_list_adr = client_entity_list_sig
        .scan(loaded_text_sec.as_slice())
        .unwrap_or(0);

    let i_input_system_sig = signature!("48 8B 05 ? ? ? ? 48 8D 4C 24 20 BA 01 00 00 00 C7");
    let i_input_system_adr = i_input_system_sig
        .scan(loaded_text_sec.as_slice())
        .unwrap_or(0);
    if i_input_system_adr > 0 {
        println!("Found IInputSystem: 0x{:X}", i_input_system_adr);
    }

    let sensitivty = read::<f32>(handle, base + 0x01ed55b0)?;
    println!("Got sensitivty: {}", sensitivty);

    let mut last_pitch_yaw = Vec2 {
        pitch: 0.0f32,
        yaw: 0.0f32,
    };

    while client_entity_list_adr > 0 {
        let client_entity_list =
            resolve_relative(handle, client_entity_list_adr + text_base, 3, 7)? + 0x8;

        if client_entity_list <= 0 {
            continue;
        }

        let weapon_pitch_yaw = read::<Vec2>(handle, local_player + 0x24B0)?;
        let mut view_angles_pitch_yaw = read::<Vec2>(handle, local_player + 0x25ac - 0x14)?;

        if weapon_pitch_yaw.pitch != 0.0f32 {
            let delta = weapon_pitch_yaw.pitch - last_pitch_yaw.pitch;
            if delta <= 90.0f32 || delta >= -90.0f32 {
                view_angles_pitch_yaw.pitch = view_angles_pitch_yaw.pitch - delta;
            }
            last_pitch_yaw.pitch = weapon_pitch_yaw.pitch;
        }

        if weapon_pitch_yaw.yaw != 0.0f32 {
            let delta = weapon_pitch_yaw.yaw - last_pitch_yaw.yaw;
            if delta <= 90.0f32 || delta >= -90.0f32 {
                view_angles_pitch_yaw.yaw = view_angles_pitch_yaw.yaw - delta;
            }
            last_pitch_yaw.yaw = weapon_pitch_yaw.yaw;
        }

        write::<Vec2>(handle, local_player + 0x25ac - 0x14, view_angles_pitch_yaw)?;

        for i in 0..70 {
            let entity = get_entity(handle, client_entity_list, i)?;
            if entity > 0 {
                let health = read::<u32>(handle, entity + 0x043C)?;
                let team = read::<u32>(handle, entity + 0x044c)?;
                let life_state = read::<u32>(handle, entity + 0x0798)?;

                if team == local_team || health == 0 || life_state != 0 || entity == local_player {
                    continue;
                }

                write::<i32>(handle, entity + 0x2C4, 1512990053)?;
                write::<i32>(handle, entity + 0x3C8, 1)?;
                write::<i32>(handle, entity + 0x3D0, 1)?;
                write::<f32>(handle, entity + 0x3B4, 99999999.0)?;
                write::<f32>(handle, entity + 0x1D0, 255.0)?;
            }
        }
    }

    Ok(())
}
