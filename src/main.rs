
mod consts;

use crate::consts::{EventClass, ProcessOperation, RegistryOperation, FileSystemOperation};
use num_traits::FromPrimitive;    
use std::mem::MaybeUninit;
use std::fmt;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let file = &args[0];
    let data = std::fs::read(file).unwrap();

    let traces = Traces::decode(&data);

    // println!("{:#?}", traces.header);
    for process in &traces.processes {
        println!("{:?}", DebugPrint(process, &traces));
    }

    traces.print_events();
}

struct Traces<'a> {
    data: &'a [u8],
    header: Header,
    strings: Vec<String>,
    processes: Vec<Process>,
}

impl<'a> Traces<'a> {
    fn decode(data: &'a [u8]) -> Traces<'a> {
        let header = Header::decode(data);
        let strings = decode_strings(&data[header.offset_to_strings as usize ..]);
        let processes = decode_processes(&data[header.offset_to_processes as usize ..]);
        Traces {
            data,
            header,
            strings,
            processes,
        }
    }

    fn find_string(&self, offset: StringIndex) -> &str {
        // println!("{:?}", self.string_offsets);
        // println!("BLARG {:?}", offset);
        // let index = self.string_offsets[&offset];
        &self.strings[offset.0 as usize]
    }

    fn print_events(&self) {
        let event_offsets = &self.data[self.header.offset_to_event_offsets as usize .. ];

        for i in 0..self.header.number_of_events as usize {
            const EVENT_OFFSET_LEN: usize = 5; // 5 because there's an extra flags byte
            let offset = u32::decode(&event_offsets[EVENT_OFFSET_LEN*i .. ]) as usize;
            println!("offset: {:?}", offset);
            let event = Event::from(EventInfo::decode(&self.data[offset..]));
            println!("{:?}", DebugPrint(&event, self));
        }
    }
}

fn decode_strings(data: &[u8]) -> Vec<String> {
    let count = u32::decode(data) as usize;
    let mut offsets = Vec::with_capacity(count);

    for i in 0..count {
        let offset = u32::decode(&data[4 + 4*i..]) as usize;
        assert!(offset >= 4 + 4*count);
        offsets.push(offset);
    }

    offsets.push(data.len());

    let mut strings = Vec::with_capacity(count);

    for pair in offsets.windows(2) {
        strings.push(decode_string(&data[pair[0] .. pair[1]]));
    }

    strings
}

fn decode_string(data: &[u8]) -> String {
    let len = u32::decode(data) as usize;
    assert!(len & 1 == 0); // len must be even, it's in bytes
    let data = &data[4 .. 4 + len];

    // TODO: use some util library to decode u16's/etc
    let mut values = Vec::with_capacity(len / 2);
    for i in 0..len/2 {
        values.push(u16::decode(&data[2*i .. ]));
    }

    if let Some(last) = values.pop() {
        assert_eq!(last, 0);
    }

    String::from_utf16(&values).unwrap()
}

fn decode_processes(data: &[u8]) -> Vec<Process> {
    let count = u32::decode(data) as usize;
    // let mut indexes = Vec::with_capacity(count);
    let mut offsets = Vec::with_capacity(count);
    let mut processes = Vec::with_capacity(count);


    // Don't bother decoding the process indices, jump straight to the offsets
    for i in 0..count {
        let offset = u32::decode(&data[4 + 4*count + 4*i..]) as usize;
        // assert_eq!(u32::decode(&data[offset..]), i as u32);
        // assert!(offset >= 4 + (4*count)*3);
        offsets.push(offset);
    }

    // for i in 0..count {
    //     let offset = u32::decode(&data[4 + 4*i..]) as usize;
    //     // assert!(offset >= 4 + (4*count)*3);
    //     string_offsets.push(offset);
    // }

    for offset in offsets {
        processes.push(Process::decode(&data[offset..]));
    }

    processes
}

macro_rules! decode_field {
    (
        $simple:ident,
        $data:expr
    ) => {
        $simple::decode($data)
    };
    (
        [$simple:ident; $len:expr],
        $data:expr
    ) => {{
        unsafe {
            let mut res: [MaybeUninit<$simple>; $len] = MaybeUninit::uninit().assume_init();
            decode_array($data, &mut res);
            std::mem::transmute(res)
        }
    }}
}

macro_rules! decode_struct {
    (
        struct $name:ident {
            $(
                #[offset($field_offset:expr)]
                $field_name:ident: $field_ty:tt
            ),*
        }
    ) => {
        #[derive(Debug, Copy, Clone)]
        struct $name {
            $(
                $field_name: $field_ty
            ),*
        }

        impl $name {
            fn decode(data: &[u8]) -> $name {
                let cur_zeros_array: [u8; 0] = [];

                $(
                    let _: [u8; $field_offset] = cur_zeros_array;
                    let cur_zeros_array: [u8; $field_offset + std::mem::size_of::<$field_ty>()] = [0; $field_offset + std::mem::size_of::<$field_ty>()];
                    let $field_name = decode_field!($field_ty, &data[$field_offset..]);
                )*

                let _ = cur_zeros_array;

                $name {
                    $($field_name),*
                }
            }
        }
    };
}

decode_struct! {
    struct Header {
        #[offset(0x0)]
        signature: [u8; 4], // "PML_"

        #[offset(0x4)]
        version: u32, // file version, currently 9

        #[offset(0x8)]
        is_64_bit: u32, // bool, 1 for 64 bit, 0 for 32

        #[offset(0xC)]
        computer_name: [u16; 0x10],

        #[offset(0x2C)]
        system_root_path: [u16; 0x104], // e.g. "C:\Windows"

        #[offset(0x234)]
        number_of_events: u32,

        #[offset(0x238)]
        unknown_0: u64,

        #[offset(0x240)]
        offset_to_events: u64,

        #[offset(0x248)]
        offset_to_event_offsets: u64,

        #[offset(0x250)]
        offset_to_processes: u64,

        #[offset(0x258)]
        offset_to_strings: u64,

        #[offset(0x260)]
        offset_to_icons: u64,

        #[offset(0x268)]
        unknown_1: [u8; 0xc],

        #[offset(0x274)]
        win_ver_major: u32,

        #[offset(0x278)]
        win_ver_minor: u32,

        #[offset(0x27C)]
        win_ver_build: u32,

        #[offset(0x280)]
        win_ver_sub_build: u32,

        #[offset(0x284)]
        win_ver_service_pack_name: [u16; 0x32],

        #[offset(0x2E8)]
        unknown_2: [u8; 0xa4],

        #[offset(0x38C)]
        number_of_logical_processors: u32,

        #[offset(0x390)]
        bytes_of_ram: u64,

        #[offset(0x398)]
        duplicate_offset_to_event_offsets: u64,

        #[offset(0x3A0)]
        offset_to_hosts_and_ports: u64

    }
}

trait Decode {
    fn decode(data: &[u8]) -> Self;
}

impl Decode for u8 {
    fn decode(data: &[u8]) -> Self {
        let mut bytes = [0; std::mem::size_of::<Self>()];
        bytes.copy_from_slice(&data[0..std::mem::size_of::<Self>()]);
        Self::from_le_bytes(bytes)
    }
}

impl Decode for u16 {
    fn decode(data: &[u8]) -> Self {
        let mut bytes = [0; std::mem::size_of::<Self>()];
        bytes.copy_from_slice(&data[0..std::mem::size_of::<Self>()]);
        Self::from_le_bytes(bytes)
    }
}

impl Decode for u32 {
    fn decode(data: &[u8]) -> Self {
        let mut bytes = [0; std::mem::size_of::<Self>()];
        bytes.copy_from_slice(&data[0..std::mem::size_of::<Self>()]);
        Self::from_le_bytes(bytes)
    }
}

impl Decode for u64 {
    fn decode(data: &[u8]) -> Self {
        let mut bytes = [0; std::mem::size_of::<Self>()];
        bytes.copy_from_slice(&data[0..std::mem::size_of::<Self>()]);
        Self::from_le_bytes(bytes)
    }
}

fn decode_array<T: Decode>(items: &[u8], output: &mut [MaybeUninit<T>]) {
    let mut offset = 0;
    for res in output {
        *res = MaybeUninit::new(T::decode(&items[offset..]));
        offset += std::mem::size_of::<T>();
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct ProcessIndex(u32);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct StringIndex(u32);

impl Decode for StringIndex {
    fn decode(data: &[u8]) -> Self {
        Self(u32::decode(data))
    }
}
impl Decode for ProcessIndex {
    fn decode(data: &[u8]) -> Self {
        Self(u32::decode(data))
    }
}
impl Decode for EventClass {
    fn decode(data: &[u8]) -> Self {
        Self::from_u32(u32::decode(data)).unwrap()
    }
}

decode_struct! {
    struct ProcessHeader {
        #[offset(0x0)]
        process_index: u32,

        #[offset(0x4)]
        process_id: u32,

        #[offset(0x8)]
        parent_process_id: u32,

        #[offset(0xC)]
        unknown_0: u32,

        #[offset(0x10)]
        authentication_id: u64,

        #[offset(0x18)]
        session_number: u32,

        #[offset(0x1C)]
        unknown_1: u32,

        #[offset(0x20)]
        start_time: u64,

        #[offset(0x28)]
        end_time: u64,

        #[offset(0x30)]
        is_virtualized: u32,

        #[offset(0x34)]
        is_64_bit: u32,

        #[offset(0x38)]
        integrity: u32,

        #[offset(0x3C)]
        user_string_index: StringIndex,

        #[offset(0x40)]
        process_string_index: StringIndex,

        #[offset(0x44)]
        image_path_string_index: StringIndex,

        #[offset(0x48)]
        command_line_string_index: StringIndex,

        #[offset(0x4C)]
        company_string_index: StringIndex,

        #[offset(0x50)]
        executable_version_string_index: StringIndex,

        #[offset(0x54)]
        executable_description_string_index: StringIndex,

        #[offset(0x58)]
        small_icon_index: u32,

        #[offset(0x5C)]
        big_icon_index: u32,

        #[offset(0x60)]
        unknown_2: u32
    }
}

decode_struct! {
    struct EventInfo {
        #[offset(0x0)]
        process_index: ProcessIndex,
        
        #[offset(0x4)]
        thread_id: u32,
        
        #[offset(0x8)]
        event_class: EventClass,
        
        #[offset(0xC)]
        event_type: u16,
        
        #[offset(0xE)]
        unknown_0: [u8; 6],
        
        #[offset(0x14)]
        duration_in_100ns: u64,
        
        #[offset(0x1C)]
        time: u64,
        
        #[offset(0x24)]
        result: u32,
        
        #[offset(0x28)]
        captured_stack_depth: u16,
        
        #[offset(0x2A)]
        unknown_1: u16,
        
        #[offset(0x2C)]
        detail_size: u32,
        
        #[offset(0x30)]
        detail_offset_from_event: u32
    }
}

struct DebugPrint<'a, T>(&'a T, &'a Traces<'a>);

impl<'a> fmt::Debug for DebugPrint<'a, Process> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Process");
        d.field("process_index", &self.0.header.process_index);
        d.field("process_id", &self.0.header.process_id);
        d.field("parent_process_id", &self.0.header.parent_process_id);
        d.field("unknown_0", &self.0.header.unknown_0);
        d.field("authentication_id", &self.0.header.authentication_id);
        d.field("session_number", &self.0.header.session_number);
        d.field("unknown_1", &self.0.header.unknown_1);
        d.field("start_time", &self.0.header.start_time);
        d.field("end_time", &self.0.header.end_time);
        d.field("is_virtualized", &self.0.header.is_virtualized);
        d.field("is_64_bit", &self.0.header.is_64_bit);
        d.field("integrity", &self.0.header.integrity);
        d.field("user_string_index", &self.1.find_string(self.0.header.user_string_index));
        d.field("process_string_index", &self.1.find_string(self.0.header.process_string_index));
        d.field("image_path_string_index", &self.1.find_string(self.0.header.image_path_string_index));
        d.field("command_line_string_index", &self.1.find_string(self.0.header.command_line_string_index));
        d.field("company_string_index", &self.1.find_string(self.0.header.company_string_index));
        d.field("executable_version_string_index", &self.1.find_string(self.0.header.executable_version_string_index));
        d.field("executable_description_string_index", &self.1.find_string(self.0.header.executable_description_string_index));
        d.field("small_icon_index", &self.0.header.small_icon_index);
        d.field("big_icon_index", &self.0.header.big_icon_index);
        d.field("unknown_2", &self.0.header.unknown_2);
        d.finish()
    }
}

impl<'a> fmt::Debug for DebugPrint<'a, Event> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("EventInfo");
        d.field("process_index", &self.0.process_index);
        d.field("thread_id", &self.0.thread_id);
        d.field("event_detail", &self.0.event_detail);
        d.field("event_type", &self.0.event_type);
        d.field("duration_in_100ns", &self.0.duration_in_100ns);
        d.field("time", &self.0.time);
        d.field("result", &self.0.result);
        d.field("captured_stack_depth", &self.0.captured_stack_depth);
        d.finish()
    }
}

struct Event {
    process_index: ProcessIndex,
    thread_id: u32,
    event_detail: EventDetail,
    event_type: u16,
    duration_in_100ns: u64,
    time: u64,
    result: u32,
    captured_stack_depth: u16,
}

#[derive(Debug)]
enum EventDetail {
    Process(ProcessEventDetail),
    Registry(RegistryEventDetail),
    FileSystem(FileSystemEventDetail),
    Profiling(ProfilingEventDetail),
    Network(NetworkEventDetail),
}

#[derive(Debug)]
enum ProcessEventDetail {
    ProcessDefined,
    ProcessCreate,
    ProcessExit,
    ThreadCreate,
    ThreadExit,
    LoadImage,
    ThreadProfile,
    ProcessStart,
    ProcessStatistics,
    SystemStatistics,
}

#[derive(Debug)]
struct RegistryEventDetail {
    op: RegistryOperation,
}

#[derive(Debug)]
struct FileSystemEventDetail {
    op: FileSystemOperation,
}

#[derive(Debug)]
struct ProfilingEventDetail {

}

#[derive(Debug)]
struct NetworkEventDetail {

}

impl From<EventInfo> for Event {
    fn from(e: EventInfo) -> Event {
        Event {
            process_index: e.process_index,
            thread_id: e.thread_id,
            event_detail: match e.event_class {
                EventClass::Process => {
                    let op = ProcessOperation::from_u16(e.event_type).expect("invalid process operation");
                    EventDetail::Process(match op {
                        ProcessOperation::ProcessDefined => ProcessEventDetail::ProcessDefined,
                        ProcessOperation::ProcessCreate => ProcessEventDetail::ProcessCreate,
                        ProcessOperation::ProcessExit => ProcessEventDetail::ProcessExit,
                        ProcessOperation::ThreadCreate => ProcessEventDetail::ThreadCreate,
                        ProcessOperation::ThreadExit => ProcessEventDetail::ThreadExit,
                        ProcessOperation::LoadImage => ProcessEventDetail::LoadImage,
                        ProcessOperation::ThreadProfile => ProcessEventDetail::ThreadProfile,
                        ProcessOperation::ProcessStart => ProcessEventDetail::ProcessStart,
                        ProcessOperation::ProcessStatistics => ProcessEventDetail::ProcessStatistics,
                        ProcessOperation::SystemStatistics => ProcessEventDetail::SystemStatistics,
                    })
                },
                EventClass::Registry => {
                    let op = RegistryOperation::from_u16(e.event_type).expect("invalid process operation");
                    EventDetail::Registry(RegistryEventDetail {
                        op,
                    })
                },
                EventClass::FileSystem => {
                    let op = FileSystemOperation::from_u16(e.event_type).expect("invalid process operation");
                    EventDetail::FileSystem(FileSystemEventDetail {
                        op,
                    })
                },
                EventClass::Profiling => {
                    EventDetail::Profiling(ProfilingEventDetail {})
                },
                EventClass::Network => {
                    EventDetail::Network(NetworkEventDetail {})
                },
                EventClass::Unknown => panic!(),
            },
            event_type: e.event_type,
            duration_in_100ns: e.duration_in_100ns,
            time: e.time,
            result: e.result,
            captured_stack_depth: e.captured_stack_depth,
        }
    }
}


struct Process {
    header: ProcessHeader,
}

impl Decode for Process {
    fn decode(data: &[u8]) -> Self {
        let header = ProcessHeader::decode(data);

        // TODO: decode modules
        Process {
            header,
        }
    }
}

