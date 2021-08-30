
mod consts;
mod cursor;
mod errors;

use crate::consts::{EventClass, ProcessOperation, RegistryOperation, FileSystemOperation};
use crate::cursor::{Cursor, Parse};
use crate::errors::{FormatError};
use num_traits::FromPrimitive;    
use std::mem::MaybeUninit;
use std::fmt;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let file = &args[0];
    let data = std::fs::read(file).unwrap();

    let traces = Traces::decode(&data).unwrap();

    // println!("{:#?}", traces.header);
    for process in &traces.processes {
        println!("{:?}", DebugPrint(process, &traces));
    }

    traces.print_events().unwrap();
}

struct Traces<'a> {
    data: &'a [u8],
    header: Header,
    strings: Vec<String>,
    processes: Vec<Process>,
}

impl<'a> Traces<'a> {
    fn decode(data: &'a [u8]) -> Result<Traces<'a>, FormatError> {
        let mut c = Cursor::new(data);
        let header = Header::parse_from(&mut c)?;
        let strings = decode_strings(&mut c.seek_read_cursor(header.offset_to_strings as usize))?;
        let processes = decode_processes(&mut c.seek_read_cursor(header.offset_to_processes as usize))?;
        Ok(Traces {
            data,
            header,
            strings,
            processes,
        })
    }

    fn find_string(&self, offset: StringIndex) -> &str {
        // println!("{:?}", self.string_offsets);
        // println!("BLARG {:?}", offset);
        // let index = self.string_offsets[&offset];
        &self.strings[offset.0 as usize]
    }

    fn print_events(&self) -> Result<(), FormatError> {
        let mut c = Cursor::new(&self.data[self.header.offset_to_event_offsets as usize .. ]);

        for _ in 0..self.header.number_of_events as usize {
            let offset = u32::parse_from(&mut c)? as usize;
            let _flags = u8::parse_from(&mut c)?;
            let info = EventInfo::parse_from(&mut Cursor::new(&self.data[offset..]))?;
            let detail_base = offset + EventInfo::SIZE + info.detail_offset_from_event as usize;
            let event = Event::from_info_and_data(
                info,
                &self.data[detail_base .. detail_base + info.detail_size as usize])?;
            println!("{:?}", DebugPrint(&event, self));
        }
        Ok(())
    }
}

fn decode_strings(c: &mut Cursor) -> Result<Vec<String>, FormatError> {
    let count = u32::parse_from(c)? as usize;
    let mut offsets = Vec::with_capacity(count);

    for _ in 0..count {
        let offset = u32::parse_from(c)? as usize;
        assert!(offset >= 4 + 4*count);
        offsets.push(offset);
    }

    let mut strings = Vec::with_capacity(count);

    for offset in offsets {
        strings.push(decode_string(&mut c.seek_read_cursor(offset))?);
    }

    Ok(strings)
}

fn decode_string(c: &mut Cursor) -> Result<String, FormatError> {
    let len: u32 = c.read()?;
    let len = len as usize;
    assert!(len & 1 == 0); // len must be even, it's in bytes
    let mut data_c = c.read_cursor(len);

    // TODO: use some util library to decode u16's/etc
    let mut values = Vec::with_capacity(len / 2);
    for _ in 0..len/2 {
        values.push(u16::parse_from(&mut data_c)?);
    }

    if let Some(last) = values.pop() {
        assert_eq!(last, 0);
    }

    String::from_utf16(&values).map_err(|_| FormatError::Utf16Error)
}

fn decode_processes(c: &mut Cursor) -> Result<Vec<Process>, FormatError> {
    let count: u32 = c.read()?;
    let count = count as usize;
    // let mut indexes = Vec::with_capacity(count);
    let mut offsets = Vec::with_capacity(count);
    let mut processes = Vec::with_capacity(count);

    // Don't bother decoding the process indices, jump straight to the offsets
    c.read_bytes(4*count);

    for _ in 0..count {
        let offset = u32::parse_from(c)? as usize;
        // assert_eq!(u32::parse_from(&data[offset..]), i as u32);
        // assert!(offset >= 4 + (4*count)*3);
        offsets.push(offset);
    }

    // for i in 0..count {
    //     let offset = u32::parse_from(&data[4 + 4*i..]) as usize;
    //     // assert!(offset >= 4 + (4*count)*3);
    //     string_offsets.push(offset);
    // }

    for offset in offsets {
        processes.push(Process::parse_from(&mut c.seek_read_cursor(offset))?);
    }

    Ok(processes)
}

macro_rules! decode_field {
    (
        $simple:ident,
        $c:expr
    ) => {
        $simple::parse_from($c)?
    };
    (
        [$simple:ident; $len:expr],
        $c:expr
    ) => {{
        unsafe {
            let mut res: [MaybeUninit<$simple>; $len] = MaybeUninit::uninit().assume_init();
            decode_array($c, &mut res)?;
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

        impl Parse for $name {
            fn parse_from(c: &mut Cursor) -> Result<$name, FormatError> {
                let cur_zeros_array: [u8; 0] = [];

                $(
                    let _: [u8; $field_offset] = cur_zeros_array;
                    let cur_zeros_array: [u8; $field_offset + std::mem::size_of::<$field_ty>()] = [0; $field_offset + std::mem::size_of::<$field_ty>()];
                    let $field_name = decode_field!($field_ty, c);
                )*

                let _ = cur_zeros_array;

                Ok($name {
                    $($field_name),*
                })
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

unsafe fn decode_array<T: Parse>(c: &mut Cursor, output: &mut [MaybeUninit<T>]) -> Result<(), FormatError> {
    for res in output {
        *res = MaybeUninit::new(T::parse_from(c)?);
    }
    Ok(())
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct ProcessIndex(u32);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct StringIndex(u32);

impl Parse for StringIndex {
    fn parse_from(c: &mut Cursor) -> Result<Self, FormatError> {
        Ok(Self(u32::parse_from(c)?))
    }
}
impl Parse for ProcessIndex {
    fn parse_from(c: &mut Cursor) -> Result<Self, FormatError> {
        Ok(Self(u32::parse_from(c)?))
    }
}
impl Parse for EventClass {
    fn parse_from(c: &mut Cursor) -> Result<Self, FormatError> {
        let id = u32::parse_from(c)?;
        Self::from_u32(id).ok_or_else(|| FormatError::InvalidEventClass(id))
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

impl EventInfo {
    const SIZE: usize = 0x34; // TODO assert things about this and the last #[offset(0x30)] above
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
enum FileSystemEventDetail {
    CreateFile(CreateFileEventDetails),
    Other(FileSystemOperation),
}


#[derive(Debug)]
struct ProfilingEventDetail {

}

#[derive(Debug)]
struct NetworkEventDetail {

}

impl Event {
    fn from_info_and_data(e: EventInfo, data: &[u8]) -> Result<Event, FormatError> {
        Ok(Event {
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
                    EventDetail::FileSystem(
                        match op {
                            FileSystemOperation::CreateFile => FileSystemEventDetail::CreateFile(CreateFileEventDetails::parse_from(&mut Cursor::new(data))?),
                            op => FileSystemEventDetail::Other(op),
                        }
                    )
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
        })
    }
}

decode_struct! {
    struct CreateFileEventDetails {
        #[offset(0x0)]
        desired_access: u32,

        #[offset(0x4)]
        impersonating_sid_length: u8,

        #[offset(0x5)]
        padding_0: [u8; 3]
    }
}

// def get_filesystem_create_file_details(io, metadata, event, details_io, extra_detail_io):
//     event.details["Desired Access"] = get_filesystem_access_mask_string(read_u32(io))
//     impersonating_sid_length = read_u8(io)
//     io.seek(0x3, 1)  # padding

//     details_io.seek(0x10, 1)
//     if metadata.sizeof_pvoid == 8:
//         details_io.seek(4, 1)  # Padding for 64 bit

//     disposition_and_options = read_u32(details_io)
//     disposition = disposition_and_options >> 0x18
//     options = disposition_and_options & 0xffffff
//     if metadata.sizeof_pvoid == 8:
//         details_io.seek(4, 1)  # Padding for 64 bit
//     attributes = read_u16(details_io)
//     share_mode = read_u16(details_io)

//     event.details["Disposition"] = get_enum_name_or(FilesystemDisposition, disposition, "<unknown>")
//     event.details["Options"] = get_filesysyem_create_options(options)
//     event.details["Attributes"] = get_filesysyem_create_attributes(attributes)
//     event.details["ShareMode"] = get_filesysyem_create_share_mode(share_mode)

//     details_io.seek(0x4 + metadata.sizeof_pvoid * 2, 1)
//     allocation = read_u32(details_io)
//     allocation_value = allocation if disposition in [FilesystemDisposition.Supersede, FilesystemDisposition.Create,
//                                                      FilesystemDisposition.OpenIf,
//                                                      FilesystemDisposition.OverwriteIf] else "n/a"
//     event.details["AllocationSize"] = allocation_value

//     if impersonating_sid_length:
//         event.details["Impersonating"] = get_sid_string(io.read(impersonating_sid_length))

//     open_result = None
//     if extra_detail_io:
//         open_result = read_u32(extra_detail_io)
//         event.details["OpenResult"] = get_enum_name_or(FilesystemOpenResult, open_result, "<unknown>")

//     if open_result in [FilesystemOpenResult.Superseded, FilesystemOpenResult.Created, FilesystemOpenResult.Overwritten]:
//         event.category = "Write"
//     elif open_result in [FilesystemOpenResult.Opened, FilesystemOpenResult.Exists, FilesystemOpenResult.DoesNotExist]:
//         pass
//     elif event.details["Disposition"] in ["Open", "<unknown>"]:
//         pass
//     else:
//         event.category = "Write"


struct Process {
    header: ProcessHeader,
}

impl Parse for Process {
    fn parse_from(c: &mut Cursor) -> Result<Self, FormatError> {
        let header = ProcessHeader::parse_from(c)?;

        // TODO: decode modules
        Ok(Process {
            header,
        })
    }
}

