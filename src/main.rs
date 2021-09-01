
mod consts;
mod cursor;
mod errors;

use std::collections::HashMap;
use std::io::Write;
use crate::consts::{EventClass, ProcessOperation, RegistryOperation, FileSystemOperation};
use crate::cursor::{Cursor, Parse};
use crate::errors::{FormatError};
use num_traits::FromPrimitive;    
use std::mem::MaybeUninit;
use std::fmt;
use chrono::prelude::*;
use chrono::Duration;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let file = &args[0];
    let output = &args[1];
    assert_eq!(args.len(), 2);
    let data = std::fs::read(file).unwrap();

    let traces = Traces::decode(&data).unwrap();

    // println!("{:#?}", traces.header);

    for (i, process) in &traces.processes {
        println!("{}: {:?}", i.0, DebugPrint(process, &traces));
    }

    let mut w = csv::WriterBuilder::new().from_path(output).unwrap();

    // traces.print_events().unwrap();
    traces.write_csv_events(&mut w).unwrap();
}

struct Traces<'a> {
    data: &'a [u8],
    header: Header,
    strings: Vec<String>,
    processes: HashMap<ProcessIndex, Process>,
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

    fn iter_events(&self) -> EventIter {
        let c = Cursor::new(&self.data[self.header.offset_to_event_offsets as usize .. ]);

        let ptr_bytes = match self.header.is_64_bit {
            0 => 4,
            1 => 8,
            _ => panic!(), // TODO: FormatError
        };
        
        EventIter {
            c,
            ptr_bytes,
            data: self.data,
            remaining_events: self.header.number_of_events as usize,
        }
    }

    fn write_csv_events<W: Write>(&self, w: &mut csv::Writer<W>) -> anyhow::Result<()> {
        let time_base = Utc.ymd(1601, 1, 1).and_hms(0, 0, 0);
        w.write_record(&["time", "duration", "category", "subcategory", "process", "path"])?;

        for event in self.iter_events() {
            let event = event?;
            let time = time_base + Duration::nanoseconds(event.time as i64) * 100;
            let process = self.processes.get(&event.process_index);
            if process.is_none() {
                println!("WARNING: couldn't find process for {0} / {0:x}", event.process_index.0);
            }
            let process_path = process.map(|p| self.strings[p.header.image_path_string_index.0 as usize].as_str());
            w.write_record(&[
                &format!("{}", time),
                &format!("{}", event.duration_in_100ns),
                event.event_detail.describe_category(),
                event.event_detail.describe_subcategory(),
                process_path.unwrap_or("<unknown>"),
                event.event_detail.path().unwrap_or(""),
            ])?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn print_events(&self) -> Result<(), FormatError> {
        for event in self.iter_events() {
            let event = event?;
            println!("{:?}", DebugPrint(&event, self));
        }
        Ok(())
    }
}

struct EventIter<'a> {
    c: Cursor<'a>,
    data: &'a [u8],
    ptr_bytes: usize,
    remaining_events: usize,
}

impl<'a> EventIter<'a> {
    fn next_event(&mut self) -> Result<Event, FormatError> {
        let offset = u32::parse_from(&mut self.c)? as usize;
        let _flags = u8::parse_from(&mut self.c)?;
        let mut event_c = Cursor::new(&self.data[offset..]);
        let info = EventInfo::parse_from(&mut event_c)?;
        // dbg!(&info);
        let stack_trace_size = info.captured_stack_depth as usize * self.ptr_bytes;
        let _stack_trace = event_c.read_bytes(stack_trace_size);
        // hexdump(_stack_trace);
        // println!("---");
        let details = event_c.read_bytes(info.detail_size as usize);
        // assert_eq!(stack_trace_size, info.extra_detail_offset_from_event as usize);
        // hexdump(details);
        let event = Event::from_info_and_data(
            self.ptr_bytes,
            info,
            details)?;
        
        Ok(event)
    }
}

impl<'a> Iterator for EventIter<'a> {
    type Item = Result<Event, FormatError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_events == 0 {
            return None;
        }
        self.remaining_events -= 1;

        Some(self.next_event())
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

    decode_sized_string(&mut data_c, len / 2)
}

fn decode_sized_string(c: &mut Cursor, chars: usize) -> Result<String, FormatError> {
    // TODO: use some util library to decode u16's/etc
    let mut values = Vec::with_capacity(chars);
    for _ in 0..chars {
        values.push(u16::parse_from(c)?);
    }

    if values.last() == Some(&0) {
        values.pop();
    }

    String::from_utf16(&values).map_err(|_| FormatError::Utf16Error)
}

fn decode_processes(c: &mut Cursor) -> Result<HashMap<ProcessIndex, Process>, FormatError> {
    let count: u32 = c.read()?;
    let count = count as usize;
    // let mut indexes = Vec::with_capacity(count);
    let mut offsets = Vec::with_capacity(count);
    let mut processes = HashMap::with_capacity(count);

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
        let proc = Process::parse_from(&mut c.seek_read_cursor(offset))?;
        processes.insert(proc.header.process_index, proc);
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
        process_index: ProcessIndex,

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
        extra_detail_offset_from_event: u32
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

impl EventDetail {
    fn path(&self) -> Option<&str> {
        match self {
            EventDetail::Process(e) => e.path(),
            EventDetail::Registry(e) => e.path(),
            EventDetail::FileSystem(e) => e.path(),
            EventDetail::Profiling(e) => e.path(),
            EventDetail::Network(e) => e.path(),
        }
    }

    fn describe_category(&self) -> &'static str {
        match self {
            EventDetail::Process(_) => "Process",
            EventDetail::Registry(_) => "Registry",
            EventDetail::FileSystem(_) => "FileSystem",
            EventDetail::Profiling(_) => "Profiling",
            EventDetail::Network(_) => "Network",
        }
    }

    fn describe_subcategory(&self) -> &'static str {
        match self {
            EventDetail::Process(e) => e.describe_subcategory(),
            EventDetail::Registry(e) => e.describe_subcategory(),
            EventDetail::FileSystem(e) => e.describe_subcategory(),
            EventDetail::Profiling(e) => e.describe_subcategory(),
            EventDetail::Network(e) => e.describe_subcategory(),
        }
    }
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

impl ProcessEventDetail {
    fn path(&self) -> Option<&str> {
        None
    }

    fn describe_subcategory(&self) -> &'static str {
        match self {
            ProcessEventDetail::ProcessDefined => "ProcessDefined",
            ProcessEventDetail::ProcessCreate => "ProcessCreate",
            ProcessEventDetail::ProcessExit => "ProcessExit",
            ProcessEventDetail::ThreadCreate => "ThreadCreate",
            ProcessEventDetail::ThreadExit => "ThreadExit",
            ProcessEventDetail::LoadImage => "LoadImage",
            ProcessEventDetail::ThreadProfile => "ThreadProfile",
            ProcessEventDetail::ProcessStart => "ProcessStart",
            ProcessEventDetail::ProcessStatistics => "ProcessStatistics",
            ProcessEventDetail::SystemStatistics => "SystemStatistics",
        }
    }
}

#[derive(Debug)]
struct RegistryEventDetail {
    op: RegistryOperation,
}

impl RegistryEventDetail {
    fn path(&self) -> Option<&str> {
        None
    }

    fn describe_subcategory(&self) -> &'static str {
        match self.op {
            RegistryOperation::RegOpenKey => "RegOpenKey",
            RegistryOperation::RegCreateKey => "RegCreateKey",
            RegistryOperation::RegCloseKey => "RegCloseKey",
            RegistryOperation::RegQueryKey => "RegQueryKey",
            RegistryOperation::RegSetValue => "RegSetValue",
            RegistryOperation::RegQueryValue => "RegQueryValue",
            RegistryOperation::RegEnumValue => "RegEnumValue",
            RegistryOperation::RegEnumKey => "RegEnumKey",
            RegistryOperation::RegSetInfoKey => "RegSetInfoKey",
            RegistryOperation::RegDeleteKey => "RegDeleteKey",
            RegistryOperation::RegDeleteValue => "RegDeleteValue",
            RegistryOperation::RegFlushKey => "RegFlushKey",
            RegistryOperation::RegLoadKey => "RegLoadKey",
            RegistryOperation::RegUnloadKey => "RegUnloadKey",
            RegistryOperation::RegRenameKey => "RegRenameKey",
            RegistryOperation::RegQueryMultipleValueKey => "RegQueryMultipleValueKey",
            RegistryOperation::RegSetKeySecurity => "RegSetKeySecurity",
            RegistryOperation::RegQueryKeySecurity => "RegQueryKeySecurity",
        }
    }
}

#[derive(Debug)]
struct FileSystemEventDetail {
    sub_op: u8,
    path: String,
    ty: FileSystemEventType,
}

impl FileSystemEventDetail {
    fn path(&self) -> Option<&str> {
        Some(&self.path)
    }

    fn describe_subcategory(&self) -> &'static str {
        match self.ty {
            FileSystemEventType::CreateFile(_) => "CreateFile",
            FileSystemEventType::Other(e) => match e {
                FileSystemOperation::VolumeDismount => "IRP_MJ_VOLUME_DISMOUNT",
                FileSystemOperation::VolumeMount => "IRP_MJ_VOLUME_MOUNT",
                FileSystemOperation::FastioMdlWriteComplete => "FASTIO_MDL_WRITE_COMPLETE",
                FileSystemOperation::WriteFile2 => "FASTIO_PREPARE_MDL_WRITE",
                FileSystemOperation::FastioMdlReadComplete => "FASTIO_MDL_READ_COMPLETE",
                FileSystemOperation::ReadFile2 => "FASTIO_MDL_READ",
                FileSystemOperation::QueryOpen => "FASTIO_NETWORK_QUERY_OPEN",
                FileSystemOperation::FastioCheckIfPossible => "FASTIO_CHECK_IF_POSSIBLE",
                FileSystemOperation::IrpMj12 => "IRP_MJ_12",
                FileSystemOperation::IrpMj11 => "IRP_MJ_11",
                FileSystemOperation::IrpMj10 => "IRP_MJ_10",
                FileSystemOperation::IrpMj9 => "IRP_MJ_9",
                FileSystemOperation::IrpMj8 => "IRP_MJ_8",
                FileSystemOperation::FastioNotifyStreamFoCreation => "FASTIO_NOTIFY_STREAM_FO_CREATION",
                FileSystemOperation::FastioReleaseForCcFlush => "FASTIO_RELEASE_FOR_CC_FLUSH",
                FileSystemOperation::FastioAcquireForCcFlush => "FASTIO_ACQUIRE_FOR_CC_FLUSH",
                FileSystemOperation::FastioReleaseForModWrite => "FASTIO_RELEASE_FOR_MOD_WRITE",
                FileSystemOperation::FastioAcquireForModWrite => "FASTIO_ACQUIRE_FOR_MOD_WRITE",
                FileSystemOperation::FastioReleaseForSectionSynchronization => "FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION",
                FileSystemOperation::CreateFileMapping => "FASTIO_ACQUIRE_FOR_SECTION_SYNCHRONIZATION",
                FileSystemOperation::CreateFile => "IRP_MJ_CREATE",
                FileSystemOperation::CreatePipe => "IRP_MJ_CREATE_NAMED_PIPE",
                FileSystemOperation::IrpMjClose => "IRP_MJ_CLOSE",
                FileSystemOperation::ReadFile => "IRP_MJ_READ",
                FileSystemOperation::WriteFile => "IRP_MJ_WRITE",
                FileSystemOperation::QueryInformationFile => "IRP_MJ_QUERY_INFORMATION",
                FileSystemOperation::SetInformationFile => "IRP_MJ_SET_INFORMATION",
                FileSystemOperation::QueryEAFile => "IRP_MJ_QUERY_EA",
                FileSystemOperation::SetEAFile => "IRP_MJ_SET_EA",
                FileSystemOperation::FlushBuffersFile => "IRP_MJ_FLUSH_BUFFERS",
                FileSystemOperation::QueryVolumeInformation => "IRP_MJ_QUERY_VOLUME_INFORMATION",
                FileSystemOperation::SetVolumeInformation => "IRP_MJ_SET_VOLUME_INFORMATION",
                FileSystemOperation::DirectoryControl => "IRP_MJ_DIRECTORY_CONTROL",
                FileSystemOperation::FileSystemControl => "IRP_MJ_FILE_SYSTEM_CONTROL",
                FileSystemOperation::DeviceIoControl => "IRP_MJ_DEVICE_CONTROL",
                FileSystemOperation::InternalDeviceIoControl => "IRP_MJ_INTERNAL_DEVICE_CONTROL",
                FileSystemOperation::Shutdown => "IRP_MJ_SHUTDOWN",
                FileSystemOperation::LockUnlockFile => "IRP_MJ_LOCK_CONTROL",
                FileSystemOperation::CloseFile => "IRP_MJ_CLEANUP",
                FileSystemOperation::CreateMailSlot => "IRP_MJ_CREATE_MAILSLOT",
                FileSystemOperation::QuerySecurityFile => "IRP_MJ_QUERY_SECURITY",
                FileSystemOperation::SetSecurityFile => "IRP_MJ_SET_SECURITY",
                FileSystemOperation::Power => "IRP_MJ_POWER",
                FileSystemOperation::SystemControl => "IRP_MJ_SYSTEM_CONTROL",
                FileSystemOperation::DeviceChange => "IRP_MJ_DEVICE_CHANGE",
                FileSystemOperation::QueryFileQuota => "IRP_MJ_QUERY_QUOTA",
                FileSystemOperation::SetFileQuota => "IRP_MJ_SET_QUOTA",
                FileSystemOperation::PlugAndPlay => "IRP_MJ_PNP",
            }
        }
    }
}

#[derive(Debug)]
enum FileSystemEventType {
    CreateFile(CreateFileEventDetails),
    Other(FileSystemOperation),
}


#[derive(Debug)]
struct ProfilingEventDetail {

}

impl ProfilingEventDetail {
    fn path(&self) -> Option<&str> {
        None
    }

    fn describe_subcategory(&self) -> &'static str {
        "<unknown>"
    }
}

#[derive(Debug)]
struct NetworkEventDetail {

}

impl NetworkEventDetail {
    fn path(&self) -> Option<&str> {
        None
    }

    fn describe_subcategory(&self) -> &'static str {
        "<unknown>"
    }
}

impl Event {
    fn from_info_and_data(ptr_bytes: usize, e: EventInfo, data: &[u8]) -> Result<Event, FormatError> {
        let mut c = Cursor::new(data);
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
                    EventDetail::FileSystem(FileSystemEventDetail::parse_event_type_data(ptr_bytes, e.event_type, &mut c)?)
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

#[allow(dead_code)]
fn hexdump(bytes: &[u8]) {
    let mut line = String::new();
    for c in bytes.chunks(16) {
        for i in 0..16 {
            if i & 0x3 == 0 && i > 0 {
                line.push(' ');
            }
            if let Some(b) = c.get(i) {
                line.push_str(&format!("{:02x} ", b));
            } else {
                line.push_str("   ");
            }
        }

        line.push_str("| ");

        for b in c {
            if b.is_ascii() && !(*b as char).is_ascii_control() {
                line.push(*b as char);
            } else {
                line.push('.');
            }
        }
        println!("{}", line);
        line.clear();
    }
}

impl FileSystemEventDetail {
    pub fn parse_event_type_data(ptr_bytes: usize, event_type: u16, c: &mut Cursor) -> Result<Self, FormatError> {
        let op = FileSystemOperation::from_u16(event_type).expect("invalid process operation");
        let sub_op: u8 = c.read()?;
        c.read_bytes(3); // padding

        let mut details_c = c.read_cursor(ptr_bytes * 5 + 0x14);

        let path_info = read_path_info(c)?;

        c.read_bytes(2); // padding

        let path = read_detail_string(c, path_info)?;

        let ty = match op {
            FileSystemOperation::CreateFile => FileSystemEventType::CreateFile(CreateFileEventDetails::parse_from(&mut details_c)?),
            op => FileSystemEventType::Other(op),
        };

        Ok(FileSystemEventDetail {
            sub_op,
            path,
            ty,
        })
    }
}

fn read_path_info(c: &mut Cursor) -> Result<(bool, usize), FormatError> {
    let flags: u16 = c.read()?;
    Ok((flags >> 15 == 1, (flags & !(1 << 15)) as usize))
}

fn read_detail_string(c: &mut Cursor, (is_ascii, chars): (bool, usize)) -> Result<String, FormatError> {
    if is_ascii {
        let bytes = c.read_bytes(chars);
        String::from_utf8(bytes.to_vec()).map_err(|_| FormatError::AsciiError)
    } else {
        decode_sized_string(c, chars)
    }
}

#[derive(Debug)]
struct CreateFileEventDetails {
    desired_access: u32,
    impersonating_sid_length: u8,
}

impl CreateFileEventDetails {
    pub fn parse_from(c: &mut Cursor) -> Result<Self, FormatError> {
        let desired_access = c.read()?;
        let impersonating_sid_length = c.read()?;
        Ok(CreateFileEventDetails {
            desired_access,
            impersonating_sid_length,
        })
    }
}

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

