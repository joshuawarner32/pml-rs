use clap::Parser;
use std::path::PathBuf;
use chrono::prelude::*;
use chrono::Duration;
use std::io::Write;
use crate::structs::Traces;

mod consts;
mod cursor;
mod errors;
mod structs;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    input: PathBuf,
    output: PathBuf,
}


fn main() {
    let args = Args::parse();
    let file = &args.input;
    let output = &args.output;

    let data = std::fs::read(file).unwrap();

    let traces = Traces::decode(&data).unwrap();

    // println!("{:#?}", traces.header);

    // for (i, process) in &traces.processes {
    //     println!("{}: {:?}", i.0, DebugPrint(process, &traces));
    // }

    let mut w = csv::WriterBuilder::new().from_path(output).unwrap();

    write_csv_events(&traces, &mut w).unwrap();
}

fn write_csv_events<W: Write>(traces: &Traces, w: &mut csv::Writer<W>) -> anyhow::Result<()> {
    let time_base = Utc.ymd(1601, 1, 1).and_hms(0, 0, 0);
    w.write_record(&["time", "duration", "category", "subcategory", "subop", "process", "path"])?;

    for event in traces.iter_events() {
        let event = event?;
        let time = time_base + Duration::nanoseconds(event.time as i64) * 100;
        let duration = Duration::nanoseconds(event.duration_in_100ns as i64) * 100;
        let process = traces.processes.get(&event.process_index);
        let subop = event.event_detail.subop().map(|op| format!("{}", op)).unwrap_or(String::new());
        if process.is_none() {
            println!("WARNING: couldn't find process for {:?}", event.process_index);
        }
        let process_path = process.map(|p| traces.find_string(p.header.image_path_string_index));
        w.write_record(&[
            &format!("{}", time),
            &format!("{}", duration),
            event.event_detail.describe_category(),
            event.event_detail.describe_subcategory(),
            &subop,
            process_path.unwrap_or("<unknown>"),
            event.event_detail.path().unwrap_or(""),
        ])?;
    }

    Ok(())
}
