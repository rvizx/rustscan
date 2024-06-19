#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use rustscan::benchmark::{Benchmark, NamedTimer};
use rustscan::input::{self, Config, Opts, ScriptsRequired};
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use rustscan::scripts::{init_scripts, Script, ScriptFile};

use futures::executor::block_on;
use std::collections::HashMap;
use std::net::IpAddr;
use std::string::ToString;
use std::time::Duration;

use rustscan::address::parse_addresses;

extern crate colorful;
extern crate dirs;

// Average value for Ubuntu
#[cfg(unix)]
const DEFAULT_FILE_DESCRIPTORS_LIMIT: u64 = 8000;
// Safest batch size based on experimentation
const AVERAGE_BATCH_SIZE: u16 = 3000;

#[macro_use]
extern crate log;

#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_lines)]
/// Faster Nmap scanning with Rust
/// If you're looking for the actual scanning, check out the module Scanner
fn main() {
    env_logger::init();
    let mut benchmarks = Benchmark::init();
    let mut rustscan_bench = NamedTimer::start("RustScan");

    let mut opts: Opts = Opts::read();
    let config = Config::read(opts.config_path.clone());
    opts.merge(&config);

    debug!("main() `opts` arguments are {:?}", opts);

    let scripts_to_run: Vec<ScriptFile> = match init_scripts(opts.scripts) {
        Ok(scripts_to_run) => scripts_to_run,
        Err(e) => {
            eprintln!("[>] error initializing scripts: {}", e);
            std::process::exit(1);
        }
    };

    debug!("scripts initialized {:?}", &scripts_to_run);

    let ips: Vec<IpAddr> = parse_addresses(&opts);

    if ips.is_empty() {
        eprintln!("[>] no IPs could be resolved, aborting scan.");
        std::process::exit(1);
    }

    #[cfg(unix)]
    let batch_size: u16 = infer_batch_size(&opts, adjust_ulimit_size(&opts));

    #[cfg(not(unix))]
    let batch_size: u16 = AVERAGE_BATCH_SIZE;

    let scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        PortStrategy::pick(&opts.range, opts.ports, opts.scan_order),
        opts.accessible,
        opts.exclude_ports.unwrap_or_default(),
    );
    debug!("scanner finished building: {:?}", scanner);

    let mut portscan_bench = NamedTimer::start("Portscan");
    let scan_result = block_on(scanner.run());
    portscan_bench.end();
    benchmarks.push(portscan_bench);

    let mut ports_per_ip = HashMap::new();

    for socket in scan_result {
        ports_per_ip
            .entry(socket.ip())
            .or_insert_with(Vec::new)
            .push(socket.port());
    }

    for ip in ips {
        if ports_per_ip.contains_key(&ip) {
            continue;
        }

        let x = format!("looks like i didn't find any open ports for {:?}. this is usually caused by a high batch size.
        \n*i used {} batch size, consider lowering it with {} or a comfortable number for your system.
        \n alternatively, increase the timeout if your ping is high. rustscan -t 2000 for 2000 milliseconds (2s) timeout.\n",
        ip,
        opts.batch_size,
        "'rustscan -b <batch_size> -a <ip address>'");
        eprintln!("[>] {}", x);
    }

    let mut script_bench = NamedTimer::start("Scripts");
    for (ip, ports) in &ports_per_ip {
        let vec_str_ports: Vec<String> = ports.iter().map(ToString::to_string).collect();

        // nmap port style is 80,443. Comma separated with no spaces.
        let ports_str = vec_str_ports.join(",");

        // if option scripts is none, no script will be spawned
        if opts.greppable || opts.scripts == ScriptsRequired::None {
            println!("[>] {} -> [{}]", &ip, ports_str);
            continue;
        }
        debug!("starting script(s)");

        // run all the scripts we found and parsed based on the script config file tags field.
        for mut script_f in scripts_to_run.clone() {
            // this part allows us to add commandline arguments to the script call_format, appending them to the end of the command.
            if !opts.command.is_empty() {
                let user_extra_args = &opts.command.join(" ");
                debug!("extra args vec {:?}", user_extra_args);
                if script_f.call_format.is_some() {
                    let mut call_f = script_f.call_format.unwrap();
                    call_f.push(' ');
                    call_f.push_str(user_extra_args);
                    println!("[>] running script {:?} on ip {}\ndepending on the complexity of the script, results may take some time to appear.", call_f, &ip);
                    debug!("call format {}", call_f);
                    script_f.call_format = Some(call_f);
                }
            }

            // building the script with the arguments from the scriptfile, and ip-ports.
            let script = Script::build(
                script_f.path,
                *ip,
                ports.clone(),
                script_f.port,
                script_f.ports_separator,
                script_f.tags,
                script_f.call_format,
            );
            match script.run() {
                Ok(script_result) => {
                    println!("[>] {}", script_result);
                }
                Err(e) => {
                    eprintln!("[>] error running script: {}", e);
                }
            }
        }
    }

    script_bench.end();
    benchmarks.push(script_bench);
    rustscan_bench.end();
    benchmarks.push(rustscan_bench);
    debug!("benchmarks raw {:?}", benchmarks);
    println!("[>] {}", benchmarks.summary());
}

#[cfg(unix)]
fn adjust_ulimit_size(opts: &Opts) -> u64 {
    use rlimit::Resource;

    if let Some(limit) = opts.ulimit {
        if Resource::NOFILE.set(limit, limit).is_ok() {
            println!("[>] automatically increasing ulimit value to {}", limit);
        } else {
            eprintln!("[>] failed to set ulimit value.");
        }
    }

    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft
}

#[cfg(unix)]
fn infer_batch_size(opts: &Opts, ulimit: u64) -> u16 {
    use std::convert::TryInto;

    let mut batch_size: u64 = opts.batch_size.into();

    // adjust the batch size when the ulimit value is lower than the desired batch size
    if ulimit < batch_size {
        eprintln!("[>] file limit is lower than default batch size. consider upping with --ulimit. may cause harm to sensitive servers");

        // when the os supports high file limits like 8000, but the user
        // selected a batch size higher than this we should reduce it to
        // a lower number.
        if ulimit < AVERAGE_BATCH_SIZE.into() {
            // ulimit is smaller than aveage batch size
            // user must have very small ulimit
            // decrease batch size to half of ulimit
            eprintln!("[>] your file limit is very small, which negatively impacts rustscan's speed. use the docker image, or up the ulimit with '--ulimit 5000'. ");
            println!("[>] halving batch_size because ulimit is smaller than average batch size");
            batch_size = ulimit / 2;
        } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
            println!("[>] batch size is now average batch size");
            batch_size = AVERAGE_BATCH_SIZE.into();
        } else {
            batch_size = ulimit - 100;
        }
    }
    // when the ulimit is higher than the batch size let the user know that the
    // batch size can be increased unless they specified the ulimit themselves.
    else if ulimit + 2 > batch_size && (opts.ulimit.is_none()) {
        println!("[>] file limit higher than batch size. can increase speed by increasing batch size '-b {}'.", ulimit - 100);
    }

    batch_size
        .try_into()
        .expect("couldn't fit the batch size into a u16.")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{adjust_ulimit_size, infer_batch_size};
    use super::{Opts};

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered() {
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        let batch_size = infer_batch_size(&opts, 120);

        assert!(batch_size < opts.batch_size);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered_average_size() {
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        let batch_size = infer_batch_size(&opts, 9_000);

        assert_eq!(batch_size, 3_000);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_equals_ulimit_lowered() {
        // because ulimit and batch size are same size, batch size is lowered
        // to ULIMIT - 100
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        let batch_size = infer_batch_size(&opts, 5_000);

        assert_eq!(batch_size, 4_900);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_adjusted_2000() {
        // ulimit == batch_size
        let mut opts = Opts::default();
        opts.batch_size = 50_000;
        opts.ulimit = Some(2_000);
        let batch_size = adjust_ulimit_size(&opts);

        assert_eq!(batch_size, 2_000);
    }

    #[test]
    #[cfg(unix)]
    fn test_high_ulimit_no_greppable_mode() {
        let mut opts = Opts::default();
        opts.batch_size = 10;
        opts.greppable = false;

        let batch_size = infer_batch_size(&opts, 1_000_000);

        assert_eq!(batch_size, opts.batch_size);
    }
}
