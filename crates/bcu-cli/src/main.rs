use bcu_core::automation::{run_automation_cycle, AutomationStatus};
use bcu_core::export::{export_to_csv, export_to_json};
use bcu_core::junk::scan_disk_junk;
use bcu_core::models::{ApplicationEntry, ConfidenceLevel};
use bcu_core::recycle::clean_junk_items;
use bcu_core::registry::scan_registry_uninstallers;
use bcu_core::registry_deep::{clean_registry_remnants, scan_deep_registry_for_target};
use bcu_core::store::scan_store_apps;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "list" => {
            let include_store = args.iter().any(|a| a == "--store" || a == "-s");
            cmd_list(include_store);
        }
        "junk" => {
            if args.len() < 3 {
                eprintln!("Error: Missing application name. Usage: bcu junk <APP_NAME>");
                return;
            }
            cmd_junk(&args[2]);
        }
        "clean" => {
            if args.len() < 3 {
                eprintln!("Error: Missing application name. Usage: bcu clean <APP_NAME> [--all]");
                return;
            }
            let allow_questionable = args.iter().any(|a| a == "--all");
            cmd_clean(&args[2], allow_questionable);
        }
        "reg-junk" => {
            if args.len() < 3 {
                eprintln!("Error: Missing application name. Usage: bcu reg-junk <APP_NAME>");
                return;
            }
            cmd_reg_junk(&args[2]);
        }
        "clean-reg" => {
            if args.len() < 3 {
                eprintln!("Error: Missing application name. Usage: bcu clean-reg <APP_NAME> [--out-dir <DIR>]");
                return;
            }
            let out_dir = args
                .iter()
                .position(|a| a == "--out-dir" || a == "-o")
                .and_then(|idx| args.get(idx + 1))
                .map(PathBuf::from);
            cmd_clean_reg(&args[2], out_dir.as_deref());
        }
        "auto-click" => {
            if args.len() < 3 {
                eprintln!("Error: Missing process PID. Usage: bcu auto-click <PID>");
                return;
            }
            let pid: u32 = match args[2].parse() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("Error: PID must be a valid positive integer.");
                    return;
                }
            };
            cmd_auto_click(pid);
        }
        "export" => {
            let is_json = args.iter().any(|a| a == "--json" || a == "-j");
            let include_store = args.iter().any(|a| a == "--store" || a == "-s");
            let out_file = args
                .iter()
                .position(|a| a == "-o" || a == "--out")
                .and_then(|idx| args.get(idx + 1));
            cmd_export(is_json, include_store, out_file.map(|s| s.as_str()));
        }
        "info" => {
            if args.len() < 3 {
                eprintln!("Error: Missing search query. Usage: bcu info <QUERY>");
                return;
            }
            cmd_info(&args[2]);
        }
        "-h" | "--help" | "help" => {
            print_usage();
        }
        other => {
            eprintln!("Unknown command: '{}'", other);
            print_usage();
        }
    }
}

fn print_usage() {
    println!(
        r#"Bulk Crap Uninstaller (BCU) CLI - High Performance Rust Engine
Usage:
    bcu list [--store]                     List installed applications
    bcu junk <APP_NAME>                    Scan for leftover files on disk
    bcu clean <APP_NAME> [--all]           Safely move leftover files to Windows Recycle Bin
    bcu reg-junk <APP_NAME>                Scan deep registry remnants (MuiCache, Startup, Keys)
    bcu clean-reg <APP_NAME> [--out-dir D] Backup & clean safe registry remnants
    bcu auto-click <PID>                   Probe & click uninstaller wizard dialogs
    bcu export [--json] [-o FILE]          Export installed apps to CSV or JSON
    bcu info <QUERY>                       Display detailed application information & silent switches
    bcu help                               Show this help message"#
    );
}

fn cmd_list(include_store: bool) {
    let start = Instant::now();
    let mut apps = scan_registry_uninstallers();

    if include_store {
        let store_apps = scan_store_apps();
        apps.extend(store_apps);
    }

    let elapsed = start.elapsed();

    println!(
        "{:<45} {:<15} {:<15} {:<8}",
        "DISPLAY NAME", "VERSION", "KIND", "QUIET?"
    );
    println!("{:-<90}", "");

    for app in &apps {
        let name = truncate(&app.display_name, 43);
        let version = truncate(app.display_version.as_deref().unwrap_or("-"), 14);
        let kind = format!("{:?}", app.uninstaller_kind);
        let has_quiet = if app.quiet_uninstall_string.is_some() {
            "YES"
        } else {
            "NO"
        };

        println!(
            "{:<45} {:<15} {:<15} {:<8}",
            name, version, kind, has_quiet
        );
    }

    println!("{:-<90}", "");
    println!(
        "Total: {} applications found in {:.2} ms",
        apps.len(),
        elapsed.as_secs_f64() * 1000.0
    );
}

fn cmd_junk(app_name: &str) {
    println!("Scanning leftover disk files for: '{}'...", app_name);
    let start = Instant::now();
    let items = scan_disk_junk(app_name, None);
    let elapsed = start.elapsed();

    if items.is_empty() {
        println!("No leftover items found for '{}' (scan took {:.2} ms).", app_name, elapsed.as_secs_f64() * 1000.0);
        return;
    }

    println!("\nFound {} leftover item(s) in {:.2} ms:\n", items.len(), elapsed.as_secs_f64() * 1000.0);
    println!("{:<14} {}", "CONFIDENCE", "PATH");
    println!("{:-<80}", "");

    for item in &items {
        let badge = match item.confidence {
            ConfidenceLevel::Safe => "[SAFE]       ",
            ConfidenceLevel::Questionable => "[QUESTIONABLE]",
            ConfidenceLevel::Dangerous => "[DANGEROUS]  ",
        };

        println!("{:<14} {}", badge, item.path.display());
    }
}

fn cmd_clean(app_name: &str, allow_questionable: bool) {
    println!("Scanning and safely recycling leftovers for '{}'...", app_name);
    let items = scan_disk_junk(app_name, None);

    if items.is_empty() {
        println!("No leftover items found for '{}'.", app_name);
        return;
    }

    let (cleaned, errors) = clean_junk_items(&items, allow_questionable);
    println!("\nSuccessfully moved {} item(s) to Windows Recycle Bin.", cleaned);

    if !errors.is_empty() {
        eprintln!("\nEncountered {} warning(s)/error(s):", errors.len());
        for err in errors {
            eprintln!(" - {}", err);
        }
    }
}

fn cmd_reg_junk(app_name: &str) {
    println!("Deep scanning registry remnants for: '{}'...", app_name);
    let start = Instant::now();
    let remnants = scan_deep_registry_for_target(app_name, None, None, &[]);
    let elapsed = start.elapsed();

    if remnants.is_empty() {
        println!("No registry remnants found for '{}' (scan took {:.2} ms).", app_name, elapsed.as_secs_f64() * 1000.0);
        return;
    }

    println!("\nFound {} registry remnant(s) in {:.2} ms:\n", remnants.len(), elapsed.as_secs_f64() * 1000.0);
    println!("{:<14} {:<20} {}", "CONFIDENCE", "TYPE", "TARGET");
    println!("{:-<85}", "");

    for rem in &remnants {
        let badge = match rem.confidence {
            ConfidenceLevel::Safe => "[SAFE]       ",
            ConfidenceLevel::Questionable => "[QUESTIONABLE]",
            ConfidenceLevel::Dangerous => "[DANGEROUS]  ",
        };

        let target = if let Some(ref vname) = rem.value_name {
            format!(r"{}\{} -> {}", rem.hive, rem.subkey, vname)
        } else {
            format!(r"{}\{}", rem.hive, rem.subkey)
        };

        println!("{:<14} {:<20} {}", badge, format!("{:?}", rem.remnant_type), target);
    }
}

fn cmd_clean_reg(app_name: &str, backup_dir: Option<&std::path::Path>) {
    println!("Scanning and cleaning registry remnants for '{}'...", app_name);
    let remnants = scan_deep_registry_for_target(app_name, None, None, &[]);

    if remnants.is_empty() {
        println!("No registry remnants found for '{}'.", app_name);
        return;
    }

    match clean_registry_remnants(&remnants, backup_dir, app_name) {
        Ok((backup_file, deleted, errors)) => {
            println!("\n[SUCCESS] Cleaned {} safe registry remnant(s)!", deleted);
            println!("Rollback backup created at: {}", backup_file.display());
            println!("(To undo this cleanup, simply double-click the .reg file)");
            for err in errors {
                eprintln!(" - Failed: {}", err);
            }
        }
        Err(err) => {
            eprintln!("\n[ERROR] Failed to clean registry remnants: {}", err);
        }
    }
}

fn cmd_auto_click(pid: u32) {
    println!("Probing uninstaller wizard windows for PID {}...", pid);
    match run_automation_cycle(pid) {
        AutomationStatus::Clicked { button_text, hwnd } => {
            println!("[AUTOMATED] Clicked button \"{}\" (HWND: 0x{:X})", button_text, hwnd);
        }
        AutomationStatus::YieldToUser { reason, window_title } => {
            println!("[SAFETY PAUSE] Yielding to user. Window: \"{}\"", window_title);
            println!("Reason: {}", reason);
        }
        AutomationStatus::NoActionFound => {
            println!("[IDLE] No actionable buttons found in visible windows.");
        }
        AutomationStatus::ProcessWindowNotFound => {
            println!("[WAITING] No visible windows found for process PID {}.", pid);
        }
    }
}

fn cmd_export(is_json: bool, include_store: bool, out_file: Option<&str>) {
    let mut apps = scan_registry_uninstallers();
    if include_store {
        apps.extend(scan_store_apps());
    }

    let default_name = if is_json {
        "installed_apps.json"
    } else {
        "installed_apps.csv"
    };

    let target = out_file.unwrap_or(default_name);

    let content = if is_json {
        export_to_json(&apps)
    } else {
        export_to_csv(&apps)
    };

    match fs::write(target, content) {
        Ok(_) => println!("Successfully exported {} applications to '{}'", apps.len(), target),
        Err(err) => eprintln!("Failed to write export file '{}': {}", target, err),
    }
}

fn cmd_info(query: &str) {
    let apps = scan_registry_uninstallers();
    let q = query.to_lowercase();
    let matches: Vec<&ApplicationEntry> = apps
        .iter()
        .filter(|a| a.display_name.to_lowercase().contains(&q))
        .collect();

    if matches.is_empty() {
        println!("No application found matching '{}'", query);
        return;
    }

    for app in matches {
        println!("\n========================================================");
        println!("Application:      {}", app.display_name);
        println!("Version:          {}", app.display_version.as_deref().unwrap_or("Unknown"));
        println!("Publisher:        {}", app.publisher.as_deref().unwrap_or("Unknown"));
        println!("Installer Kind:   {:?}", app.uninstaller_kind);
        println!("Install Location: {}", app.install_location.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "Unknown".into()));
        println!("Uninstall String: {}", app.uninstall_string.as_deref().unwrap_or("None"));
        println!("Quiet Uninstall:  {}", app.quiet_uninstall_string.as_deref().unwrap_or("Not detected"));
        println!("System Component: {}", app.is_system_component);
        println!("========================================================");
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() > max_chars {
        let mut truncated: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    } else {
        s.to_string()
    }
}
