mod eauth;

use eauth::EauthClient;
use std::io::{self, Write};
use std::process;
use std::thread::sleep;
use std::time::Duration;

/// Equivalent of Python's `os.system('cls')` / clearing the terminal.
fn clear_screen() {
    if cfg!(target_os = "windows") {
        let _ = process::Command::new("cmd").args(["/C", "cls"]).status();
    } else {
        // ANSI clear-screen + move cursor home; works in any unix terminal
        print!("\x1B[2J\x1B[1;1H");
        let _ = io::stdout().flush();
    }
}

/// Prompt for a line of input and return it trimmed, like Python's input().
fn prompt(label: &str) -> String {
    print!("{label}");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap_or(0);
    buf.trim_end_matches(['\r', '\n']).to_string()
}

/// Equivalent of run_pause_command() in main.py
fn run_pause_command() {
    if cfg!(target_os = "windows") {
        let _ = process::Command::new("cmd").args(["/C", "pause"]).status();
    } else {
        prompt("Press Enter to continue...");
    }
}

fn print_banner() {
    println!("▒█▀▀▀ ░█▀▀█ ▒█░▒█ ▀▀█▀▀ ▒█░▒█ ");
    println!("▒█▀▀▀ ▒█▄▄█ ▒█░▒█ ░▒█░░ ▒█▀▀█ ");
    println!("▒█▄▄▄ ▒█░▒█ ░▀▄▄▀ ░▒█░░ ▒█░▒█");
    println!(" ");
    println!(" ");
}

/// Equivalent of main_f() in main.py. Loops instead of recursing so a long
/// running session can't overflow the stack.
fn main_menu(client: &mut EauthClient) {
    loop {
        clear_screen();
        print_banner();
        println!("[ 1 ] Login     [ 2 ] Register");
        println!(" ");
        print!("[?] ");
        let _ = io::stdout().flush();
        let value = prompt("user@eauth:~$ ");

        match value.as_str() {
            "1" => {
                clear_screen();
                let username = prompt("Username: ");
                let password = prompt("Password: ");

                if client.login_request(&username, &password) {
                    clear_screen();
                    println!("You are logged in!");
                    println!(" ");
                    println!("Rank: {}", client.rank);
                    println!("Create Date: {}", client.register_date);
                    println!("Expire Date: {}", client.expire_date);
                    println!("Hardware ID: {}", client.user_hwid);
                } else {
                    println!("{}", client.error_message);
                }
                sleep(Duration::from_millis(3000));
            }
            "2" => {
                clear_screen();
                let username = prompt("Username: ");
                let password = prompt("Password: ");
                let invite = prompt("License Key: ");

                if client.register_request(&username, &password, &invite) {
                    clear_screen();
                    println!("You are registered!");
                } else {
                    println!("{}", client.error_message);
                }
                sleep(Duration::from_millis(1500));
            }
            _ => {
                clear_screen();
                println!("Invalid input!");
                sleep(Duration::from_millis(1000));
            }
        }
    }
}

fn main() {
    let mut client = EauthClient::new();

    // Init request
    if !client.init_request() {
        println!("{}", client.error_message);
        sleep(Duration::from_millis(1500));
        process::exit(0);
    }

    main_menu(&mut client);

    // Unreachable while main_menu loops forever, kept for parity with main.py
    // in case you later add a "quit" branch to the menu.
    #[allow(unreachable_code)]
    run_pause_command();
}
