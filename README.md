# AzurePasswordSprayer

Tool written in Rust to perform Password Spraying attacks against Azure/Office 365 accounts.

It is multi threaded and **makes no connection attempts**.

It enables password spraying attacks against a single email address or multiple addresses from a list in a file, with the option of saving valid results to an output file.

## usage

```
Performs password spraying attacks against Azure/Office 365 accounts using one or multiple email addresses.

Usage: azure_password_sprayer [OPTIONS]

Options:
  -e, --email <EMAIL>        Email address to check
  -p, --password <PASSWORD>  Password for authentication
  -U, --userlist <USERLIST>  Path to a file containing a list of emails to check
  -o, --outfile <OUTFILE>    Output file to write the results. Defaults to "output.txt"
  -h, --help                 Print help
  -V, --version              Print version

Examples:
  ./azure_password_sprayer -e 'emailalone@mail.com' -p 'Password123'
  ./azure_password_sprayer -U mails.txt -p 'Password123' -o validaccounts.txt
```

## prerequisites

- [Rust](https://www.rust-lang.org/tools/install)

## installation

```
cargo install azure_password_sprayer
```

## compile

Linux:
```
cargo build --release
```

Windows: 

```
sudo apt update && sudo apt install mingw-w64
rustup target add x86_64-pc-windows-gnu
rustup toolchain install stable-x86_64-pc-windows-gnu
```

```
cargo build --release --target x86_64-pc-windows-gnu
```

## credits

- Technique originally discovered by Secureworks Counter Threat Unit and described on this [blog](https://www.secureworks.com/research/undetected-azure-active-directory-brute-force-attacks)
- [SSOh-No](https://github.com/optionalCTF/SSOh-No) the Go tool that motivated this Rust renovation