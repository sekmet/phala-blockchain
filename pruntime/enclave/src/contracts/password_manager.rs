use std::collections::{BTreeMap};
use serde::{Serialize, Deserialize};

use crate::contracts;
use crate::types::TxRef;
use crate::TransactionStatus;
use crate::contracts::{AccountIdWrapper};

use crate::std::string::String;
use crate::std::vec::Vec;
use core::str;

pub type LoginId = u32;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginMetadata {
    owner: AccountIdWrapper,
    website: String,
    id: u32
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginData {
    metadata: LoginMetadata,
    website: String,
    email: String,
    password: String,
    id: u32
}


/// PasswordManager contract states.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordManager {
    next_id: u32,
    logins: BTreeMap<u32, LoginData>,
    metadata: BTreeMap<u32, LoginMetadata>
}

/// The commands that the contract accepts from the blockchain. Also called transactions.
/// Commands are supposed to update the states of the contract.
#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    /// Set the password for current user
    SetCredential {
        website: String,
        email: String,
        password: String,
    },
    Destroy {
        id: LoginId,
    },
}

/// The errors that the contract could throw for some queries
#[derive(Serialize, Deserialize, Debug)]
pub enum Error {
    NotAuthorized,
    Other(String),
}

/// Query requests. The end users can only query the contract states by sending requests.
/// Queries are not supposed to write to the contract states.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    /// Read the password for current user
    GetCredential {
        id: LoginId,
        account: AccountIdWrapper
    },
    Metadata,
    /// List credentials for current user
    ListLogins {
        available_only :bool
    },
}

/// Query responses.
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    /// Return the password for current user
    GetCredential {
        website: String,
        email: String,
        password: String,
    },
    Metadata {
        metadata: Vec<LoginMetadata>
    },
    ListLogins {
        logins: Vec<LoginData>
    },
    /// Something wrong happened
    Error(Error)
}

const ALICE: &'static str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

impl PasswordManager {
    /// Initializes the contract
    pub fn new() -> Self {
        let mut logins = BTreeMap::<u32, LoginData>::new();
        let mut metadata = BTreeMap::<u32, LoginMetadata>::new();

        let adlogin = (String::from("https://www.open4g.com"), String::from("sekmet"), String::from("@MySecretPassword"));

        let owner = AccountIdWrapper::from_hex(ALICE);
        let website = String::from(adlogin.clone().0);
        let email = String::from(adlogin.clone().1);
        let password = String::from(adlogin.clone().2);

        let metadatum = LoginMetadata {
            owner: owner.clone(),
            website: website.clone(),
            id: 0
        };

        let datum = LoginData {
            metadata: metadatum.clone(),
            website: website.clone(),
            email: email.clone(),
            password: password.clone(),
            id: 0
        };

        metadata.insert(0, metadatum);
        logins.insert(0, datum);

        PasswordManager { next_id: 1, logins, metadata }
    }
}

impl contracts::Contract<Command, Request, Response> for PasswordManager {
    // Returns the contract id
    fn id(&self) -> contracts::ContractId { contracts::PASSWORD_MANAGER }

    // Handles the commands from transactions on the blockchain. This method doesn't respond.
    fn handle_command(&mut self, _origin: &chain::AccountId, _txref: &TxRef, cmd: Command) -> TransactionStatus {
        match cmd {
            // Handle the `SetCredential` command with one parameter
            Command::SetCredential { website, email, password } => {
                // Simply increment the counter by some value
                let current_user = AccountIdWrapper(_origin.clone());
                if let None = self.metadata.iter().find(|(_, metadatum)| metadatum.website == website) {

                    let id = self.next_id;
                    let metadatum = LoginMetadata {
                        owner: current_user.clone(),
                        website: website.clone(),
                        id
                    };

                    let datum = LoginData {
                        metadata: metadatum.clone(),
                        website: website.clone(),
                        email: email.clone(),
                        password: password.clone(),
                        id
                    };

                    self.metadata.insert(id, metadatum);
                    self.logins.insert(id, datum);
                    self.next_id += 1;

                    TransactionStatus::Ok
                } else {
                    TransactionStatus::WebsiteExist
                }
            
            },
            Command::Destroy {id} => {
                let o = AccountIdWrapper(_origin.clone());

                if let Some(metadatum) = self.metadata.get(&id) {
                    if metadatum.owner.to_string() == o.to_string() {
                        self.metadata.remove(&id);
                        self.logins.remove(&id);

                        TransactionStatus::Ok
                    } else {
                        TransactionStatus::NotLoginOwner
                    }
                } else {
                    TransactionStatus::LoginIdNotFound
                }
            },
        }
    }

    // Handles a direct query and responds to the query. It shouldn't modify the contract states.
    fn handle_query(&mut self, _origin: Option<&chain::AccountId>, req: Request) -> Response {
        let inner = || -> Result<Response, Error> {
            match req {
                // Handle the `GetCredential` request
                Request::GetCredential { id, account } => {
                    if _origin == None || _origin.unwrap() != &account.0 {
                        return Err(Error::NotAuthorized)
                    }

                    if let Some(metadatum) = self.metadata.get(&id) {
                        let current_userlogin = self.logins.get(&metadatum.id).unwrap();
                        
                        let email = current_userlogin.email.clone();
                        let password = current_userlogin.password.clone();
                        let website = current_userlogin.website.clone();
                        return Ok(Response::GetCredential { email, password, website })

                    } else {
                        Err(Error::Other(String::from("Credentials not found")))
                    }


                },
                Request::Metadata => {
                    Ok(Response::Metadata { metadata: self.metadata.values().cloned().collect() })
                },
                Request::ListLogins { available_only } => {
                    Ok(Response::ListLogins { logins: self.logins.values().cloned().collect() })
                }                
            }
        };
        match inner() {
            Err(error) => Response::Error(error),
            Ok(resp) => resp
        }
    }
}