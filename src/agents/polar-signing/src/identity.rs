/*
   ACE Tool

   Copyright 2026 Carnegie Mellon University.

   NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
   FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
   EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
   PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
   MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
   TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   Licensed under a MIT (SEI)-style license, please see license.txt or contact
   permission@sei.cmu.edu for full terms.

   [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
   distribution.  Please see Copyright notice for non-US Government use and distribution.

   This Software includes and/or makes use of Third-Party Software each subject to its own license.

   DM26-0670
*/

//! A person's way of signing, from the files `just admin-claim` leaves: their certificate, what links it to the CA, and
//! their key. Here so both the tool that signs documents and the one that asks a running agent read it the same way.

/// The certificates in a PEM file, each as its own PEM string.
pub fn split_pem(pem: &str) -> Vec<String> {
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(end) = rest.find(END) {
        let (block, tail) = rest.split_at(end + END.len());
        if let Some(begin) = block.find("-----BEGIN CERTIFICATE-----") {
            out.push(format!("{}\n", block[begin..].trim_end()));
        }
        rest = tail;
    }
    out
}

/// A user's way of signing: their certificate, the certificates that link it to the CA, and their key.
pub struct Identity {
    /// The signer's own certificate first, then whatever links it to the CA.
    pub chain: Vec<String>,
    pub key_pem: String,
}

/// Reads `<user>.crt`, `<user>.key` and, if there is one, `<user>.chain.pem` (the CA certificates)
/// from `dir`, where `just admin-claim` puts them.
pub fn load_identity(dir: &std::path::Path, user: &str) -> Result<Identity, String> {
    let read = |name: String| {
        let path = dir.join(&name);
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    };
    let leaf = split_pem(&read(format!("{user}.crt"))?);
    let [leaf] = leaf.as_slice() else {
        return Err(format!(
            "{user}.crt holds {} certificates, not one",
            leaf.len()
        ));
    };
    let mut chain = vec![leaf.clone()];
    if let Ok(more) = read(format!("{user}.chain.pem")) {
        chain.extend(split_pem(&more));
    }
    Ok(Identity {
        chain,
        key_pem: read(format!("{user}.key"))?,
    })
}
