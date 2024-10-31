use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::page_data::{HashChain, PageData};
use aqua_verifier_rs_types::models::revision::Revision;

use std::sync::mpsc;
use std::thread;

use crate::revision_integrity::{RevisionIntegrity, HashChainIntegrity};
use crate::verification::{only_signature_hash_integrity, only_verification_hash_integrity, only_witness_hash_integrity};

pub fn revision_integrity_ignore_absent(
    rev: &Revision,
    prev: Option<&Revision>,
) -> flagset::FlagSet<RevisionIntegrity> {
    ignore_absent(revision_integrity(rev, prev))
}

pub fn revision_integrity(
    rev: &Revision,
    prev: Option<&Revision>,
) -> flagset::FlagSet<RevisionIntegrity> {
    let mut integrity = only_verification_hash_integrity(rev, prev);
    integrity |= only_signature_hash_integrity(rev, prev);
    integrity |= only_witness_hash_integrity(rev, prev);

    integrity
}

pub fn ignore_absent(
    mut revision_integrity: flagset::FlagSet<RevisionIntegrity>,
) -> flagset::FlagSet<RevisionIntegrity> {
    use RevisionIntegrity::*;
    revision_integrity -= NoSignature;
    revision_integrity -= NoWitness;
    revision_integrity
}

#[cfg(test)]
pub fn hash_chain_integrity(
    hash_chain: &HashChain,
) -> (
    flagset::FlagSet<HashChainIntegrity>,
    Vec<(&Revision, flagset::FlagSet<RevisionIntegrity>)>,
) {
    use crate::revision_integrity::HashChainIntegrity;

    let (mut integrity, chain) = only_hash_chain_extract_revision_chain(hash_chain);

    let revision_integrities = chain
        .iter()
        .copied()
        .map(|(rev, prev)| {
            let rev_integ = revision_integrity(rev, prev);
            if !ignore_absent(rev_integ).is_empty() {
                integrity |= HashChainIntegrity::RevisionIntegrityFatal;
            }
            (rev, rev_integ)
        })
        .collect();

    (integrity, revision_integrities)
}

pub fn validate(content: String, _rpc: String) {
    let representation_json: PageData = match serde_json::from_str(content.as_str()) {
        Err(why) => {
            eprintln!("couldn't parse object from json: {}", why);
            return;
        }
        Ok(repr) => repr,
    };

    for p in representation_json.pages {
        // vector of channels to write read results of individual revision validations
        let mut rs: Vec<mpsc::Receiver<(String, flagset::FlagSet<RevisionIntegrity>)>> = vec![];
        thread::scope(|s| {
            let mut handles: Vec<thread::ScopedJoinHandle<()>> = vec![];

            let mut i = 0;

            for (key, r) in p.revisions.iter() {
                let mut previous_revision = None;
                if i > 0 {
                    previous_revision = Some(p.revisions[i - 1].1.clone());
                };
                i += 1;
                let (tx, rx) = mpsc::channel();
                rs.push(rx);
                let handle = s.spawn(move || {
                    let vresult =
                        revision_validation(key.to_string(), r, previous_revision.as_ref());
                    tx.send(vresult).unwrap()
                });
                handles.push(handle);
            }
            for h in handles {
                h.join().unwrap();
            }
        });

        for r in rs {
            let (k3y, rec) = r.recv().unwrap();
            println!("got: {:#?} for: {}", rec, k3y);
        }

        let chain_linear = chain_validation(p);
        if chain_linear {
            println!("chain linear integrity valid");
        } else {
            eprintln!("chain linear integrity broken");
        }
    }
}

pub fn revision_validation(
    key: String,
    r: &Revision,
    p: Option<&Revision>,
) -> (String, flagset::FlagSet<RevisionIntegrity>) {
    let revision_integrity = revision_integrity_ignore_absent(r, p);
    (key, revision_integrity)
}

pub fn chain_validation(p: HashChain) -> bool {
    let mut integrity = true;

    let mut last_hash: Option<Hash> = None;

    for (key, r) in p.revisions {
        if key != r.metadata.verification_hash {
            integrity = false;
            eprintln!(
                "key didnt match verification hash in metadata: {} {}",
                key, r.metadata.verification_hash
            );
        }

        if let Some(value) = last_hash {
            println!("last_hash has value: {}", value);
            if r.metadata.previous_verification_hash != last_hash {
                integrity = false;
                eprintln!(
                    "last hash didnt match current last verification hash in metadata: {:#?} {:#?}",
                    last_hash, r.metadata.previous_verification_hash
                );
            }
        }

        last_hash = Some(r.metadata.verification_hash);
    }

    integrity
}
