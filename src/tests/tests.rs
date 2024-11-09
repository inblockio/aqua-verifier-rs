#[cfg(test)]
pub mod tests {
    use std::{fs, path::{Path, PathBuf}};

    use aqua_verifier_rs_types::models::page_data::PageData;

    use crate::util::{ verify_content_util, verify_metadata_util, verify_signature_util};

     fn read_aqua_data(path: &PathBuf) -> Result<PageData, String> {
        let data = fs::read_to_string(path);
        match data {
            Ok(data) => {
                let res = serde_json::from_str::<PageData>(&data);
                match res {
                    Ok(res_data) => Ok(res_data),
                    Err(err_data) => {
                        return Err(format!("Error, parsing json {}", err_data));
                    }
                }
            }
            Err(e) => {
                return Err(format!("Error , {}", e));
            }
        }
    }

    #[test]
    fn test_verify_file_content() {

        let path = Path::new("src/tests/sample.json");

        print!("Path is  {}", path.display());
        let res: Result<PageData, String> = read_aqua_data(&path.to_path_buf());

        if res.is_err(){
            panic!("Cannot read json");

        }
        let hash_chain = res.unwrap().pages;
        let (_hash,revsion) = hash_chain.get(0).unwrap().revisions.get(0).unwrap();

        let (is_ok , _reason ) = verify_content_util(&revsion.content);

        assert_eq!(is_ok, true);
    }


    #[test]
    fn test_verify_metadata_content() {

        let path = Path::new("src/tests/sample.json");

        print!("Path is  {}", path.display());
        let res: Result<PageData, String> = read_aqua_data(&path.to_path_buf());

        if res.is_err(){
            panic!("Cannot read json");

        }
        let hash_chain = res.unwrap().pages;
        let (_hash,revsion) = hash_chain.get(0).unwrap().revisions.get(0).unwrap();

        let (is_ok , _reason ) = verify_metadata_util(&revsion.metadata);

        assert_eq!(is_ok, true);
    }



    #[test]
    fn test_verify_signature() {

        let path = Path::new("src/tests/sample.json");

        print!("Path is  {}", path.display());
        let res: Result<PageData, String> = read_aqua_data(&path.to_path_buf());

        if res.is_err(){
            panic!("Cannot read json");

        }
        let hash_chain = res.unwrap().pages;
        let (_hash,revsion) = hash_chain.get(0).unwrap().revisions.get(0).unwrap();
        let (_hash_2,revsion_2) = hash_chain.get(0).unwrap().revisions.get(1).unwrap();

        let (is_ok , _reason ) = verify_signature_util(revsion_2.signature.clone().unwrap(),revsion.metadata.verification_hash);

        assert_eq!(is_ok, true);
    }


}
