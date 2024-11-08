#[cfg(test)]
pub mod tests {
    use std::path::Path;

    use aqua_verifier_rs_types::models::page_data::PageData;

    use crate::util::{read_aqua_data, verify_content_util, verify_metadata_util};


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


}
