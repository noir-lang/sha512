use std::collections::BTreeMap;
use std::path::PathBuf;

use noir_runner::{InputValue, NoirRunner, ToNoir};
use proptest::{prelude::prop, prop_assert_eq, test_runner::TestRunner};
use sha2::{Digest, Sha512, Sha384};

#[test]
fn test_prop_sha512_1() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 1>(0..255u8);
    
    test_runner
        .run(&strategy, |vector| {
            let bounded_vec = BTreeMap::from([
                ("storage".to_string(), vector.into_iter().collect::<Vec<_>>().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);
            let input = BTreeMap::from([
                ("input".to_string(), InputValue::Struct(bounded_vec)),
            ]); 
            
            let result = runner.run("test_sha512_1", input).unwrap().unwrap();
            let expected: [u8; 64] = Sha512::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}




#[test]
fn test_prop_sha512_100() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 100>(0..255u8);
    
    test_runner
        .run(&strategy, |vector| {
            let bounded_vec = BTreeMap::from([
                ("storage".to_string(), vector.into_iter().collect::<Vec<_>>().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);
            let input = BTreeMap::from([
                ("input".to_string(), InputValue::Struct(bounded_vec)),
            ]); 
            
            let result = runner.run("test_sha512_100", input).unwrap().unwrap();
            let expected: [u8; 64] = Sha512::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}


#[test]
fn test_prop_sha512_256() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 256>(0..255u8);
    
    test_runner
        .run(&strategy, |vector| {
            let bounded_vec = BTreeMap::from([
                ("storage".to_string(), vector.into_iter().collect::<Vec<_>>().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);
            let input = BTreeMap::from([
                ("input".to_string(), InputValue::Struct(bounded_vec)),
            ]); 
            
            let result = runner.run("test_sha512_256", input).unwrap().unwrap();
            let expected: [u8; 64] = Sha512::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}

#[test]

#[test]
fn test_prop_sha384_1() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 1>(0..255u8);
    
    test_runner
        .run(&strategy, |vector| {
            let bounded_vec = BTreeMap::from([
                ("storage".to_string(), vector.into_iter().collect::<Vec<_>>().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);
            let input = BTreeMap::from([
                ("input".to_string(), InputValue::Struct(bounded_vec)),
            ]); 
            
            let result = runner.run("test_sha384_1", input).unwrap().unwrap();
            let expected: [u8; 48] = Sha384::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}




#[test]
fn test_prop_sha384_100() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 100>(0..255u8);
    
    test_runner
        .run(&strategy, |vector| {
            let bounded_vec = BTreeMap::from([
                ("storage".to_string(), vector.into_iter().collect::<Vec<_>>().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);
            let input = BTreeMap::from([
                ("input".to_string(), InputValue::Struct(bounded_vec)),
            ]); 
            
            let result = runner.run("test_sha384_100", input).unwrap().unwrap();
            let expected: [u8; 48] = Sha384::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}



#[test]
fn test_prop_sha384_256() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 256>(0..255u8);
    
    test_runner
        .run(&strategy, |vector| {
            let bounded_vec = BTreeMap::from([
                ("storage".to_string(), vector.into_iter().collect::<Vec<_>>().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);
            let input = BTreeMap::from([
                ("input".to_string(), InputValue::Struct(bounded_vec)),
            ]); 
            
            let result = runner.run("test_sha384_256", input).unwrap().unwrap();
            let expected: [u8; 48] = Sha384::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}




