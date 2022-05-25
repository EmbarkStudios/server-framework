mod hello_world {
    tonic::include_proto!("helloworld");
}

#[cfg(test)]
mod timeout;
