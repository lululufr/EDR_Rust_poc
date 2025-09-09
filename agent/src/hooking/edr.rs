use agent::SocketEntryReadable;


pub fn catch_net(entry: SocketEntryReadable){

    println!("blocking : {}",entry.remote_addr)


}