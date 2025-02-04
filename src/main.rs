use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::message_base::MessageBase;
use crate::records::a_record::ARecord;
use crate::records::aaaa_record::AAAARecord;
use crate::records::cname_record::CNameRecord;
use crate::records::inter::dns_record::DnsRecord;
use crate::records::mx_record::MxRecord;
use crate::records::ns_record::NsRecord;
use crate::records::opt_record::OptRecord;
use crate::records::ptr_record::PtrRecord;
use records::inter::record_handler::RecordHandler;
use crate::records::soa_record::SoaRecord;
use crate::records::txt_record::TxtRecord;
use crate::utils::dns_query::DnsQuery;

mod messages;
mod records;
mod utils;

//GET AWAY FROM USING ENUM FOR TYPE, GO WITH METHOD USED IN rlibdht TO HANDLE CUSTOM MESSAGES


fn main() {

    //let mut type_handler = TypeHandler::new();
    //type_handler.register_type("A", 1);

    let mut record_handler = RecordHandler::new();
    record_handler.register_record(|| Box::new(ARecord::default()));
    record_handler.register_record(|| Box::new(AAAARecord::default()));
    record_handler.register_record(|| Box::new(NsRecord::default()));
    record_handler.register_record(|| Box::new(CNameRecord::default()));
    record_handler.register_record(|| Box::new(SoaRecord::default()));
    record_handler.register_record(|| Box::new(PtrRecord::default()));
    record_handler.register_record(|| Box::new(MxRecord::default()));
    record_handler.register_record(|| Box::new(TxtRecord::default()));
    record_handler.register_record(|| Box::new(OptRecord::default()));
    //Srv
    //Opt
    //Rrsig
    //Nsec
    //Tsig
    //Caa



    /*
    Self::A => 1,
    Self::Aaaa => 28,
    Self::Ns => 2,
    Self::Cname => 5,
    Self::Soa => 6,
    Self::Ptr => 12,
    Self::Mx => 15,
    Self::Txt => 16,
    Self::Srv => 33,
    Self::Opt => 41,
    Self::Rrsig => 46,
    Self::Nsec => 47,
    Self::Spf => 99,
    Self::Tsig => 250,
    Self::Caa => 257
    */

    /*
    let hex_data: Vec<u8> = vec![
        0xaf, 0xcc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x07, 0x6f, 0x75, 0x74,
        0x6c, 0x6f, 0x6f, 0x6b, 0x06, 0x6f, 0x66, 0x66, 0x69, 0x63, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x23, 0x00, 0x0c,
        0x09, 0x73, 0x75, 0x62, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0xc0, 0x14, 0xc0, 0x30, 0x00, 0x05,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x2a, 0x00, 0x14, 0x07, 0x6f, 0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b,
        0x09, 0x6f, 0x66, 0x66, 0x69, 0x63, 0x65, 0x33, 0x36, 0x35, 0xc0, 0x1b, 0xc0, 0x48, 0x00, 0x05,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x0e, 0x06, 0x6f, 0x6f, 0x63, 0x2d, 0x67, 0x32, 0x04,
        0x74, 0x6d, 0x2d, 0x34, 0xc0, 0x14, 0xc0, 0x68, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0f,
        0x00, 0x12, 0x07, 0x6f, 0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b, 0x07, 0x6d, 0x73, 0x2d, 0x61, 0x63,
        0x64, 0x63, 0xc0, 0x14, 0xc0, 0x82, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0x00, 0x0a,
        0x07, 0x43, 0x59, 0x53, 0x2d, 0x65, 0x66, 0x7a, 0xc0, 0x8a, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x34, 0x60, 0xe4, 0xc2, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x28, 0x63, 0xa5, 0x72, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x28, 0x63, 0xa5, 0x22, 0xc0, 0xa0, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x28, 0x63, 0xfd, 0x82, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    ];

    let mut message = MessageBase::decode(&hex_data, 0);
    println!("{:x?}", hex_data);
    println!("");
    println!("{:x?}", message.encode());

    return;
    */


    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("Failed to bind socket");

    let mut message = MessageBase::new(20);
    message.add_query(DnsQuery::new("outlook.office.com", 1, DnsClasses::In));
    //message.add_query(DnsQuery::new("google.com", Types::A, DnsClasses::In));
    //message.add_query(DnsQuery::new("gmail.com", Types::Mx, DnsClasses::In));
    //message.add_query(DnsQuery::new("1.1.1.1.in-addr.arpa", Types::A, DnsClasses::In));
    message.set_recursion_desired(true);

    //message.add_query(DnsQuery::new("github.com", Types::Aaaa, DnsClasses::In));


    let encoded = message.encode();
    println!("{:?}", &encoded);

    socket.send_to(message.encode().as_slice(), SocketAddr::from((IpAddr::from([1, 1, 1, 1]), 53))).expect("Failed to send message");

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((size, src_addr)) => {
            println!("{:?}", buf);

            let message = MessageBase::decode(&record_handler, &buf, 0);
            println!("{:?}", &message.encode());
        }
        _ => {}
    }











}
