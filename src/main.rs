use crate::protos::proc_search_service_server::{ProcSearchService, ProcSearchServiceServer};
use crate::protos::{ProcInfoRequest, ProcInfoResponse};
use bpf::ProcInfoFollower;
use log::info;
use tonic::transport::Server;
use tonic::{Code, Request, Response, Status};

mod bpf;

mod procexec_bpf {
    include!(concat!(env!("OUT_DIR"), "/procexec.skel.rs"));
}

mod protos {
    tonic::include_proto!("procsearch");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    simple_logger::init()?;

    let proc_info_follower = tokio::task::spawn_blocking(|| ProcInfoFollower::new()).await??;
    let searcher = ProcSearcher { proc_info_follower };
    info!("Serving gRPC server");
    Server::builder()
        .add_service(ProcSearchServiceServer::new(searcher))
        .serve("127.0.0.1:50051".parse()?)
        .await?;

    Ok(())
}

pub struct ProcSearcher {
    proc_info_follower: ProcInfoFollower,
}

#[tonic::async_trait]
impl ProcSearchService for ProcSearcher {
    async fn proc_info(
        &self,
        request: Request<ProcInfoRequest>,
    ) -> Result<Response<ProcInfoResponse>, Status> {
        let pid = request.into_inner().pid;
        let proc_info = self.proc_info_follower.get_proc_info(pid).await;
        if let Some(proc_info) = proc_info {
            Ok(Response::new(ProcInfoResponse {
                pid: proc_info.pid.try_into().expect("PIDs must fit in an i32"),
                command: proc_info.command,
                args: proc_info.args,
            }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("PID {pid} does not exist in map"),
            ))
        }
    }
}
