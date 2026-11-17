// Loopback transport regressions for the same acquisition function used above.
// Synthetic protobuf payloads are NOT valid cryptographic decryption responses.
// These tests never start KMS, FHE, setup, owner approval or release operations.
#[cfg(test)]
mod recipient_result_transport_tests {
    use super::acquire_accepted_user_results;
    use kms_grpc::kms::v1::{RequestId, UserDecryptionResponse};
    use kms_grpc::kms_service::v1::{
        core_service_endpoint_client::CoreServiceEndpointClient,
        core_service_endpoint_server::{CoreServiceEndpoint, CoreServiceEndpointServer},
    };
    use std::{collections::VecDeque, sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}};
    use tonic::{Request, Response, Status};

    #[derive(Clone)]
    enum Reply { Ready(u8), Pending, Missing }
    #[derive(Clone)]
    struct MockCore {
        replies: Arc<Mutex<VecDeque<Reply>>>,
        last: Arc<Mutex<Reply>>,
        calls: Arc<AtomicUsize>,
        unexpected: Arc<AtomicUsize>,
    }
    #[tonic::async_trait]
    impl CoreServiceEndpoint for MockCore {
        async fn get_user_decryption_result(&self, request: Request<RequestId>)
            -> std::result::Result<Response<UserDecryptionResponse>, Status> {
            if request.get_ref().request_id != "11".repeat(32) {
                return Err(Status::invalid_argument("request ID changed during result acquisition"));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            let next = self.replies.lock().unwrap().pop_front();
            let reply = match next {
                Some(value) => { *self.last.lock().unwrap() = value.clone(); value },
                None => self.last.lock().unwrap().clone(),
            };
            match reply {
                Reply::Ready(core) => Ok(Response::new(UserDecryptionResponse {
                    extra_data: vec![core], ..Default::default()
                })),
                Reply::Pending => Err(Status::unavailable("acknowledged computation pending")),
                Reply::Missing => Err(Status::not_found("no acknowledged computation on this core")),
            }
        }
        async fn key_gen_preproc(&self, _request: tonic::Request<kms_grpc::kms::v1::KeyGenPreprocRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn partial_key_gen_preproc(&self, _request: tonic::Request<kms_grpc::kms::v1::PartialKeyGenPreprocRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_key_gen_preproc_result(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::KeyGenPreprocResult>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn key_gen(&self, _request: tonic::Request<kms_grpc::kms::v1::KeyGenRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_key_gen_result(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::KeyGenResult>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn insecure_key_gen(&self, _request: tonic::Request<kms_grpc::kms::v1::KeyGenRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_insecure_key_gen_result(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::KeyGenResult>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn abort_key_gen(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn public_decrypt(&self, _request: tonic::Request<kms_grpc::kms::v1::PublicDecryptionRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_public_decryption_result(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::PublicDecryptionResponse>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn user_decrypt(&self, _request: tonic::Request<kms_grpc::kms::v1::UserDecryptionRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn crs_gen(&self, _request: tonic::Request<kms_grpc::kms::v1::CrsGenRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_crs_gen_result(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::CrsGenResult>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn insecure_crs_gen(&self, _request: tonic::Request<kms_grpc::kms::v1::CrsGenRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_insecure_crs_gen_result(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::CrsGenResult>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn abort_crs_gen(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn new_mpc_context(&self, _request: tonic::Request<kms_grpc::kms::v1::NewMpcContextRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn destroy_mpc_context(&self, _request: tonic::Request<kms_grpc::kms::v1::DestroyMpcContextRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn new_custodian_context(&self, _request: tonic::Request<kms_grpc::kms::v1::NewCustodianContextRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn destroy_custodian_context(&self, _request: tonic::Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn new_mpc_epoch(&self, _request: tonic::Request<kms_grpc::kms::v1::NewMpcEpochRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_epoch_result(&self, _request: tonic::Request<kms_grpc::kms::v1::RequestId>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::EpochResultResponse>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn destroy_mpc_epoch(&self, _request: tonic::Request<kms_grpc::kms::v1::DestroyMpcEpochRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_operator_public_key(&self, _request: tonic::Request<kms_grpc::kms::v1::Empty>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::OperatorPublicKey>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn restore_from_backup(&self, _request: tonic::Request<kms_grpc::kms::v1::Empty>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn custodian_recovery_init(&self, _request: tonic::Request<kms_grpc::kms::v1::CustodianRecoveryInitRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::RecoveryRequest>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn custodian_backup_recovery(&self, _request: tonic::Request<kms_grpc::kms::v1::CustodianRecoveryRequest>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_key_material_availability(&self, _request: tonic::Request<kms_grpc::kms::v1::Empty>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::KeyMaterialAvailabilityResponse>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
        async fn get_health_status(&self, _request: tonic::Request<kms_grpc::kms::v1::Empty>)
            -> std::result::Result<tonic::Response<kms_grpc::kms::v1::HealthStatusResponse>, tonic::Status> {
            self.unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(tonic::Status::unimplemented("transport test only permits bound result reads"))
        }
    }
    struct Harness {
        clients: Vec<CoreServiceEndpointClient<tonic::transport::Channel>>,
        calls: Vec<Arc<AtomicUsize>>,
        unexpected: Arc<AtomicUsize>,
        servers: Vec<tokio::task::JoinHandle<()>>,
    }
    impl Drop for Harness {
        fn drop(&mut self) { for server in &self.servers { server.abort(); } }
    }
    impl Harness {
        async fn new(scripts: Vec<Vec<Reply>>) -> Self {
            assert_eq!(scripts.len(), 4);
            let mut clients=Vec::new(); let mut calls=Vec::new(); let mut servers=Vec::new();
            let unexpected=Arc::new(AtomicUsize::new(0));
            for script in scripts {
                let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address=listener.local_addr().unwrap();
                let counter=Arc::new(AtomicUsize::new(0));
                let service=MockCore { replies:Arc::new(Mutex::new(script.clone().into())),
                    last:Arc::new(Mutex::new(script.last().unwrap().clone())),
                    calls:counter.clone(), unexpected:unexpected.clone() };
                let incoming=Box::pin(futures::stream::unfold(listener, |listener| async move {
                    Some((listener.accept().await.map(|(socket,_)|socket),listener))
                }));
                servers.push(tokio::spawn(async move {
                    tonic::transport::Server::builder().add_service(CoreServiceEndpointServer::new(service))
                        .serve_with_incoming(incoming).await.unwrap();
                }));
                clients.push(CoreServiceEndpointClient::connect(format!("http://{address}")).await.unwrap());
                calls.push(counter);
            }
            Self {clients,calls,unexpected,servers}
        }
        fn counts(&self) -> Vec<usize> { self.calls.iter().map(|c|c.load(Ordering::SeqCst)).collect() }
        fn no_mutations(&self) { assert_eq!(self.unexpected.load(Ordering::SeqCst),0); }
    }
    fn request() -> RequestId { RequestId {request_id:"11".repeat(32)} }
    fn scripts() -> Vec<Vec<Reply>> {
        vec![vec![Reply::Ready(1)],vec![Reply::Ready(2)],vec![Reply::Missing],vec![Reply::Ready(4)]]
    }

    #[tokio::test]
    async fn tops_transport_accepted_124_skips_failed3() {
        let harness=Harness::new(scripts()).await;
        let (responses,polls)=acquire_accepted_user_results(&harness.clients,&request(),&[1,2,4],&[3],2).await.unwrap();
        assert_eq!(responses.iter().map(|r|r.extra_data[0]).collect::<Vec<_>>(),vec![1,2,4]);
        assert_eq!(polls,3); assert_eq!(harness.counts(),vec![1,1,0,1]); harness.no_mutations();
    }

    #[tokio::test]
    async fn tops_transport_original_numeric_order_counterexample() {
        let harness=Harness::new(scripts()).await;
        let mut responses=Vec::new(); let mut failure=None;
        for client in &harness.clients {
            match client.clone().get_user_decryption_result(Request::new(request())).await {
                Ok(response)=>responses.push(response.into_inner()),
                Err(error)=>{ failure=Some(error); break; }
            }
            if responses.len()>=3 { break; }
        }
        assert_eq!(failure.unwrap().code(),tonic::Code::NotFound);
        assert_eq!(responses.len(),2); assert_eq!(harness.counts(),vec![1,1,1,0]); harness.no_mutations();
    }

    #[tokio::test]
    async fn tops_transport_two_acks_rejected_before_fetch() {
        let harness=Harness::new(scripts()).await;
        assert!(acquire_accepted_user_results(&harness.clients,&request(),&[1,2],&[3,4],2).await.is_err());
        assert_eq!(harness.counts(),vec![0,0,0,0]); harness.no_mutations();
    }

    #[tokio::test]
    async fn tops_transport_unavailable_is_polled_without_resubmission() {
        let mut values=scripts(); values[0]=vec![Reply::Pending,Reply::Ready(1)];
        let harness=Harness::new(values).await;
        let (responses,polls)=acquire_accepted_user_results(&harness.clients,&request(),&[1,2,4],&[3],2).await.unwrap();
        assert_eq!(responses.len(),3); assert_eq!(polls,4);
        assert_eq!(harness.counts(),vec![2,1,0,1]); harness.no_mutations();
    }

    #[tokio::test]
    async fn tops_transport_accepted_core_notfound_fails_closed() {
        let harness=Harness::new(scripts()).await;
        let error=acquire_accepted_user_results(&harness.clients,&request(),&[1,2,3,4],&[],2).await.unwrap_err();
        assert_eq!(error.downcast_ref::<Status>().unwrap().code(),tonic::Code::NotFound);
        assert_eq!(harness.counts(),vec![1,1,1,0]); harness.no_mutations();
    }

    #[tokio::test]
    async fn tops_transport_insufficient_results_remain_failure() {
        let mut values=scripts(); values[0]=vec![Reply::Pending];
        let harness=Harness::new(values).await;
        assert!(acquire_accepted_user_results(&harness.clients,&request(),&[1,2,4],&[3],2).await.is_err());
        assert_eq!(harness.counts(),vec![2,1,0,1]); harness.no_mutations();
    }

    #[tokio::test]
    async fn tops_transport_duplicate_core_partition_rejected_before_fetch() {
        let harness=Harness::new(scripts()).await;
        assert!(acquire_accepted_user_results(&harness.clients,&request(),&[1,2,2],&[3,4],2).await.is_err());
        assert_eq!(harness.counts(),vec![0,0,0,0]); harness.no_mutations();
    }
}
