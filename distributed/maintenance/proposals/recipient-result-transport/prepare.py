"""Prepare a guarded recipient-only candidate in a fresh directory.

Never edits the current client, builds native code or calls a cloud/role API.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED_SOURCE_SHA256 = 'ac97b5b7199c4d002d83380db5173742cf5dbd9949ebc14728e5233b9d9953ba'
OLD_SUBMISSION = '''        for (core,result) in futures::future::join_all(submissions).await {
            match result {
                Ok(Ok(_))=>accepted_submit_cores.push(core),
                Ok(Err(_))|Err(_)=>failed_submit_cores.push(core),
            }
        }
        validate_submit_core_partition(&accepted_submit_cores,&failed_submit_cores)?;
'''
NEW_SUBMISSION = '''        let mut submit_outcomes=Vec::new();
        for (core,result) in futures::future::join_all(submissions).await {
            match result {
                Ok(Ok(_))=>{
                    accepted_submit_cores.push(core);
                    submit_outcomes.push(serde_json::json!({"core":core,"accepted":true,"grpcCode":"Ok","clientTimeout":false}));
                },
                Ok(Err(error))=>{
                    failed_submit_cores.push(core);
                    submit_outcomes.push(serde_json::json!({"core":core,"accepted":false,
                        "grpcCode":format!("{:?}",error.code()),"clientTimeout":false}));
                },
                Err(_)=>{
                    failed_submit_cores.push(core);
                    submit_outcomes.push(serde_json::json!({"core":core,"accepted":false,
                        "grpcCode":null,"clientTimeout":true}));
                },
            }
        }
        // Private diagnosis survives a result-polling failure. It asserts
        // neither final decryption nor successful protocol completion.
        campaign_write(Path::new("/recipient").join(format!("submit-{index}.json")),&serde_json::json!({
            "schema":"vcfhe-recipient-submission-observation-v1","index":index,"name":message["name"],
            "requestId":signed["releaseRequest"]["requestId"],"requestKey":signed["releaseRequest"]["requestKey"],
            "acceptedSubmitCores":accepted_submit_cores,"failedSubmitCores":failed_submit_cores,
            "outcomes":submit_outcomes,"userDecryptResubmissions":0,
        }))?;
        validate_submit_core_partition(&accepted_submit_cores,&failed_submit_cores)?;
'''
OLD_POLL = '''        let mut responses=Vec::new();let mut seen=std::collections::HashSet::new();let mut poll_count=0;
        for _ in 0..polls {
            for (i,endpoint) in endpoints.iter_mut().enumerate() {
                if seen.contains(&i){continue;}
                poll_count+=1;
                match endpoint.get_user_decryption_result(tonic::Request::new(request.request_id.clone().unwrap())).await {
                    Ok(response)=>{responses.push(response.into_inner());seen.insert(i);},
                    Err(e) if e.code()==tonic::Code::Unavailable=>(),
                    Err(e)=>return Err(e.into()),
                }
                if responses.len()>=3 {break;}
            }
            if responses.len()>=3 {break;}
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        anyhow::ensure!(responses.len()>=3,"threshold response timeout");
'''
NEW_POLL = '''        let (responses,poll_count)=acquire_accepted_user_results(&endpoints,
            request.request_id.as_ref().unwrap(),&accepted_submit_cores,&failed_submit_cores,polls).await?;
'''


def sha(value):
    return hashlib.sha256(value).hexdigest()


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('The original recipient source anchor changed')
    return source.replace(old, new)


def security_tail(source):
    return source[source.index('        let plain=tops_recipient_validation::decrypt_bound('):
                  source.index('        let encrypted=serde_json::to_vec(&responses)?;')]


def render(source):
    if sha(source.encode()) != EXPECTED_SOURCE_SHA256:
        raise ValueError('Candidate is restricted to the exact reviewed original transport source')
    candidate = once(source, OLD_SUBMISSION, NEW_SUBMISSION)
    candidate = once(candidate, OLD_POLL, NEW_POLL)
    if security_tail(source) != security_tail(candidate):
        raise ValueError('Recipient authentication or negative checks changed')
    original_prefix = source[:source.index('        let started=std::time::Instant::now();\n        let mut accepted_submit_cores=')]
    if not candidate.startswith(original_prefix):
        raise ValueError('A submission, authorization, negative-ingress or setup operation changed')
    return candidate + '\n' + (HERE/'acquire-accepted-results.rs').read_text() + '\n' + (HERE/'transport-regressions.rs').read_text()


def prepare(source_path, destination):
    source_path, destination = Path(source_path), Path(destination)
    source = source_path.read_text()
    candidate = render(source)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Candidate output must be a fresh directory')
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(destination, 0o700)
    patch = ''.join(difflib.unified_diff(source.splitlines(True), candidate.splitlines(True),
        fromfile='a/VC-FHE/threshold-kms/campaign/transport.rs', tofile='b/VC-FHE/threshold-kms/campaign/transport.rs'))
    for name, value in [('transport.proposed.rs', candidate), ('transport.proposed.patch', patch)]:
        with (destination/name).open('x') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    report = {'schema':'vcfhe-recipient-result-transport-proposal-v1','status':'candidate-not-applied',
        'sourceSha256':sha(source.encode()),'candidateSha256':sha(candidate.encode()),
        'pollingPolicy':'only successful-submit cores, UNAVAILABLE remains pending, any other error fails',
        'acceptedSubmitThreshold':3,'authenticatedResponseThreshold':3,
        'recipientAuthenticationByteIdentical':True,'negativeIngressPrefixByteIdentical':True,
        'submissionTimeoutSeconds':180,'retrySleepMilliseconds':100,
        'userDecryptResubmissions':0,'nativeCompiled':False,'nativeExecuted':False,
        'loopbackTests':'Rust/Tonic tests included but not compiled or executed in this preparation'}
    with (destination/'proposal.local.json').open('x') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))
