use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

use anyhow::{anyhow, Context, Result as AnyResult};
use clap::Parser;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{Api, DeleteParams, PostParams},
    core::{NotUsed, Object, ObjectMeta},
    discovery,
    runtime::{wait::delete::delete_and_finalize, watcher},
    Client,
};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::signal::unix::{signal, SignalKind};

const RUNNER_INFO_ANNOTATION: &str = "li.zhaofeng.kubevirt-actions-runner/runner-info";
const RUNNER_INFO_VOLUME: &str = "runner-info";
const RUNNER_INFO_PATH: &str = "runner-info.json";

type VirtualMachine = Object<VirtualMachineSpec, NotUsed>;
type VirtualMachineInstance = Object<VirtualMachineInstanceSpec, VirtualMachineInstanceStatus>;

/// Information passed to the VM.
///
/// This is added to the VMI as a `downwardAPI` volume
/// named `runner-info` at the path `runner-info.json`.
///
/// To use it, add the following device to your domain:
///
/// ```text
/// devices:
///   filesystems:
///     - name: runner-info
///       virtiofs: {}
/// ```
///
/// Alternatively, you can also mount it as a `disk`.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum RunnerInfo {
    Jit(JitRunnerInfo),
    Legacy(LegacyRunnerInfo),
}

/// JIT runner info.
///
/// This is the new-style configuration passed by ARC. You simply
/// need to start the runner with the `ACTIONS_RUNNER_INPUT_JITCONFIG`
/// environment variable.
#[derive(Debug, Clone, Serialize)]
struct JitRunnerInfo {
    /// A base64-encoded structure recognized by the runner.
    ///
    /// Set `ACTIONS_RUNNER_INPUT_JITCONFIG` to this value.
    jitconfig: String,
}

/// Legacy runner info.
///
/// You need to configure the runner manually using these
/// configurations.
#[derive(Debug, Clone, Serialize)]
struct LegacyRunnerInfo {
    /// The name of the runner.
    name: String,

    /// The runner registration token.
    token: String,

    /// The URL of an organization or repo to register the runner in.
    url: String,

    /// Whether the runner should be ephemeral or not.
    ephemeral: bool,

    /// Runner groups to attach to the runner.
    groups: String,

    /// Labels to attach to the runner.
    labels: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VirtualMachineSpec {
    template: VirtualMachineTemplate,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VirtualMachineTemplate {
    metadata: ObjectMeta,
    spec: VirtualMachineInstanceSpec,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VirtualMachineInstanceSpec {
    volumes: Option<Vec<Volume>>,

    #[serde(flatten)]
    data: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VirtualMachineInstanceStatus {
    phase: String,
}

impl Default for VirtualMachineInstanceStatus {
    fn default() -> Self {
        Self {
            phase: "Unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Volume {
    name: String,

    #[serde(flatten)]
    data: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmiOutcome {
    /// The VMI has succeeded.
    Succeeded,

    /// The VMI has failed.
    ///
    /// This usually means it did not shut down within the grace period.
    Failed,

    /// The VMI was (force) deleted.
    Deleted,

    /// The watcher was interrupted.
    WatchInterrupted,
}

#[derive(Parser, Debug)]
struct Opts {
    /// The namespace to operate in.
    ///
    /// When run in-cluster, it defaults to the namespace the
    /// runner pod is in.
    #[clap(short = 'n', long)]
    namespace: Option<String>,

    /// The name of the runner.
    #[clap(long, default_value = "runner", env = "RUNNER_NAME")]
    name: String,

    /// The opaque JIT runner config.
    ///
    /// If this is specified, other GitHub API configs except `name` are ignored.
    #[clap(long, env = "ACTIONS_RUNNER_INPUT_JITCONFIG")]
    jitconfig: Option<String>,

    /// The runner registration token.
    #[clap(long, env = "RUNNER_TOKEN")]
    token: Option<String>,

    /// The URL of an organization or repo to register the runner in.
    ///
    /// If unspecified, this is auto-detected from the following
    /// environment variables:
    ///
    /// - GITHUB_URL
    /// - RUNNER_ORG (org)
    /// - RUNNER_REPO (org/repo)
    #[clap(long)]
    url: Option<String>,

    /// Whether the runner should be ephemeral or not.
    #[clap(long, env = "RUNNER_EPHEMERAL")]
    ephemeral: bool,

    /// Runner groups to attach to the runner.
    #[clap(long, default_value = "", env = "RUNNER_GROUPS")]
    groups: String,

    /// Labels to attach to the runner.
    #[clap(long, default_value = "", env = "RUNNER_LABELS")]
    labels: String,

    /// The VirtualMachine resource to use as the template.
    #[clap(long, env = "KUBEVIRT_VM_TEMPLATE")]
    vm_template: String,

    /// TODO: this is not optimal. Lets rework this mechanism
    /// The workflow id to serve with resources
    #[clap(long, env = "GITHUB_WORKFLOW_ID")]
    github_workflow_id: String,
}

impl VmiOutcome {
    fn is_abnormal(&self) -> bool {
        matches!(self, Self::Failed | Self::Deleted | Self::WatchInterrupted)
    }
}

#[tokio::main]
async fn main() {
    let opts = Opts::parse();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opts).await {
        eprintln!("Error: {}", e);

        // Makes it easier to get logs (the controller deletes us immediately)
        eprintln!("Exiting in 10 seconds...");
        tokio::time::sleep(Duration::from_secs(10)).await;

        std::process::exit(1);
    }
}

async fn fetch_kernel_version(opts: &Opts) -> Result<String, Box<dyn std::error::Error>> {
    //Fetch the GITHUB_TOKEN secret
    let client = Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), client.default_namespace());
    let gh_token_secret = secrets
        .get(format!("github-config-secret").as_str())
        .await?;
    let data = gh_token_secret
        .data
        .ok_or("GitHub config secret data is missing")?;
    let gh_token = data
        .get("github_token")
        .ok_or("github_token is missing")?
        .0
        .clone();

    //TODO: Handle errors by retrying the REST API calls n times.
    //Start REST API calls with the help of the previoursly fetched token
    let token = String::from_utf8(gh_token)?;
    let org = env::var("GITHUB_ORG").expect("GITHUB_ORG not set");
    let repo = env::var("GITHUB_REPO").expect("GITHUB_REPO not set");
    let workflow_id = &opts.github_workflow_id;
    let mut kernel_version = "";

    //TODO: This does not work in a scenario with multiple workflow triggers
    //
    //Fetching the latest workflow run, which we further on use to get the run_id of the completed
    //sub-job that contains the evaluated variables for building the kernel.
    let runs = format!(
        "https://api.github.com/repos/{org}/{repo}/actions/workflows/{workflow_id}/runs?per_page=1"
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        "X-GitHub-Api-Version",
        HeaderValue::from_static("2022-11-28"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token))?,
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("kubevirt-actions-runner"),
    );

    let client = reqwest::Client::new();
    let response = client.get(&runs).headers(headers.clone()).send().await?;

    let runs_status = response.status();
    if !runs_status.is_success() {
        panic!("Bad status code: {runs_status}");
    }
    let runs_text = response.text().await?;

    let runs: Value = serde_json::from_str(&runs_text)?;

    let run = runs["workflow_runs"]
        .as_array()
        .and_then(|arr| arr.get(0))
        .ok_or_else(|| "No successful runs found")?;

    let run_id = run["id"].as_u64().expect("Run ID not found");

    // Get the completed job for the specific run
    let jobs_url = format!(
        "https://api.github.com/repos/{org}/{repo}/actions/runs/{run_id}/jobs?status=completed"
    );
    let jobs_response = client
        .get(&jobs_url)
        .headers(headers.clone())
        .send()
        .await?;

    let jobs_status = jobs_response.status();
    if !jobs_status.is_success() {
        panic!("Bad status code for jobs query: {runs_status}");
    }
    let jobs_text = jobs_response.text().await?;

    let jobs: Value = serde_json::from_str(&jobs_text)?;

    let job = jobs["jobs"]
        .as_array()
        .and_then(|arr| arr.get(0))
        .ok_or_else(|| "No jobs found")?;

    let job_id = job["id"].as_u64().expect("Job ID not found");

    tracing::info!("Fetching kernel information for run_id='{run_id}' and job_id='{job_id}'");
    // Get the logs for the specific job
    let logs_url = format!(
        "https://api.github.com/repos/{}/{}/actions/jobs/{}/logs",
        org, repo, job_id
    );
    let logs_response = client.get(&logs_url).headers(headers).send().await?;

    let logs_status = logs_response.status();
    if !logs_status.is_success() {
        panic!("Bad status code for logs query: {logs_status}");
    }

    let logs_text = logs_response.text().await?;

    // Extract the value of KERNEL_VERSION from the logs
    let re_commit_sha = Regex::new(r#"KERNEL_VERSION:\s*(.*)"#)?;
    if let Some(captures) = re_commit_sha.captures(&logs_text) {
        if let Some(var_value) = captures.get(1) {
            tracing::info!("Found KERNEL_VERSION='{}'", var_value.as_str());
            kernel_version = var_value.as_str();
        } else {
            panic!("KERNEL_VERSION not found in logs");
        }
    } else {
        panic!("KERNEL_VERSION not found in logs");
    }
    Ok(kernel_version.to_string())
}

fn replace_kernel_version(data: &mut BTreeMap<String, Value>, kernel_version: &str) {
    for (_, value) in data.iter_mut() {
        replace_in_value(value, kernel_version);
    }
}

fn replace_in_value(value: &mut Value, kernel_version: &str) {
    match value {
        Value::String(s) => {
            if s.contains("{{ kernel_version }}") {
                *s = s.replace("{{ kernel_version }}", kernel_version);
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                replace_in_value(v, kernel_version);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                replace_in_value(v, kernel_version);
            }
        }
        _ => {}
    }
}

async fn run(opts: Opts) -> AnyResult<()> {
    let kernel_version = fetch_kernel_version(&opts).await.unwrap();
    //TODO: alternatively the RUNNER_NAME var could be set to include the run-id or patch-id?
    //let vmi_name = format!("{}-{}", opts.name, kernel_version);
    let vmi_name = opts.name;
    let runner_info = if let Some(jitconfig) = &opts.jitconfig {
        RunnerInfo::Jit(JitRunnerInfo {
            jitconfig: jitconfig.clone(),
        })
    } else {
        let runner_url = opts.url.ok_or(()).or_else(|_| {
            let base = env::var("GITHUB_URL").unwrap_or_else(|_| "https://github.com/".to_string());
            let repo =
                env::var("RUNNER_REPO")
                    .ok()
                    .and_then(|v| if v.is_empty() { None } else { Some(v) });
            let org =
                env::var("RUNNER_ORG")
                    .ok()
                    .and_then(|v| if v.is_empty() { None } else { Some(v) });

            let path = match (org, repo) {
                (Some(_), Some(_)) => {
                    return Err(anyhow!(
                        "RUNNER_REPO and RUNNER_ORG cannot both be non-empty"
                    ));
                }
                (None, None) => {
                    return Err(anyhow!("RUNNER_REPO or RUNNER_ORG must be set"));
                }
                (Some(org), None) => org,
                (None, Some(repo)) => repo,
            };

            Ok(format!("{}{}", base, path))
        })?;

        tracing::info!("Runner URL: {}", runner_url);

        RunnerInfo::Legacy(LegacyRunnerInfo {
            name: vmi_name.clone(),
            token: opts.token.expect("A token is required"),
            url: runner_url,
            ephemeral: opts.ephemeral,
            groups: opts.groups,
            labels: opts.labels,
        })
    };

    let client = Client::try_default().await?;
    let namespace = opts
        .namespace
        .as_deref()
        .unwrap_or(client.default_namespace());

    let kubevirt = discovery::group(&client, "kubevirt.io")
        .await
        .context("Failed to get kubevirt.io API group")?;
    let (vm_resource, _vm_caps) = kubevirt
        .recommended_kind("VirtualMachine")
        .ok_or_else(|| anyhow!("The kubevirt.io API group doesn't have the VirtualMachine type"))?;
    let (vmi_resource, _vmi_caps) = kubevirt
        .recommended_kind("VirtualMachineInstance")
        .ok_or_else(|| {
            anyhow!("The kubevirt.io API group doesn't have the VirtualMachineInstance type")
        })?;

    let vms: Api<VirtualMachine> = Api::namespaced_with(client.clone(), namespace, &vm_resource);
    let vmis: Api<VirtualMachineInstance> =
        Api::namespaced_with(client.clone(), namespace, &vmi_resource);

    //TODO: what happens here if we spawn multiple runner jobs at the same time?
    if vmis.get_opt(&vmi_name).await?.is_some() {
        tracing::info!("The VMI already exists (were we killed?) - Deleting");
        delete_and_finalize(vmis.clone(), &vmi_name, &DeleteParams::default())
            .await
            .context("Failed to delete existing VMI")?;
    }

    let template = vms.get(&opts.vm_template).await?;
    //TODO: adjust the "runner" vm name -> this might solve the issue of concurrency

    let mut vmi = VirtualMachineInstance::new("vmi", &vmi_resource, template.spec.template.spec);
    vmi.metadata = template.spec.template.metadata;
    vmi.metadata.name = Some(vmi_name.clone());
    vmi.metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            RUNNER_INFO_ANNOTATION.to_string(),
            serde_json::to_string(&runner_info)?,
        );
    replace_kernel_version(&mut vmi.spec.data, kernel_version.as_str());

    let mut data = BTreeMap::new();
    data.insert(
        "downwardAPI".to_string(),
        serde_json::json!({
            "fields": [
                {
                    "path": RUNNER_INFO_PATH,
                    "fieldRef": {
                        "fieldPath": format!("metadata.annotations['{}']", RUNNER_INFO_ANNOTATION)
                    }
                }
            ]
        }),
    );

    let volumes = vmi.spec.volumes.get_or_insert_with(Default::default);
    if let Some(volume) = volumes.iter_mut().find(|v| v.name == RUNNER_INFO_VOLUME) {
        volume.data = data;
    } else {
        volumes.push({
            Volume {
                name: RUNNER_INFO_VOLUME.to_string(),
                data,
            }
        });
    }

    tracing::info!("Creating VMI");
    vmis.create(&PostParams::default(), &vmi).await?;

    tracing::info!("Watching VMI");
    let mut sigterm = signal(SignalKind::terminate()).context("Failed to watch SIGTERM")?;
    let mut sigint = signal(SignalKind::interrupt()).context("Failed to watch SIGINT")?;
    let outcome = tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("Got SIGTERM");
            VmiOutcome::WatchInterrupted
        }
        _ = sigint.recv() => {
            tracing::info!("Got SIGINT");
            VmiOutcome::WatchInterrupted
        }
        outcome = wait_for_vmi(vmis.clone(), &vmi_name) => {
            let outcome = outcome
                .context("Failed to watch VMI")?;

            match outcome {
                VmiOutcome::Succeeded | VmiOutcome::Failed => {
                    tracing::info!("VMI has terminated");
                }
                VmiOutcome::Deleted => {
                    tracing::info!("VMI was deleted by something");
                }
                VmiOutcome::WatchInterrupted => {
                    tracing::info!("The stream ended prematurely");
                }
            }

            outcome
        }
    };

    if outcome != VmiOutcome::Deleted {
        tracing::info!("Deleting VMI");
        delete_and_finalize(vmis.clone(), &vmi_name, &DeleteParams::default())
            .await
            .context("Failed to delete VMI")?;
    }

    if outcome.is_abnormal() {
        return Err(anyhow!("VMI outcome: {:?}", outcome));
    }

    Ok(())
}

/// Waits until the VMI terminates.
async fn wait_for_vmi(api: Api<VirtualMachineInstance>, name: &str) -> AnyResult<VmiOutcome> {
    let mut stream = Box::pin(watcher::watcher(
        api,
        watcher::Config {
            field_selector: Some(format!("metadata.name={}", name)),
            ..Default::default()
        },
    ));

    let mut last_phase = "Unknown".to_string();
    while let Some(event) = stream.next().await {
        use watcher::Event;
        match event? {
            Event::Applied(obj) => {
                if let Some(status) = obj.status {
                    tracing::debug!("VMI has phase: {}", status.phase);

                    if status.phase != last_phase {
                        tracing::info!("VMI has transitioned to {}", status.phase);

                        match status.phase.as_str() {
                            "Succeeded" => {
                                return Ok(VmiOutcome::Succeeded);
                            }
                            "Failed" => {
                                return Ok(VmiOutcome::Failed);
                            }
                            _ => {}
                        }
                        last_phase = status.phase;
                    }
                } else {
                    tracing::debug!("VMI has no status");
                }
            }
            Event::Deleted(_) => {
                return Ok(VmiOutcome::Deleted);
            }
            _ => {}
        }
    }

    Ok(VmiOutcome::WatchInterrupted)
}
